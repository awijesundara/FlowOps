import os
import tempfile
import threading
import unittest

tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
tmp.close()
os.environ['FLOWOPS_DB'] = tmp.name
os.environ['FLOWOPS_PREVIEW_TOKENS'] = 'true'
os.environ['FLOWOPS_SETTINGS_ENCRYPTION_KEY'] = 'a1J1M20wV3JlbklvNWt1a2NTYk9pQ3VHTW5PRzFjTFI='
import server

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None


@unittest.skipIf(sync_playwright is None, "playwright is not installed")
class FlowOpsBrowserTest(unittest.TestCase):
    """Real-browser regression coverage for UI bugs found and fixed by hand
    this session: a permanently-visible notification badge with nothing
    unread, a duplicated 'New runbook' button on the Runbooks page, and the
    Administration landing page's category list rendering exactly once."""

    @classmethod
    def setUpClass(cls):
        server.init_db()
        cls.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.base = f'http://127.0.0.1:{cls.http.server_port}'
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.playwright = sync_playwright().start()
        launch_options = {}
        if os.getenv('FLOWOPS_BROWSER_CHANNEL'):
            launch_options['channel'] = os.environ['FLOWOPS_BROWSER_CHANNEL']
        cls.browser = cls.playwright.chromium.launch(**launch_options)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.http.shutdown()
        os.unlink(tmp.name)

    def setUp(self):
        self.page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        self.page.goto(self.base)
        self.page.fill('input[name=username]', 'admin')
        self.page.fill('input[name=password]', 'FlowOps!Preview2026')
        self.page.click('.login-button')
        self.page.wait_for_selector('.shell:not(.app-hidden)')

    def tearDown(self):
        self.page.close()

    def test_temporary_session_check_failure_does_not_attempt_sso_or_show_login(self):
        calls = []
        self.page.route('**/api/auth/me', lambda route: route.fulfill(
            status=503, content_type='application/json', body='{"error":"Temporarily unavailable"}'))
        self.page.route('**/api/auth/sso', lambda route: (calls.append('sso'), route.fulfill(
            status=401, content_type='application/json', body='{"error":"No identity"}')))
        self.page.reload()
        self.page.wait_for_timeout(700)
        self.assertEqual(calls, [])
        self.assertFalse(self.page.locator('#enterpriseLoginForm').is_visible())
        self.page.unroute('**/api/auth/me')
        self.page.wait_for_selector('.shell:not(.app-hidden)', timeout=8000)

    def test_failed_logout_keeps_authenticated_workspace(self):
        self.page.route('**/api/auth/logout', lambda route: route.fulfill(
            status=503, content_type='application/json', body='{"error":"Temporarily unavailable"}'))
        self.page.evaluate("document.querySelector('#logout').click()")
        self.page.wait_for_timeout(300)
        self.assertTrue(self.page.locator('.shell').is_visible())
        self.assertTrue(self.page.evaluate('!!state.user'))

    def test_workspace_render_error_does_not_replace_valid_session_with_sso(self):
        calls = []
        self.page.route('**/api/auth/sso', lambda route: calls.append('sso'))
        self.page.evaluate("applyIdentity = () => {throw new Error('Workspace render failed')}; boot()")
        self.page.wait_for_timeout(400)
        self.assertEqual(calls, [])
        self.assertFalse(self.page.locator('#loginScreen').is_visible())
        self.assertTrue(self.page.evaluate('!!state.user'))

    def test_live_disconnect_checks_session_without_logging_out_on_network_failure(self):
        self.page.route('**/api/auth/me', lambda route: route.fulfill(
            status=503, content_type='application/json', body='{"error":"Temporarily unavailable"}'))
        self.page.evaluate('lastLiveSessionCheck=0; checkLiveSession()')
        self.assertTrue(self.page.evaluate('!!state.user'))
        self.page.unroute('**/api/auth/me')
        self.page.route('**/api/auth/me', lambda route: route.fulfill(
            status=401, content_type='application/json', body='{"error":"Authentication required"}'))
        self.page.evaluate('lastLiveSessionCheck=0; checkLiveSession()')
        self.assertFalse(self.page.evaluate('!!state.user'))

    def test_sign_out_clears_previous_users_activity_and_task_filters(self):
        self.page.evaluate("announceActivity({data:JSON.stringify({action:'comment.added',actor:'Previous user',detail:'Private activity',created_at:new Date().toISOString()})}); cxMine=true; document.querySelector('#logout').click()")
        self.page.wait_for_selector('#enterpriseLoginForm', state='visible')
        self.assertEqual(self.page.evaluate('activity.length'), 0)
        self.assertFalse(self.page.evaluate('cxMine'))

    def test_expired_session_returns_to_sign_in_and_stops_live_feed(self):
        self.page.route('**/api/runbooks', lambda route: route.fulfill(
            status=401, content_type='application/json', body='{"error":"Authentication required"}'))
        self.page.evaluate('load()')
        self.page.wait_for_selector('#enterpriseLoginForm', state='visible')
        self.assertFalse(self.page.evaluate('!!state.user'))
        self.assertTrue(self.page.evaluate('liveFeed === null'))

    def test_live_refresh_preserves_task_comment_draft_and_focus(self):
        self.page.evaluate('openRunbook(state.runbooks[0].id)')
        self.page.wait_for_selector('#detail.view.active .cx-row')
        self.page.evaluate('cxOpenTask(state.current.tasks[0].id)')
        field = self.page.locator('.cx-panel input[name=body]')
        field.fill('Keep this unfinished comment')
        field.focus()
        self.page.evaluate('liveRefresh()')
        self.page.wait_for_timeout(600)
        self.assertEqual(field.input_value(), 'Keep this unfinished comment')
        self.assertTrue(field.evaluate('(el) => el === document.activeElement'))

    def test_notification_bell_has_no_visible_badge_with_no_unread_activity(self):
        badge = self.page.query_selector('.unread-count')
        self.assertIsNotNone(badge, "unread-count badge element should exist in the DOM")
        self.assertFalse(badge.is_visible(), "badge must be hidden when there is nothing unread")

    def test_notification_bell_rings_and_colors_by_severity(self):
        """The bell rings on every new live-activity arrival and its badge
        (plus each drawer row) is colored by a severity derived from the
        audit action string: failures/incidents/escalations are critical
        (red, the pre-existing default badge color), things worth a look
        soon are warning (amber), everything else is informational (blue)."""
        self.page.evaluate(
            "announceActivity({data: JSON.stringify({"
            "action: 'task.escalated', actor: 'System', "
            "detail: 'Deploy application release is overdue', "
            "created_at: new Date().toISOString()})})"
        )
        animation = self.page.evaluate(
            "getComputedStyle(document.querySelector('#notifBell')).animationName"
        )
        self.assertEqual(animation, "notifBellRing", "the bell must ring on a new arrival")
        badge = self.page.query_selector('.unread-count')
        self.assertTrue(badge.is_visible())
        self.assertNotIn("sev-warning", badge.get_attribute("class"))
        self.assertNotIn("sev-info", badge.get_attribute("class"))

        self.page.evaluate(
            "announceActivity({data: JSON.stringify({"
            "action: 'comment.added', actor: 'Priya', "
            "detail: 'left a comment on Payments release', "
            "created_at: new Date().toISOString()})})"
        )
        self.page.click('#notifBell')
        self.page.wait_for_selector('.notification-drawer.open')
        items = self.page.query_selector_all('.notification-item')
        classes = [item.get_attribute("class") for item in items]
        self.assertTrue(any("sev-critical" in c for c in classes), classes)
        self.assertTrue(any("sev-info" in c for c in classes), classes)
        # Opening the drawer resets the unread state, including the
        # severity that had colored the badge, back to the base style.
        self.assertEqual(badge.get_attribute("class"), "unread-count")

    def test_runbooks_page_shows_new_runbook_button_exactly_once(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        visible = [
            b for b in self.page.query_selector_all('button:has-text("New runbook")')
            if b.is_visible()
        ]
        self.assertEqual(len(visible), 1, "exactly one visible 'New runbook' button on the Runbooks page")

    def test_admin_landing_shows_category_areas_exactly_once(self):
        self.page.click('[data-view="admin"]')
        self.page.wait_for_selector('#admin.view.active')
        self.page.wait_for_timeout(250)
        rows = self.page.query_selector_all('#adminCatList .admin-cat-row')
        self.assertGreater(len(rows), 0)
        titles = [r.inner_text() for r in rows]
        self.assertEqual(len(titles), len(set(titles)), "no category should be listed twice")

    def test_enabling_push_notifications_registers_a_real_service_worker_and_subscribes(self):
        self.page.context.grant_permissions(['notifications'], origin=self.base)
        registration_scope = self.page.evaluate("""async () => {
            const reg = await navigator.serviceWorker.register('/sw.js');
            await navigator.serviceWorker.ready;
            return reg.scope;
        }""")
        self.assertTrue(registration_scope.endswith('/'))
        vapid_key = self.page.evaluate("""async () => {
            const res = await fetch('/api/push/vapid-public-key');
            const body = await res.json();
            return body.data.public_key;
        }""")
        raw_point_length = self.page.evaluate("""(key) => {
            const padding = '='.repeat((4 - key.length % 4) % 4);
            const raw = atob((key + padding).replace(/-/g, '+').replace(/_/g, '/'));
            return raw.length;
        }""", vapid_key)
        self.assertEqual(raw_point_length, 65, 'VAPID public key must be a real 65-byte uncompressed P-256 point')
        try:
            subscribed = self.page.evaluate("""async (key) => {
                const padding = '='.repeat((4 - key.length % 4) % 4);
                const raw = atob((key + padding).replace(/-/g, '+').replace(/_/g, '/'));
                const applicationServerKey = Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
                const reg = await navigator.serviceWorker.ready;
                const sub = await reg.pushManager.subscribe({userVisibleOnly: true, applicationServerKey});
                const csrf = state.csrf;
                const res = await fetch('/api/push/subscribe', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
                    body: JSON.stringify(sub.toJSON()),
                });
                return {status: res.status, endpoint: sub.endpoint};
            }""", vapid_key)
        except Exception as exc:
            self.skipTest(f'This browser/environment cannot reach a real push service to complete subscription: {exc}')
        self.assertEqual(subscribed['status'], 201)
        self.assertTrue(subscribed['endpoint'].startswith('http'))

    def test_switching_locale_to_japanese_translates_nav_and_falls_back_for_unknown_locale(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        nav_runbooks = self.page.locator('.nav[data-view="runbooks"] span')
        self.assertEqual(nav_runbooks.inner_text(), 'Runbooks')
        self.page.evaluate("setLocale('ja')")
        self.assertEqual(nav_runbooks.inner_text(), 'ランブック')
        self.assertEqual(self.page.locator('.nav[data-view="home"] span').inner_text(), 'コマンドセンター')
        # an unknown/unsupported locale must fall back to English, not show raw keys or crash
        self.page.evaluate("setLocale('xx-not-real')")
        self.assertEqual(nav_runbooks.inner_text(), 'Runbooks')
        self.page.evaluate("setLocale('en')")  # restore for other tests

    def test_login_screen_renders_in_the_locale_persisted_from_a_previous_session(self):
        self.page.click('#accountMenuToggle')
        self.page.click('#logout')
        self.page.wait_for_selector('.login-button')
        self.page.evaluate("localStorage.setItem('flowops_locale','ja')")
        self.page.reload()
        self.page.wait_for_selector('.login-button')
        self.assertEqual(self.page.locator('.login-button').inner_text(), 'サインイン')
        self.page.evaluate("localStorage.setItem('flowops_locale','en')")

    def test_api_explorer_can_call_a_real_endpoint_with_a_pasted_token(self):
        token = self.page.evaluate("""async () => {
            const res = await fetch('/api/admin/api-tokens', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf},
                body: JSON.stringify({name: 'Browser explorer test', scopes: ['runbooks:read']})
            });
            const body = await res.json();
            return body.data.token;
        }""")
        self.assertTrue(token.startswith('fo_'))
        self.page.goto(self.base + '/api-explorer')
        self.page.wait_for_selector('#endpointList button')
        self.page.fill('#token', token)
        self.page.click('#endpointList button:has-text("GET")')
        self.page.wait_for_selector('#tryForm')
        self.page.click('#tryForm button:has-text("Try it")')
        self.page.wait_for_selector('#responseView pre')
        status_chip = self.page.inner_text('#responseView .chip')
        self.assertIn('Status 200', status_chip)
        response_text = self.page.inner_text('#responseView pre')
        self.assertIn('"data"', response_text)
    def test_runbook_search_surfaces_task_level_matches(self):
        self.page.click('[data-view="runbooks"]')
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.fill('#search', 'stakeholders')
        self.page.wait_for_timeout(500)
        rows = self.page.query_selector_all('.trow[data-id]')
        self.assertGreater(len(rows), 0, "search should return at least one task-title match")

    def test_axe_has_no_serious_or_critical_execution_ui_violations(self):
        axe_path = os.getenv('FLOWOPS_AXE_CORE_PATH')
        if not axe_path:
            self.skipTest('FLOWOPS_AXE_CORE_PATH is not configured')
        self.page.add_script_tag(path=axe_path)
        violations = []
        for view in ('home', 'runbooks'):
            self.page.click(f'[data-view="{view}"]')
            result = self.page.evaluate("""async () => await axe.run(document, {
                runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}
            })""")
            violations.extend(
                f"{view}: {item['id']} ({item['impact']}) "
                + '; '.join(', '.join(node['target']) for node in item['nodes'])
                for item in result['violations']
                if item['impact'] in ('serious', 'critical')
            )
        self.page.evaluate("show('runbooks')")
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        result = self.page.evaluate("""async () => await axe.run(document, {
            runOnly: {type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa']}
        })""")
        violations.extend(
            f"detail: {item['id']} ({item['impact']}) "
            + '; '.join(', '.join(node['target']) for node in item['nodes'])
            for item in result['violations']
            if item['impact'] in ('serious', 'critical')
        )
        self.assertEqual(violations, [], '\n'.join(violations))

    def test_sidebar_stays_fixed_in_place_while_the_page_scrolls(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        position = self.page.evaluate("getComputedStyle(document.querySelector('aside')).position")
        self.assertEqual(position, 'fixed', "the primary nav sidebar must be truly fixed, not sticky, so it never drifts during scroll")
        before = self.page.eval_on_selector('aside', "el => { const r = el.getBoundingClientRect(); return {x: r.x, y: r.y}; }")
        self.page.mouse.wheel(0, 1500)
        self.page.wait_for_timeout(100)
        after = self.page.eval_on_selector('aside', "el => { const r = el.getBoundingClientRect(); return {x: r.x, y: r.y}; }")
        self.assertEqual(before, after, "the sidebar must not move at all while the page scrolls")

    def test_modal_close_buttons_are_square_icon_buttons_not_stretched(self):
        self.page.click('#accountMenuToggle')
        self.page.click('#openProfile')
        self.page.wait_for_selector('#profileModal[open]')
        box = self.page.eval_on_selector('.close-profile', "el => { const r = el.getBoundingClientRect(); return {w: r.width, h: r.height}; }")
        self.assertLess(box['h'], 60, f"profile modal close button is stretched tall: {box}")
        self.assertAlmostEqual(box['w'], box['h'], delta=4, msg=f"close button should be roughly square: {box}")

    def test_compact_layout_and_viewport_aware_menus_at_desktop_widths(self):
        for width in (1440, 1280, 1024):
            self.page.set_viewport_size({'width': width, 'height': 800})
            self.page.evaluate("show('home')")
            card_heights = self.page.eval_on_selector_all('#home .metrics article', 'els => els.map(e => e.getBoundingClientRect().height)')
            self.assertTrue(card_heights)
            self.assertLessEqual(max(card_heights), 130, f'KPI cards are too tall at {width}px: {card_heights}')
            self.assertLessEqual(max(card_heights)-min(card_heights), 1, f'KPI cards are not equal-height at {width}px')
            self.page.evaluate("show('runbooks')")
            self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
            self.page.wait_for_selector('#detail.view.active')
            if width > 1024:
                columns = self.page.eval_on_selector('.detail-grid', "el => {const a=el.children[0].getBoundingClientRect().width,b=el.children[1].getBoundingClientRect().width;return {a,b,ratio:a/(a+b)}}")
                self.assertGreaterEqual(columns['ratio'], .74, f'execution plan should receive at least 74% at {width}px: {columns}')
            self.page.click('.more-menu-toggle')
            bounds = self.page.eval_on_selector('.more-menu:not([hidden])', "el => {const r=el.getBoundingClientRect();return {left:r.left,top:r.top,right:r.right,bottom:r.bottom,height:r.height,viewportW:innerWidth,viewportH:innerHeight,overflow:getComputedStyle(el).overflowY}}")
            self.assertGreaterEqual(bounds['left'], 0); self.assertGreaterEqual(bounds['top'], 0)
            self.assertLessEqual(bounds['right'], bounds['viewportW']); self.assertLessEqual(bounds['bottom'], bounds['viewportH'])
            self.assertLessEqual(bounds['height'], bounds['viewportH']*.7+1)
            self.assertIn(bounds['overflow'], ('auto','scroll'))
            self.page.keyboard.press('Escape')

    def test_sidebar_collapses_and_account_menu_is_keyboard_accessible(self):
        before = self.page.eval_on_selector('#appSidebar', 'el => el.getBoundingClientRect().width')
        self.page.click('#collapseSidebar')
        self.page.wait_for_timeout(250)
        after = self.page.eval_on_selector('#appSidebar', 'el => el.getBoundingClientRect().width')
        self.assertLess(after, before)
        self.assertTrue(self.page.locator('#profile .avatar').is_visible())
        self.assertFalse(self.page.locator('#profile .profile-copy').is_visible())
        self.page.click('#accountMenuToggle')
        self.page.wait_for_selector('#accountMenu:not([hidden])')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'openProfile')
        self.page.keyboard.press('ArrowDown')
        self.assertEqual(self.page.evaluate('document.activeElement.id'), 'accountSettings')
        self.page.keyboard.press('Escape')
        self.assertTrue(self.page.locator('#accountMenu').is_hidden())

    def test_dashboard_greeting_boundaries_and_visible_runbook_source_are_consistent(self):
        periods = self.page.evaluate("[4,5,11,12,16,17,23].map(greetingPeriod)")
        self.assertEqual(periods, ['evening','morning','morning','afternoon','afternoon','evening','evening'])
        expected = self.page.evaluate("state.runbooks.filter(r => !['complete','cancelled'].includes(r.status)).length")
        self.assertEqual(int(self.page.inner_text('#mRunbooks')), expected)
        card_count = self.page.locator('#runbookCards .runbook-card').count()
        if self.page.evaluate('state.runbooks.length'):
            self.assertGreater(card_count, 0, 'a non-empty runbook collection must not render the empty state')
            self.assertEqual(self.page.locator('#runbookCards .dashboard-empty').count(), 0)

    def test_administration_uses_global_icon_rail_and_compact_secondary_navigation(self):
        self.page.set_viewport_size({'width': 1440, 'height': 900})
        self.page.click('[data-view="admin"]')
        self.page.wait_for_selector('#admin.view.active')
        widths = self.page.evaluate("""() => ({
            global: document.querySelector('#appSidebar').getBoundingClientRect().width,
            admin: document.querySelector('.admin-sidenav').getBoundingClientRect().width,
            overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        })""")
        self.assertLessEqual(widths['global'], 72)
        self.assertGreaterEqual(widths['admin'], 230)
        self.assertLessEqual(widths['admin'], 250)
        self.assertLessEqual(widths['overflow'], 0)
        self.assertFalse(self.page.locator('#adminScopeBanner').is_visible())

    def test_administration_global_navigation_can_expand_and_collapse(self):
        self.page.set_viewport_size({'width': 1440, 'height': 900})
        self.page.evaluate("localStorage.removeItem('flowops_admin_global_expanded')")
        baseline = self.page.evaluate("getComputedStyle(document.querySelector('[data-view=\"runbooks\"]')).fontSize")
        self.page.click('[data-view="admin"]')
        self.page.wait_for_selector('#admin.view.active')
        self.assertLessEqual(self.page.locator('#appSidebar').bounding_box()['width'], 72)
        self.page.click('#collapseSidebar')
        self.page.wait_for_timeout(250)
        self.assertGreaterEqual(self.page.locator('#appSidebar').bounding_box()['width'], 230)
        self.assertIn('Collapse', self.page.get_attribute('#collapseSidebar', 'aria-label'))
        self.assertEqual(
            self.page.evaluate("getComputedStyle(document.querySelector('[data-view=\"runbooks\"]')).fontSize"),
            baseline,
            'expanding global navigation in Administration must not change label typography',
        )
        self.page.click('#collapseSidebar')
        self.page.wait_for_timeout(250)
        self.assertLessEqual(self.page.locator('#appSidebar').bounding_box()['width'], 72)
        self.assertIn('Expand', self.page.get_attribute('#collapseSidebar', 'aria-label'))

    def test_runbook_and_generated_dialog_actions_never_overlap(self):
        self.page.click('#newRunbook')
        self.page.wait_for_selector('#runbookModal[open]')
        buttons = self.page.locator('#runbookModal .modalactions button')
        self.assertEqual(buttons.count(), 2)
        left, right = buttons.nth(0).bounding_box(), buttons.nth(1).bounding_box()
        self.assertLessEqual(left['x'] + left['width'], right['x'])
        self.assertEqual(round(left['height']), round(right['height']))
        self.assertGreaterEqual(left['height'], 44)
        self.assertEqual(
            self.page.evaluate("getComputedStyle(document.querySelector('#runbookModal .modalactions button:first-child')).fontSize"),
            self.page.evaluate("getComputedStyle(document.querySelector('#runbookModal .modalactions button:last-child')).fontSize"),
        )
        self.page.click('#runbookModal .close')
        self.page.set_viewport_size({'width': 390, 'height': 844})
        self.page.click('#newRunbook')
        self.page.wait_for_selector('#runbookModal[open]')
        left, right = buttons.nth(0).bounding_box(), buttons.nth(1).bounding_box()
        self.assertLessEqual(left['x'] + left['width'], right['x'])
        self.assertLessEqual(right['x'] + right['width'], 390)

    def test_analytics_is_populated_from_real_runbook_and_delay_sources(self):
        self.page.click('[data-view="analytics"]')
        self.page.wait_for_selector('#analytics.view.active')
        self.page.wait_for_function("document.querySelector('#analyticsTotal').textContent !== '—'")
        self.assertEqual(int(self.page.inner_text('#analyticsTotal')), self.page.evaluate('state.runbooks.length'))
        self.assertEqual(self.page.locator('[data-analytics-runbook]').count(), self.page.evaluate('state.runbooks.length'))
        self.assertTrue(self.page.locator('#analyticsDistribution').is_visible())
        self.assertTrue(self.page.locator('#delayReportTable').is_visible())
        self.assertLessEqual(self.page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth'), 0)

    def test_account_control_only_shows_acting_context_for_real_elevation(self):
        self.assertTrue(self.page.locator('#actingContext').is_hidden())
        self.page.click('#accountMenuToggle')
        self.assertIn('Administrator', self.page.inner_text('#accountCurrentRole'))
        if self.page.locator('#actingAs').is_visible():
            self.assertTrue(self.page.evaluate("Boolean(state.user.available_roles?.length > 1 || state.user.workspaces?.length > 1)"))
        self.assertTrue(self.page.locator('#accountEmail').count())

    def test_dashboard_and_administration_reflow_at_supported_widths(self):
        for width in (1536, 1440, 1280, 1024, 768, 390):
            self.page.set_viewport_size({'width': width, 'height': 900})
            self.page.evaluate("show('home', {skipHistory:true})")
            self.page.wait_for_timeout(220)
            home = self.page.evaluate("""() => ({
                overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
                columns: getComputedStyle(document.querySelector('.metrics')).gridTemplateColumns.split(' ').length,
            })""")
            self.assertLessEqual(home['overflow'], 0, f'dashboard overflow at {width}px')
            self.assertEqual(home['columns'], 4 if width > 1100 else 2 if width > 480 else 1)
            self.page.evaluate("show('admin', {skipHistory:true})")
            self.page.wait_for_timeout(220)
            admin_overflow = self.page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
            self.assertLessEqual(admin_overflow, 0, f'administration overflow at {width}px')

    def test_view_switches_and_admin_pane_switches_use_a_real_reveal_animation(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        name = self.page.evaluate("getComputedStyle(document.querySelector('#runbooks.view.active')).animationName")
        self.assertNotEqual(name, 'none', 'switching views should play a reveal animation, not cut instantly')
        self.page.click('[data-view="admin"]', force=True)
        self.page.wait_for_selector('#admin.view.active')
        self.page.click('text=People & access')
        self.page.wait_for_selector('.admin-tool-card')
        self.page.click('text=Users & access')
        self.page.wait_for_selector('.admin-pane.active')
        pane_name = self.page.evaluate("getComputedStyle(document.querySelector('.admin-pane.active')).animationName")
        self.assertNotEqual(pane_name, 'none', 'switching admin panes should play the same reveal animation as the rest of the app')

    def test_monitor_view_opens_from_the_runbook_and_shows_live_task_state(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        rid = self.page.evaluate('state.current.id')
        self.page.goto(f'{self.base}/monitor.html?rid={rid}')
        self.page.wait_for_selector('.card')
        self.assertIn('Confirm change approval', self.page.inner_text('.card'))
        self.assertIn('Live', self.page.inner_text('#liveLabel'))

    def test_monitor_view_prompts_sign_in_when_not_authenticated(self):
        fresh_context = self.browser.new_context()
        fresh_page = fresh_context.new_page()
        rid = self.page.evaluate('state.current ? state.current.id : 1')
        fresh_page.goto(f'{self.base}/monitor.html?rid={rid}')
        fresh_page.wait_for_selector('.signin')
        self.assertIn('Sign in', fresh_page.inner_text('.signin'))
        fresh_context.close()

    def test_dependency_gate_badges_show_entry_sequential_and_and_or_correctly(self):
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        badges = self.page.eval_on_selector_all(
            '.task .gate-badge',
            "els => els.map(e => ({text: e.textContent, cls: e.className}))",
        )
        self.assertGreater(len(badges), 0)
        self.assertIn('gate-entry', badges[0]['cls'], 'first task (no dependencies) should show the entry badge')
        self.assertEqual(badges[0]['text'], '▶')
        sequential = [b for b in badges[1:] if 'gate-seq' in b['cls']]
        self.assertTrue(sequential, 'tasks with exactly one dependency should show the sequential arrow badge')
        self.page.evaluate("""async () => {
            const rid = state.current.id;
            async function addTask(title, dependsOn, logic) {
                const res = await fetch(`/api/runbooks/${rid}/tasks`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf},
                    body: JSON.stringify({title, depends_on: dependsOn, dependency_logic: logic}),
                });
                const body = await res.json();
                state.current = body.data;
                return body.data.tasks[body.data.tasks.length - 1].id;
            }
            const a = await addTask('Gate A', [], 'and');
            const b = await addTask('Gate B', [], 'and');
            await addTask('AND join', [a, b], 'and');
            await addTask('OR join', [a, b], 'or');
            renderDetail();
        }""")
        self.page.wait_for_selector('.task h3:has-text("OR join")')
        badge_map = self.page.eval_on_selector_all(
            '.task',
            "els => els.map(el => ({title: el.querySelector('h3').textContent.trim(), badge: el.querySelector('.gate-badge')?.textContent, cls: el.querySelector('.gate-badge')?.className}))",
        )
        and_row = next(r for r in badge_map if 'AND join' in r['title'])
        or_row = next(r for r in badge_map if 'OR join' in r['title'])
        self.assertEqual(and_row['badge'], 'AND'); self.assertIn('gate-and', and_row['cls'])
        self.assertEqual(or_row['badge'], 'OR'); self.assertIn('gate-or', or_row['cls'])

    def test_escalating_and_flagging_a_task_applies_real_visual_state_via_the_ui(self):
        # toggleEscalate()/toggleIncident() used to collect their optional
        # reason via a native prompt() -- this test used to answer it via
        # Playwright's page.once('dialog', ...). Both now go through the
        # app's own formDialog() (a real <dialog>), matching the rest of the
        # app's dialog conversion, so this test fills that form instead.
        self.page.click('[data-view="runbooks"]', force=True)
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        self.page.locator('.task .escalate-btn').first.click()
        self.page.wait_for_selector('dialog.generic-dialog[open]')
        self.page.fill('dialog.generic-dialog textarea[name=reason]', 'Vendor is unresponsive')
        self.page.click('dialog.generic-dialog .modalactions .primary')
        self.page.wait_for_selector('.task.escalated')
        self.assertTrue(self.page.locator('.task.escalated .escalated-chip').is_visible())
        self.page.locator('.task.escalated .incident-btn').click()
        self.page.wait_for_selector('dialog.generic-dialog[open]')
        self.page.fill('dialog.generic-dialog textarea[name=reason]', 'Caused a brief outage')
        self.page.click('dialog.generic-dialog .modalactions .primary')
        self.page.wait_for_selector('.task.incident')
        self.assertTrue(self.page.locator('.task.incident .incident-chip').is_visible())
        self.assertTrue(self.page.locator('.task.escalated.incident').count() > 0, 'escalation must survive flagging an incident on the same task')

    def test_runbook_rows_are_keyboard_operable(self):
        self.page.click('[data-view="runbooks"]')
        row = self.page.locator('.trow[data-id]').first
        row.focus()
        self.assertTrue(row.evaluate('(element) => element === document.activeElement'))
        row.press('Enter')
        self.page.wait_for_selector('#detail.view.active')

    def test_execution_ui_reflows_without_horizontal_page_scroll(self):
        self.page.set_viewport_size({'width': 320, 'height': 800})
        self.page.evaluate("show('runbooks')")
        overflow = self.page.evaluate('document.documentElement.scrollWidth - window.innerWidth')
        layout = self.page.evaluate("({innerWidth,media:matchMedia('(max-width: 900px)').matches,main:getComputedStyle(document.querySelector('main')).marginLeft,mainBox:document.querySelector('main').getBoundingClientRect().toJSON(),shell:document.querySelector('.shell').className})")
        offenders = self.page.evaluate("[...document.querySelectorAll('body *')].map(e=>({tag:e.tagName,id:e.id,cls:e.className&&String(e.className).slice(0,80),right:e.getBoundingClientRect().right,width:e.getBoundingClientRect().width})).filter(x=>x.right>innerWidth+1||x.width>innerWidth+1).slice(0,12)")
        self.assertLessEqual(overflow, 1, f'page overflows horizontally by {overflow}px; layout={layout}; offenders={offenders}')

    def _assert_task_execution_view_reflows_and_has_real_touch_targets(self, width, height):
        self.page.set_viewport_size({'width': width, 'height': height})
        self.page.click('#menu')  # off-canvas sidebar below 900px -- open it first, like a real mobile user would
        self.page.click('.shell.menu-open [data-view="runbooks"]')
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]', has_text='Payments platform release').first.click()
        self.page.wait_for_selector('#detail.view.active')
        self.page.wait_for_selector('.task .task-actions button')
        overflow = self.page.evaluate('document.documentElement.scrollWidth - window.innerWidth')
        self.assertLessEqual(overflow, 1, f'execution view overflows horizontally by {overflow}px at {width}x{height}')
        boxes = self.page.eval_on_selector_all(
            '.task-actions button',
            "els => els.map(el => { const r = el.getBoundingClientRect(); return {w: r.width, h: r.height}; })",
        )
        self.assertGreater(len(boxes), 0, 'expected at least one visible task action button')
        # Rounded: layout can report 43.9998px for a 44px box during the view-reveal animation.
        undersized = [b for b in boxes if round(b['w'], 1) < 44 or round(b['h'], 1) < 44]
        self.assertEqual(undersized, [], f'task action buttons under the 44x44 touch target minimum at {width}x{height}: {undersized}')

    def test_task_execution_view_reflows_and_meets_touch_targets_at_375(self):
        self._assert_task_execution_view_reflows_and_has_real_touch_targets(375, 812)

    def test_task_execution_view_reflows_and_meets_touch_targets_at_414(self):
        self._assert_task_execution_view_reflows_and_has_real_touch_targets(414, 896)

    # ---- Cutover parity ----
    def _make_runbook(self, name, tasks):
        return self.page.evaluate("""async ([name, tasks]) => {
            const rb = await api('/api/runbooks', {method: 'POST', body: JSON.stringify({name, scheduled_at: new Date().toISOString().slice(0, 16)})});
            for (const t of tasks) await api(`/api/runbooks/${rb.id}/tasks`, {method: 'POST', body: JSON.stringify(t)});
            await api(`/api/runbooks/${rb.id}/transition`, {method: 'POST', body: JSON.stringify({status: 'ready'})});
            await load();
            return rb.id;
        }""", [name, tasks])

    def test_starting_a_rehearsal_from_the_ui_shows_the_banner_and_reset_returns_it_to_ready(self):
        rid = self._make_runbook('UI rehearsal', [{'title': 'Practice step'}])
        self.page.evaluate('id => openRunbook(id)', rid)
        self.page.click('.transition[data-status=live]')
        self.page.select_option('.generic-dialog select[name=run_type]', 'rehearsal')
        self.page.click('.generic-dialog button.primary')
        self.page.wait_for_selector('.cx-runbadge.rehearsal')
        self.assertEqual(self.page.inner_text('.cx-runbadge'), 'Rehearsal')
        self.page.click('#cxResetRehearsal')
        self.page.click('.generic-confirm-dialog .gd-ok')
        self.page.wait_for_function('() => state.current && state.current.status === "ready"')
        self.assertIsNone(self.page.query_selector('#cxResetRehearsal'))
        self.page.click('[data-cx-drawer=history]')
        self.page.wait_for_selector('.run-history:not([hidden])')
        self.assertIn('Rehearsal', self.page.inner_text('.run-history'))

    def test_checklist_comments_gantt_and_excel_export_work_in_the_runbook_view(self):
        rid = self._make_runbook('UI checklist', [{'title': 'Pre-flight', 'task_type': 'checklist', 'checklist_items': ['Backups verified', 'Freeze announced']}])
        self.page.evaluate("id => api(`/api/runbooks/${id}/transition`, {method: 'POST', body: JSON.stringify({status: 'live', run_type: 'live'})})", rid)
        self.page.evaluate('id => openRunbook(id)', rid)
        self.page.click('#tasks .task.cx-row .cx-open')
        self.page.wait_for_selector('.cx-panel .task-checklist input')
        self.page.check('.cx-panel .task-checklist input[data-index="0"]')
        self.page.wait_for_function('() => state.current.tasks[0].checklist[0].done === true')
        self.page.click('#tasks .task-comment-toggle')
        self.page.fill('.cx-panel .task-thread input[name=body]', 'Backups confirmed by DBA')
        self.page.click('.cx-panel .task-thread button.primary')
        self.page.wait_for_function('() => state.current.tasks[0].comments.length === 1')
        self.assertIn('Backups confirmed by DBA', self.page.inner_text('.cx-panel .task-thread'))
        self.assertEqual(self.page.inner_text('#tasks .cx-count'), '1')
        self.page.click('[data-gantt]')
        self.page.wait_for_selector('.gantt .gantt-bar')
        self.assertEqual(len(self.page.query_selector_all('.gantt-row')), 1)
        self.assertIsNotNone(self.page.query_selector('#exportTasksXlsx'))

    def test_my_tasks_view_lists_assigned_work_and_starts_it(self):
        user_id = self.page.evaluate('state.user.id')
        rid = self._make_runbook('UI my tasks', [{'title': 'Mine to start', 'owner_user_id': user_id}])
        self.page.evaluate("id => api(`/api/runbooks/${id}/transition`, {method: 'POST', body: JSON.stringify({status: 'live', run_type: 'live'})})", rid)
        self.page.click('.nav[data-view=mytasks]')
        self.page.wait_for_selector('.mytask')
        self.assertIn('/my-tasks', self.page.url)
        card = self.page.locator('.mytask', has_text='Mine to start')
        card.locator('button[data-status=running]').click()
        self.page.wait_for_function("() => [...document.querySelectorAll('.mytask')].some(el => el.textContent.includes('Mine to start') && el.textContent.includes('running'))")
        self.page.set_viewport_size({'width': 390, 'height': 844})
        overflow = self.page.evaluate('document.documentElement.scrollWidth - window.innerWidth')
        self.assertLessEqual(overflow, 1)

    def test_runbooks_timeline_view_plots_scheduled_runbooks(self):
        self._make_runbook('UI timeline', [{'title': 'Plotted', 'duration': 30}])
        self.page.click('.nav[data-view=runbooks]')
        self.page.click('[data-portfolio=timeline]')
        self.page.wait_for_selector('#portfolioTimeline .gantt-row')
        self.assertIn('UI timeline', self.page.inner_text('#portfolioTimeline'))
        self.assertTrue(self.page.locator('#runbookTable').is_hidden())
        self.page.click('[data-portfolio=list]')
        self.assertTrue(self.page.locator('#runbookTable').is_visible())

    def test_task_panel_is_padded_and_its_header_does_not_overlap_the_timing_card(self):
        rid = self._make_runbook('UI panel geometry', [{'title': 'A task with a long enough title to wrap onto two lines in the panel'}])
        self.page.evaluate('id => openRunbook(id)', rid)
        self.page.click('#tasks .task.cx-row .cx-open')
        self.page.wait_for_selector('.cx-panel')
        geometry = self.page.evaluate("""() => {
            const side = document.querySelector('.detail-side').getBoundingClientRect();
            const q = s => document.querySelector(s).getBoundingClientRect();
            const touching = [...document.querySelectorAll('.cx-panel .cx-pbody *, .cx-panel .cx-ph *')].filter(e => { const r = e.getBoundingClientRect(); return r.width && (r.left < side.left + 8 || r.right > side.right - 8); }).length;
            return {chipsBottom: q('.cx-ph .cx-chips').bottom, headerBottom: q('.cx-ph').bottom, cardTop: q('.cx-timecard').top, touching};
        }""")
        self.assertLessEqual(geometry['chipsBottom'], geometry['headerBottom'])
        self.assertLess(geometry['headerBottom'], geometry['cardTop'])
        self.assertEqual(geometry['touching'], 0, 'panel content must keep its padding from the panel edges')

    def test_plan_views_and_admin_matrices_do_not_overflow_the_page_on_a_phone(self):
        self.page.set_viewport_size({'width': 390, 'height': 844})
        self.page.evaluate("openRunbook(state.runbooks.find(r => r.name === 'Payments platform release').id)")
        self.page.wait_for_selector('.cx-row')
        for selector in ('[data-mode=map]', '[data-gantt]', '[data-cx-table]'):
            self.page.click(selector)
            self.page.wait_for_timeout(150)
            overflow = self.page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
            self.assertLessEqual(overflow, 0, f'{selector} overflows the page by {overflow}px')
        for tool in ('roles', 'sessions'):
            self.page.evaluate(f"show('admin'); openAdminTool('{tool}')")
            self.page.wait_for_timeout(400)
            overflow = self.page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
            self.assertLessEqual(overflow, 0, f'admin {tool} overflows the page by {overflow}px')

    def test_serviceops_events_and_writeback_cards_generate_a_secret_shown_once(self):
        self.page.evaluate("show('admin'); openAdminTool('connections')")
        self.page.wait_for_selector('.so-events-card')
        self.assertIn('/api/integrations/serviceops/events/flowops', self.page.inner_text('.so-receiver'))
        self.page.wait_for_selector('.so-outbox p, .so-outbox .so-outbox-row')
        self.page.click('#soGenerateSecret')
        self.page.wait_for_selector('#soSecretValue')
        secret = self.page.inner_text('#soSecretValue')
        self.assertTrue(secret.startswith('whsec_'))
        self.assertIn('Receiving', self.page.inner_text('.so-events-card .connection-state'))
        # The secret is never sent back to the browser after this response.
        integrations = self.page.evaluate("api('/api/admin/integrations')")
        self.assertNotIn(secret, str(integrations))
        self.page.set_viewport_size({'width': 390, 'height': 844})
        self.page.wait_for_timeout(200)
        overflow = self.page.evaluate('document.documentElement.scrollWidth - document.documentElement.clientWidth')
        self.assertLessEqual(overflow, 0, f'ServiceOps connection cards overflow the page by {overflow}px')
        self.page.evaluate("api('/api/admin/integrations/serviceops/events-secret', {method:'POST', body: JSON.stringify({revoke:true})})")

    def test_withdrawn_serviceops_change_shows_an_alert_on_the_runbook(self):
        rid = self._make_runbook('Withdrawn change UI', [{'title': 'Step'}])
        with server.connect() as db:
            db.execute("UPDATE runbooks SET serviceops_ticket='CHG0000900',serviceops_state='Cancelled',serviceops_alert=? WHERE id=?",
                       ('ServiceOps change CHG0000900 is now Cancelled. The work is no longer authorised; confirm with the change manager before continuing.', rid))
            db.commit()
        self.page.evaluate('id => openRunbook(id)', rid)
        self.page.wait_for_selector('#soAlert')
        self.assertTrue(self.page.is_visible('#soAlert'))
        self.assertEqual(self.page.get_attribute('#soAlert', 'role'), 'alert')
        self.assertIn('CHG0000900 is now Cancelled', self.page.inner_text('#soAlert'))

    def test_administration_sidenav_heading_is_readable(self):
        self.page.evaluate("show('admin')")
        color = self.page.eval_on_selector('.admin-sidenav-head strong', 'e => getComputedStyle(e).color')
        self.assertNotEqual(color, 'rgb(215, 217, 228)', 'admin heading inherited the dark-sidebar text colour on a white panel')


if __name__ == '__main__':
    unittest.main()
