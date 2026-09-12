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

    def test_notification_bell_has_no_visible_badge_with_no_unread_activity(self):
        badge = self.page.query_selector('.unread-count')
        self.assertIsNotNone(badge, "unread-count badge element should exist in the DOM")
        self.assertFalse(badge.is_visible(), "badge must be hidden when there is nothing unread")

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
        self.page.locator('.trow[data-id]').first.click()
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
        self.page.locator('.trow[data-id]').first.click()
        self.page.wait_for_selector('#detail.view.active')
        position = self.page.evaluate("getComputedStyle(document.querySelector('aside')).position")
        self.assertEqual(position, 'fixed', "the primary nav sidebar must be truly fixed, not sticky, so it never drifts during scroll")
        before = self.page.eval_on_selector('aside', "el => { const r = el.getBoundingClientRect(); return {x: r.x, y: r.y}; }")
        self.page.mouse.wheel(0, 1500)
        self.page.wait_for_timeout(100)
        after = self.page.eval_on_selector('aside', "el => { const r = el.getBoundingClientRect(); return {x: r.x, y: r.y}; }")
        self.assertEqual(before, after, "the sidebar must not move at all while the page scrolls")

    def test_modal_close_buttons_are_square_icon_buttons_not_stretched(self):
        self.page.click('#openProfile')
        self.page.wait_for_selector('#profileModal[open]')
        box = self.page.eval_on_selector('.close-profile', "el => { const r = el.getBoundingClientRect(); return {w: r.width, h: r.height}; }")
        self.assertLess(box['h'], 60, f"profile modal close button is stretched tall: {box}")
        self.assertAlmostEqual(box['w'], box['h'], delta=4, msg=f"close button should be roughly square: {box}")

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
        self.page.locator('.trow[data-id]').first.click()
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
        self.page.locator('.trow[data-id]').first.click()
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
        self.page.locator('.trow[data-id]').first.click()
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
        self.assertLessEqual(overflow, 1, f'page overflows horizontally by {overflow}px')

    def _assert_task_execution_view_reflows_and_has_real_touch_targets(self, width, height):
        self.page.set_viewport_size({'width': width, 'height': height})
        self.page.click('#menu')  # off-canvas sidebar below 900px -- open it first, like a real mobile user would
        self.page.click('.shell.menu-open [data-view="runbooks"]')
        self.page.wait_for_selector('#runbooks.view.active')
        self.page.locator('.trow[data-id]').first.click()
        self.page.wait_for_selector('#detail.view.active')
        self.page.wait_for_selector('.task .task-actions button')
        overflow = self.page.evaluate('document.documentElement.scrollWidth - window.innerWidth')
        self.assertLessEqual(overflow, 1, f'execution view overflows horizontally by {overflow}px at {width}x{height}')
        boxes = self.page.eval_on_selector_all(
            '.task-actions button',
            "els => els.map(el => { const r = el.getBoundingClientRect(); return {w: r.width, h: r.height}; })",
        )
        self.assertGreater(len(boxes), 0, 'expected at least one visible task action button')
        undersized = [b for b in boxes if b['w'] < 44 or b['h'] < 44]
        self.assertEqual(undersized, [], f'task action buttons under the 44x44 touch target minimum at {width}x{height}: {undersized}')

    def test_task_execution_view_reflows_and_meets_touch_targets_at_375(self):
        self._assert_task_execution_view_reflows_and_has_real_touch_targets(375, 812)

    def test_task_execution_view_reflows_and_meets_touch_targets_at_414(self):
        self._assert_task_execution_view_reflows_and_has_real_touch_targets(414, 896)


if __name__ == '__main__':
    unittest.main()
