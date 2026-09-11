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
