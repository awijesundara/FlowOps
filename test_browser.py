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


if __name__ == '__main__':
    unittest.main()
