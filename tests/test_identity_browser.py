"""Real-Chrome coverage for the sign-in and identity UI: no pre-filled
credentials, the multi-factor sign-in step, MFA enrolment from the profile,
and the Sign-in & identity administration pane against a real slapd."""
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
os.environ.setdefault("FLOWOPS_DB", tmp.name)
os.environ["FLOWOPS_PREVIEW_TOKENS"] = "true"
os.environ["FLOWOPS_BOOTSTRAP_PASSWORD"] = "FlowOps!Preview2026"
os.environ["FLOWOPS_BOOTSTRAP_EMAIL"] = "admin@flowops.local"
os.environ["FLOWOPS_SETTINGS_ENCRYPTION_KEY"] = "a1J1M20wV3JlbklvNWt1a2NTYk9pQ3VHTW5PRzFjTFI="
sys.path.insert(0, os.path.dirname(__file__))

import flowops.crypto  # noqa: E402
import flowops.db  # noqa: E402
import flowops.ratelimit  # noqa: E402
import flowops.schema  # noqa: E402
import flowops.web.handler  # noqa: E402
from flowops import identity  # noqa: E402
import ldap_server  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

PASSWORD = "Browser-Mfa-Test-2026"


@unittest.skipIf(sync_playwright is None, "playwright is not installed")
class IdentityBrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flowops.schema.init_db()
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), flowops.web.handler.Handler)
        cls.base = f"http://127.0.0.1:{cls.http.server_port}"
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        cls.limits = [patch.object(flowops.ratelimit, "LOGIN_RATE_LIMIT_PER_IP", 100000),
                      patch.object(flowops.ratelimit, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 100000)]
        for limit in cls.limits:
            limit.start()
        cls.playwright = sync_playwright().start()
        options = {"channel": os.environ["FLOWOPS_BROWSER_CHANNEL"]} if os.getenv("FLOWOPS_BROWSER_CHANNEL") else {}
        cls.browser = cls.playwright.chromium.launch(**options)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        for limit in cls.limits:
            limit.stop()
        cls.http.shutdown()

    def setUp(self):
        self.errors = []
        self.page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        with flowops.db.connect() as db:
            self.saved = [tuple(r) for r in db.execute("SELECT instance_id,key,value,updated_at FROM instance_settings")]

    def tearDown(self):
        self.page.close()
        with flowops.db.connect() as db:
            db.execute("DELETE FROM instance_settings")
            db.executemany("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?)", self.saved)
            db.execute("DELETE FROM integration_credentials WHERE provider='ldap'")
            db.execute("DELETE FROM users WHERE auth_provider='ldap'")
            db.commit()
        self.assertEqual(self.errors, [], "JavaScript errors on the page")

    def sign_in(self, username, password):
        self.page.goto(self.base)
        self.page.wait_for_selector("#enterpriseLoginForm:not([hidden])")
        self.page.fill("#loginIdentity", username)
        self.page.fill("#loginPassword", password)
        self.page.click("#enterpriseLoginForm .login-button")

    def make_user(self, username):
        with flowops.db.connect() as db:
            db.execute("DELETE FROM users WHERE username=?", (username,))
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) "
                       "VALUES(?,?,?,?,?,?,?,(SELECT id FROM instances ORDER BY id LIMIT 1))",
                       (username, "Browser Member", "", "Member", "", flowops.crypto.password_hash(PASSWORD), flowops.db.now()))
            db.commit()

    def test_sign_in_page_ships_no_credentials(self):
        self.page.goto(self.base)
        self.page.wait_for_selector("#enterpriseLoginForm")
        html = self.page.content()
        self.assertNotIn("FlowOps!Preview2026", html)
        self.assertEqual(self.page.input_value("#loginIdentity"), "")
        self.assertEqual(self.page.input_value("#loginPassword"), "")
        source = self.page.evaluate("fetch('/').then(r=>r.text())")
        self.assertNotIn("Preview2026", source)

    def test_enrol_mfa_from_the_profile_then_sign_in_with_a_code(self):
        self.make_user("browser-mfa")
        self.sign_in("browser-mfa", PASSWORD)
        self.page.wait_for_selector(".shell:not(.app-hidden)")
        self.page.click("#accountMenuToggle")
        self.page.click("#openProfile")
        self.page.click('[data-ptab="security"]')
        self.page.fill("#mfaSetupForm input[name=password]", PASSWORD)
        self.page.click("#mfaSetupForm .primary")
        secret = self.page.inner_text(".secret-box").replace(" ", "")
        self.page.fill("#mfaEnableForm input[name=code]", identity.totp_code(secret))
        self.page.click("#mfaEnableForm .primary")
        self.page.wait_for_selector(".backup-codes")
        self.assertEqual(self.page.locator(".backup-codes span").count(), identity.BACKUP_CODE_COUNT)
        self.page.click("#backupCodesDone")
        self.page.wait_for_selector("#mfaManageForm")
        self.assertIn("10 backup codes left", self.page.inner_text("#profileTabSecurity"))
        # A fresh browser now gets the verification step.
        self.page.close()
        self.page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.sign_in("browser-mfa", PASSWORD)
        self.page.wait_for_selector("#mfaForm:not([hidden])")
        self.assertTrue(self.page.locator("#enterpriseLoginForm").is_hidden())
        self.page.fill("#mfaCode", "000000")
        self.page.click("#mfaForm .login-button")
        self.page.wait_for_selector("#toast:has-text('Invalid verification code')")
        self.page.fill("#mfaCode", identity.totp_code(secret, at=time.time() + 30))
        self.page.click("#mfaForm .login-button")
        self.page.wait_for_selector(".shell:not(.app-hidden)")

    @unittest.skipUnless(ldap_server.available(), "slapd is not installed")
    def test_identity_pane_configures_and_tests_the_directory(self):
        directory = ldap_server.LdapServer().start()
        try:
            self.sign_in("admin", "FlowOps!Preview2026")
            self.page.wait_for_selector(".shell:not(.app-hidden)")
            self.page.evaluate("show('admin',{skipHistory:true}); openAdminTool('identity')")
            form = "#ldapForm"
            self.page.wait_for_selector(form)
            self.page.check(f"{form} input[name=enabled]")
            self.page.fill(f"{form} input[name=url]", directory.url)
            self.page.fill(f"{form} input[name=domain]", "flowops.test")
            self.page.fill(f"{form} input[name=base_dn]", ldap_server.SUFFIX)
            self.page.fill(f"{form} input[name=bind_dn]", ldap_server.SERVICE_DN)
            self.page.fill(f"{form} input[name=credential]", ldap_server.SERVICE_PASSWORD)
            self.page.click(f"{form} [data-preset=openldap]")
            self.page.uncheck(f"{form} input[name=start_tls]")
            self.page.click(f'{form} [data-add-mapping="role_mappings"]')
            row = f'{form} [data-mapping="role_mappings"] .mapping-row'
            self.page.fill(f"{row} input", "gg_flowops_editors")
            self.page.select_option(f"{row} select", "Editor")
            self.page.click("#testLdap")
            self.page.wait_for_selector("#ldapTest:has-text('base DN readable')")
            self.page.click(f"{form} .form-actions .primary")
            self.page.wait_for_selector("#toast:has-text('Directory settings saved')")
            self.page.wait_for_selector(f'{row} input[value="gg_flowops_editors"]')
            self.page.fill("#checkUserForm input[name=username]", "erin")
            self.page.click("#checkUserForm button")
            self.page.wait_for_selector("#checkUserResult:has-text('Can sign in')")
            self.assertIn("Editor", self.page.inner_text("#checkUserResult"))
            # The sign-in page now offers the directory by its domain.
            context = self.browser.new_context()
            page = context.new_page()
            page.goto(self.base)
            page.wait_for_function("document.querySelector('#authSource option')?.textContent==='flowops.test'")
            page.fill("#loginIdentity", "erin")
            page.fill("#loginPassword", ldap_server.USER_PASSWORD)
            page.click("#enterpriseLoginForm .login-button")
            page.wait_for_selector(".shell:not(.app-hidden)")
            self.assertEqual(page.evaluate("state.user.role"), "Editor")
            context.close()
        finally:
            directory.stop()
