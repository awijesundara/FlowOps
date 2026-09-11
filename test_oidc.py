"""Real OIDC authorization-code + PKCE regression coverage, driven against a
throwaway local Keycloak container -- not a customer IdP, since none is
available in this environment. This is a heavy, opt-in suite (boots a real
Docker container and a real Playwright browser) kept out of the default fast
run. Enable with:

    FLOWOPS_OIDC_TEST_KEYCLOAK=1 python3 -m pytest test_oidc.py -v

Everything here is real: a real Keycloak container, real admin REST API
calls to provision a realm/client/user, a real running FlowOps instance, and
a real browser driving the actual authorization-code redirect + Keycloak
login form + PKCE token exchange + FlowOps session cookie. No mocking of the
OIDC flow itself.
"""
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest.mock import patch

SKIP_REASON = "set FLOWOPS_OIDC_TEST_KEYCLOAK=1 to run the live-Keycloak OIDC suite"
RUN = os.getenv("FLOWOPS_OIDC_TEST_KEYCLOAK") == "1"

if RUN:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.environ["FLOWOPS_DB"] = tmp.name
    os.environ["FLOWOPS_PREVIEW_TOKENS"] = "true"
    os.environ["FLOWOPS_SETTINGS_ENCRYPTION_KEY"] = "a1J1M20wV3JlbklvNWt1a2NTYk9pQ3VHTW5PRzFjTFI="
    import server
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sync_playwright = None
else:
    server = None
    sync_playwright = None


def _admin_token(base):
    body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"}).encode()
    with urllib.request.urlopen(urllib.request.Request(f"{base}/realms/master/protocol/openid-connect/token", data=body), timeout=15) as r:
        return json.loads(r.read())["access_token"]


def _admin_post(base, token, path, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{base}{path}", data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status


def _admin_get(base, token, path):
    req = urllib.request.Request(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _unrestricted_urlopen(url, data=None, headers=None, method="GET", timeout=8, allow_private_network=False, max_redirects=3):
    """Bypasses only the SSRF loopback rejection so this suite can reach a
    real local Keycloak container -- production OIDC providers sit at a
    real routable hostname, not 127.0.0.1, so this is a test-environment
    artifact, not a production gap. Same pattern as test_flowops.py's
    unrestricted_urlopen, used for the same reason."""
    return urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers or {}, method=method), timeout=timeout)


@unittest.skipUnless(RUN and sync_playwright is not None, SKIP_REASON if not RUN else "playwright is not installed")
class OidcLiveKeycloakTest(unittest.TestCase):
    """Drives the real authorization-code + PKCE flow end to end against a
    throwaway local Keycloak container, provisioned via its own admin REST
    API (no manual clicking to set up the realm/client/user)."""

    KC_PORT = 18082
    KC_BASE = f"http://127.0.0.1:{KC_PORT}"
    CONTAINER = "flowops-oidc-livetest-kc"
    REALM = "flowops-livetest"
    CLIENT_ID = "flowops"
    TEST_EMAIL = "oidc.livetest@example.com"
    TEST_PASSWORD = "OidcLiveTest!2026"

    @classmethod
    def setUpClass(cls):
        subprocess.run(["docker", "rm", "-f", cls.CONTAINER], capture_output=True)
        launch = subprocess.run(
            ["docker", "run", "-d", "--name", cls.CONTAINER, "-p", f"{cls.KC_PORT}:8080",
             "-e", "KEYCLOAK_ADMIN=admin", "-e", "KEYCLOAK_ADMIN_PASSWORD=admin",
             "quay.io/keycloak/keycloak:latest", "start-dev"],
            capture_output=True, text=True,
        )
        if launch.returncode != 0:
            raise unittest.SkipTest(f"Could not start a local Keycloak container: {launch.stderr.strip()}")
        cls._wait_for_keycloak()

        server.init_db()
        cls.http = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = f"http://127.0.0.1:{cls.http.server_port}"
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        os.environ["FLOWOPS_PUBLIC_URL"] = cls.base

        token = _admin_token(cls.KC_BASE)
        _admin_post(cls.KC_BASE, token, "/admin/realms", {"realm": cls.REALM, "enabled": True})
        _admin_post(cls.KC_BASE, token, f"/admin/realms/{cls.REALM}/clients", {
            "clientId": cls.CLIENT_ID, "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
            "redirectUris": [f"{cls.base}/auth/oidc/callback"], "webOrigins": ["*"],
        })
        clients = _admin_get(cls.KC_BASE, token, f"/admin/realms/{cls.REALM}/clients?clientId={cls.CLIENT_ID}")
        client_uuid = clients[0]["id"]
        secret_doc = _admin_get(cls.KC_BASE, token, f"/admin/realms/{cls.REALM}/clients/{client_uuid}/client-secret")
        cls.client_secret = secret_doc["value"]
        _admin_post(cls.KC_BASE, token, f"/admin/realms/{cls.REALM}/users", {
            "username": "oidclivetest", "email": cls.TEST_EMAIL, "emailVerified": True, "enabled": True,
            "firstName": "Oidc", "lastName": "Livetest",
            "credentials": [{"type": "password", "value": cls.TEST_PASSWORD, "temporary": False}],
        })

        with server.connect() as db:
            instance = db.execute("SELECT id FROM instances WHERE slug=?", (server.DEFAULT_INSTANCE_SLUG,)).fetchone()
            stamp = server.now()
            for key, value in {
                "oidc_enabled": "true",
                "oidc_url": f"{cls.KC_BASE}/realms/{cls.REALM}",
                "oidc_client_id": cls.CLIENT_ID,
            }.items():
                db.execute(
                    "INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) "
                    "ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
                    (instance["id"], key, value, stamp),
                )
            encrypted = server.settings_cipher().encrypt(cls.client_secret.encode()).decode()
            db.execute(
                "INSERT INTO integration_credentials(instance_id,provider,secret_encrypted,updated_by,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(instance_id,provider) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_at=excluded.updated_at",
                (instance["id"], "oidc", encrypted, None, stamp),
            )
            db.execute(
                "INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",
                ("oidclivetest", "OIDC Live Test", cls.TEST_EMAIL, "Member", "", server.password_hash(server.secrets.token_urlsafe(48)), stamp, instance["id"]),
            )
            db.commit()

        cls.playwright = sync_playwright().start()
        launch_options = {}
        if os.getenv("FLOWOPS_BROWSER_CHANNEL"):
            launch_options["channel"] = os.environ["FLOWOPS_BROWSER_CHANNEL"]
        cls.browser = cls.playwright.chromium.launch(**launch_options)

    @classmethod
    def _wait_for_keycloak(cls):
        for _ in range(60):
            try:
                with urllib.request.urlopen(f"{cls.KC_BASE}/realms/master", timeout=2) as r:
                    if r.status == 200:
                        return
            except Exception:
                pass
            time.sleep(1)
        raise unittest.SkipTest("Local Keycloak container did not become ready in time")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "browser", None):
            cls.browser.close()
        if getattr(cls, "playwright", None):
            cls.playwright.stop()
        if getattr(cls, "http", None):
            cls.http.shutdown()
        subprocess.run(["docker", "rm", "-f", cls.CONTAINER], capture_output=True)
        try:
            os.unlink(tmp.name)
        except FileNotFoundError:
            pass

    def test_full_authorization_code_pkce_flow_establishes_a_real_flowops_session(self):
        page = self.browser.new_page()
        patcher = patch("server.safe_urlopen", _unrestricted_urlopen)
        patcher.start()
        try:
            page.goto(f"{self.base}/auth/oidc/login")
            page.wait_for_selector("#username", timeout=15000)
            page.fill("#username", "oidclivetest")
            page.fill("#password", self.TEST_PASSWORD)
            page.click("#kc-login")
            page.wait_for_url(f"{self.base}/**", timeout=15000)
            cookies = {c["name"]: c["value"] for c in page.context.cookies()}
            self.assertIn("flowops_session", cookies, "FlowOps session cookie must be set after a successful OIDC callback")

            me_request = urllib.request.Request(f"{self.base}/api/auth/me", headers={"Cookie": f"flowops_session={cookies['flowops_session']}"})
            with urllib.request.urlopen(me_request, timeout=10) as r:
                me = json.loads(r.read())
            self.assertEqual(me["data"]["user"]["email"], self.TEST_EMAIL)
        finally:
            page.close()
            patcher.stop()

        with server.connect() as db:
            row = db.execute("SELECT * FROM audit WHERE action='auth.oidc_login' ORDER BY id DESC LIMIT 1").fetchone()
            self.assertIsNotNone(row, "a real auth.oidc_login audit row must be written")
            self.assertIn(self.TEST_EMAIL, row["detail"])

    def test_login_is_rejected_when_no_active_flowops_account_matches_the_oidc_email(self):
        with server.connect() as db:
            token = _admin_token(self.KC_BASE)
            _admin_post(self.KC_BASE, token, f"/admin/realms/{self.REALM}/users", {
                "username": "oidc-unmatched", "email": "no-such-flowops-user@example.com", "emailVerified": True,
                "enabled": True, "firstName": "Oidc", "lastName": "Unmatched",
                "credentials": [{"type": "password", "value": "Unmatched!2026", "temporary": False}],
            })
        page = self.browser.new_page()
        patcher = patch("server.safe_urlopen", _unrestricted_urlopen)
        patcher.start()
        try:
            page.goto(f"{self.base}/auth/oidc/login")
            page.wait_for_selector("#username", timeout=15000)
            page.fill("#username", "oidc-unmatched")
            page.fill("#password", "Unmatched!2026")
            page.click("#kc-login")
            page.wait_for_load_state("networkidle", timeout=15000)
            body_text = page.inner_text("body")
            self.assertIn("No active FlowOps account matches", body_text)
            cookies = {c["name"]: c["value"] for c in page.context.cookies()}
            self.assertNotIn("flowops_session", cookies)
        finally:
            page.close()
            patcher.stop()


if __name__ == "__main__":
    unittest.main()
