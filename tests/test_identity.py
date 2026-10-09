"""Sign-in parity with ServiceOps: native AD/LDAP (against a real slapd),
group-to-role/team mapping, Keycloak/OIDC claim mapping, TOTP multi-factor,
persistent lockout, local sign-in policy and the bootstrap account rules."""
import contextlib
import http.cookiejar
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp.close()
os.environ.setdefault("FLOWOPS_DB", tmp.name)
os.environ["FLOWOPS_PREVIEW_TOKENS"] = "true"
os.environ["FLOWOPS_SETTINGS_ENCRYPTION_KEY"] = "a1J1M20wV3JlbklvNWt1a2NTYk9pQ3VHTW5PRzFjTFI="
os.environ["FLOWOPS_BOOTSTRAP_PASSWORD"] = "FlowOps!Preview2026"
os.environ["FLOWOPS_BOOTSTRAP_EMAIL"] = "admin@flowops.local"
sys.path.insert(0, os.path.dirname(__file__))

import flowops.config  # noqa: E402
import flowops.crypto  # noqa: E402
import flowops.db  # noqa: E402
import flowops.ratelimit  # noqa: E402
import flowops.schema  # noqa: E402
import flowops.web.handler  # noqa: E402
from flowops import identity  # noqa: E402
from flowops.web.auth import AuthRoutes  # noqa: E402
import ldap_server  # noqa: E402

ADMIN_PASSWORD = "FlowOps!Preview2026"
LOCAL_PASSWORD = "Local-Member-Test-2026"


class Client:
    """One browser: its own cookies and CSRF token."""

    def __init__(self, base):
        self.base = base
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""

    def req(self, path, method="GET", body=None):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "X-CSRF-Token": self.csrf}
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request) as response:
                payload = json.load(response)
                return response.status, payload.get("data", payload)
        except urllib.error.HTTPError as err:
            return err.code, json.load(err)

    def login(self, username, password, source="local"):
        code, body = self.req("/api/auth/login", "POST", {"username": username, "password": password, "source": source})
        if code == 200 and "csrf_token" in body:
            self.csrf = body["csrf_token"]
        return code, body

    def mfa(self, token, code):
        status, body = self.req("/api/auth/mfa", "POST", {"mfa_token": token, "code": code})
        if status == 200:
            self.csrf = body["csrf_token"]
        return status, body


def instance_id(db):
    return db.execute("SELECT id FROM instances WHERE slug=?", (flowops.config.DEFAULT_INSTANCE_SLUG,)).fetchone()["id"]


def last_audit(action):
    with flowops.db.connect() as db:
        row = db.execute("SELECT detail FROM audit WHERE action=? ORDER BY id DESC LIMIT 1", (action,)).fetchone()
        return row["detail"] if row else None


class IdentityTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flowops.schema.init_db()
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), flowops.web.handler.Handler)
        cls.base = f"http://127.0.0.1:{cls.http.server_port}"
        threading.Thread(target=cls.http.serve_forever, daemon=True).start()
        # Other test modules share this worker's in-memory login limiter.
        cls.limits = [patch.object(flowops.ratelimit, "LOGIN_RATE_LIMIT_PER_IP", 100000),
                      patch.object(flowops.ratelimit, "LOGIN_RATE_LIMIT_PER_ACCOUNT", 100000)]
        for limit in cls.limits:
            limit.start()
        cls.admin = Client(cls.base)
        code, _ = cls.admin.login("admin", ADMIN_PASSWORD)
        assert code == 200, "bootstrap admin must sign in"

    @classmethod
    def tearDownClass(cls):
        for limit in cls.limits:
            limit.stop()
        cls.http.shutdown()

    def setUp(self):
        # Test modules share one database per worker: restore every setting
        # this test changes so sign-in sources elsewhere are unaffected.
        with flowops.db.connect() as db:
            self.iid = instance_id(db)
            self.saved_settings = [tuple(row) for row in db.execute(
                "SELECT key,value,updated_at FROM instance_settings WHERE instance_id=?", (self.iid,))]

    def tearDown(self):
        with flowops.db.connect() as db:
            db.execute("DELETE FROM instance_settings WHERE instance_id=?", (self.iid,))
            db.executemany("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?)",
                           [(self.iid, *row) for row in self.saved_settings])
            db.execute("DELETE FROM integration_credentials WHERE instance_id=? AND provider='ldap'", (self.iid,))
            db.commit()

    def local_user(self, username, role="Member"):
        with flowops.db.connect() as db:
            db.execute("DELETE FROM users WHERE username=?", (username,))
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) "
                       "VALUES(?,?,?,?,?,?,?,?)", (username, username.title(), f"{username}@example.com", role, "",
                                                   flowops.crypto.password_hash(LOCAL_PASSWORD), flowops.db.now(), self.iid))
            db.commit()
            return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()["id"]

    def user(self, username):
        with flowops.db.connect() as db:
            return db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


class IdentityRulesTest(unittest.TestCase):
    def test_totp_matches_rfc6238_and_refuses_replay(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 SHA1 test key
        self.assertEqual(identity.totp_code(secret, at=59), "287082")
        self.assertEqual(identity.totp_code(secret, at=1111111109), "081804")
        step = identity.totp_match(secret, "081804", at=1111111109)
        self.assertEqual(step, 1111111109 // 30)
        self.assertIsNone(identity.totp_match(secret, "081804", after_step=step, at=1111111109))
        self.assertIsNone(identity.totp_match(secret, "000000", at=1111111109))
        self.assertIsNone(identity.totp_match(secret, "08180", at=1111111109))

    def test_role_mapping_picks_the_highest_role_and_accepts_dn_or_cn(self):
        mapping = identity.parse_mapping('{"gg_editors":"Editor","CN=gg_admins,OU=Groups,DC=corp":"Admin"}', "role")
        groups = ["cn=GG_Editors,ou=groups,dc=corp", "CN=gg_admins,OU=Groups,DC=corp"]
        self.assertEqual(identity.mapped_role(groups, mapping), ("Admin", "CN=gg_admins,OU=Groups,DC=corp"))
        self.assertEqual(identity.mapped_role([], mapping, "Stakeholder"), ("Stakeholder", None))
        with self.assertRaises(ValueError):
            identity.parse_mapping('{"gg_x":"Superuser"}', "role")
        with self.assertRaises(ValueError):
            identity.parse_mapping('["gg_x"]', "role")

    def test_login_local_part_accepts_windows_forms(self):
        for typed in ("jsmith", "CORP\\jsmith", "jsmith@corp.example.com"):
            self.assertEqual(identity.login_local_part(typed), "jsmith")


@unittest.skipUnless(ldap_server.available(), "slapd is not installed (apt install slapd ldap-utils)")
class DirectorySignInTest(IdentityTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = ldap_server.LdapServer().start()

    @classmethod
    def tearDownClass(cls):
        cls.directory.stop()
        super().tearDownClass()

    def configure(self, **overrides):
        settings = {
            "provider": "ldap", "enabled": True, "url": self.directory.url, "bind_dn": ldap_server.SERVICE_DN,
            "credential": ldap_server.SERVICE_PASSWORD, "base_dn": ldap_server.SUFFIX,
            "user_filter": "(&(objectClass=inetOrgPerson)(uid={username}))", "start_tls": False,
            "role_mappings": '{"gg_flowops_admins":"Admin","gg_flowops_editors":"Editor"}',
            "team_mappings": '{"gg_unix":"Unix","gg_network":"Network"}', "default_role": "Member",
            "require_access_group": False, "domain": "flowops.test",
        }
        settings.update(overrides)
        code, body = self.admin.req("/api/admin/integrations", "POST", settings)
        self.assertEqual(code, 200, body)

    def tearDown(self):
        with flowops.db.connect() as db:
            db.execute("DELETE FROM users WHERE auth_provider='ldap'")
            db.commit()
        super().tearDown()

    def test_connection_test_binds_the_service_account_and_reports_failures(self):
        self.configure()
        code, body = self.admin.req("/api/admin/integrations/test", "POST", {"provider": "ldap"})
        self.assertEqual(code, 200, body)
        self.assertIn("base DN readable", body["message"])
        code, body = self.admin.req("/api/admin/integrations/test", "POST", {"provider": "ldap", "credential": "wrong"})
        self.assertEqual(code, 502)
        self.assertIn("bind was rejected", body["error"])
        _, connections = self.admin.req("/api/admin/integrations")
        self.assertTrue(connections["ldap"]["credential_configured"])
        self.assertNotIn(ldap_server.SERVICE_PASSWORD, json.dumps(connections))

    def test_sources_offer_the_directory_with_its_domain(self):
        self.configure()
        _, sources = Client(self.base).req("/api/auth/sources")
        self.assertEqual(sources["default"], "ldap")
        self.assertEqual(sources["sources"][0], {"id": "ldap", "label": "flowops.test",
                                                 "placeholder": "jsmith or jsmith@flowops.test"})

    def test_directory_sign_in_creates_the_account_with_mapped_role_and_team(self):
        self.configure()
        browser = Client(self.base)
        code, body = browser.login("alice@flowops.test", ldap_server.USER_PASSWORD, "ldap")
        self.assertEqual(code, 200, body)
        self.assertEqual((body["username"], body["role"], body["team"]), ("alice", "Admin", "Unix"))
        row = self.user("alice")
        self.assertEqual((row["auth_provider"], row["external_id"], row["email"]),
                         ("ldap", self.directory.user_dn("alice"), "alice@flowops.test"))
        self.assertIn("alice created from the directory as Admin", last_audit("auth.user_provisioned"))
        code, me = browser.req("/api/auth/me")
        self.assertEqual(code, 200)
        self.assertNotIn("mfa_secret_encrypted", me["user"])
        # FLOWOPS\erin form and the Editor mapping.
        code, body = Client(self.base).login("FLOWOPS\\erin", ldap_server.USER_PASSWORD, "ldap")
        self.assertEqual((code, body["role"], body["team"]), (200, "Editor", "Network"))

    def test_role_follows_directory_group_changes(self):
        self.configure()
        self.assertEqual(Client(self.base).login("alice", ldap_server.USER_PASSWORD, "ldap")[1]["role"], "Admin")
        self.directory.set_membership("gg_flowops_admins", "alice", False)
        try:
            self.assertEqual(Client(self.base).login("alice", ldap_server.USER_PASSWORD, "ldap")[1]["role"], "Member")
        finally:
            self.directory.set_membership("gg_flowops_admins", "alice", True)

    def test_wrong_empty_and_wildcard_credentials_are_refused(self):
        self.configure()
        browser = Client(self.base)
        self.assertEqual(browser.login("alice", "not-the-password", "ldap")[0], 401)
        self.assertIn("directory rejected the password", last_audit("auth.login_failed"))
        # An empty password would be an anonymous bind; it must never sign in.
        self.assertEqual(browser.login("alice", "", "ldap")[0], 401)
        self.assertIn("empty password", last_audit("auth.login_failed"))
        self.assertEqual(browser.login("*", ldap_server.USER_PASSWORD, "ldap")[0], 401)
        self.assertEqual(browser.login("al*", ldap_server.USER_PASSWORD, "ldap")[0], 401)

    def test_required_access_group_refuses_unmapped_users(self):
        self.configure(require_access_group=True)
        code, body = Client(self.base).login("bob", ldap_server.USER_PASSWORD, "ldap")
        self.assertEqual((code, body["error"]), (401, "Invalid username or password"))
        self.assertIn("not in a mapped access group", last_audit("auth.login_failed"))
        self.assertIsNone(self.user("bob"))

    def test_directory_account_cannot_take_over_the_local_administrator(self):
        self.configure()
        code, _ = Client(self.base).login("admin", ldap_server.USER_PASSWORD, "ldap")
        self.assertEqual(code, 401)
        self.assertIn("belongs to a local administrator", last_audit("auth.login_blocked"))
        admin = self.user("admin")
        self.assertEqual((admin["auth_provider"], admin["display_name"]), ("local", "Administrator"))

    def test_directory_accounts_cannot_use_local_password_paths(self):
        self.configure()
        Client(self.base).login("erin", ldap_server.USER_PASSWORD, "ldap")
        code, body = Client(self.base).req("/api/auth/password-reset/request", "POST", {"identity": "erin"})
        self.assertEqual(code, 202)
        self.assertNotIn("preview_token", body)
        with flowops.db.connect() as db:
            uid = db.execute("SELECT id FROM users WHERE username='erin'").fetchone()["id"]
        code, body = self.admin.req(f"/api/admin/users/{uid}", "PATCH", {"password": "A-new-local-password-1"})
        self.assertEqual(code, 409)

    def test_check_user_explains_what_sign_in_would_grant(self):
        self.configure()
        code, body = self.admin.req("/api/admin/directory/check", "POST", {"username": "alice"})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["found"] and body["allowed"])
        self.assertEqual((body["role"], body["team"], body["group_count"]), ("Admin", "Unix", 2))
        code, body = self.admin.req("/api/admin/directory/check", "POST", {"username": "nobody"})
        self.assertEqual((code, body["found"]), (200, False))
        code, _ = Client(self.base).req("/api/admin/directory/check", "POST", {"username": "alice"})
        self.assertEqual(code, 401)

    def test_invalid_directory_settings_are_rejected(self):
        for overrides, message in (({"url": "http://dc.example"}, "ldap://"),
                                   ({"role_mappings": '{"gg":"Root"}'}, "Role mapping"),
                                   ({"user_filter": "uid={username}"}, "parentheses"),
                                   ({"default_role": "Owner"}, "Default role")):
            code, body = self.admin.req("/api/admin/integrations", "POST", {"provider": "ldap", **overrides})
            self.assertEqual(code, 400, overrides)
            self.assertIn(message, body["error"])

    def test_directory_outage_is_reported_without_counting_a_failure(self):
        self.configure(url="ldap://127.0.0.1:1")
        code, body = Client(self.base).login("alice", ldap_server.USER_PASSWORD, "ldap")
        self.assertEqual(code, 503)
        self.assertIn("directory is unavailable", body["error"])


class MultiFactorTest(IdentityTestBase):
    def enrol(self, username):
        self.local_user(username)
        browser = Client(self.base)
        self.assertEqual(browser.login(username, LOCAL_PASSWORD)[0], 200)
        code, setup = browser.req("/api/profile/mfa/setup", "POST", {"password": "wrong"})
        self.assertEqual(code, 401)
        code, setup = browser.req("/api/profile/mfa/setup", "POST", {"password": LOCAL_PASSWORD})
        self.assertEqual(code, 200, setup)
        self.assertTrue(setup["otpauth_uri"].startswith("otpauth://totp/FlowOps%3A"))
        code, _ = browser.req("/api/profile/mfa/enable", "POST", {"code": "000000"})
        self.assertEqual(code, 400)
        code, enabled = browser.req("/api/profile/mfa/enable", "POST", {"code": identity.totp_code(setup["secret"])})
        self.assertEqual(code, 200, enabled)
        self.assertEqual(len(enabled["backup_codes"]), identity.BACKUP_CODE_COUNT)
        return browser, setup["secret"], enabled["backup_codes"]

    def test_sign_in_requires_a_fresh_code_or_a_single_use_backup_code(self):
        _, secret, backups = self.enrol("mfa-user")
        browser = Client(self.base)
        code, body = browser.login("mfa-user", LOCAL_PASSWORD)
        self.assertEqual((code, body["mfa_required"]), (200, True))
        self.assertNotIn("csrf_token", body)
        self.assertEqual(browser.req("/api/auth/me")[0], 401)
        self.assertEqual(browser.mfa(body["mfa_token"], "123456")[0], 401)
        # The enrolment code's time step is spent; the next one is accepted.
        self.assertEqual(browser.mfa(body["mfa_token"], identity.totp_code(secret))[0], 401)
        code, session = browser.mfa(body["mfa_token"], identity.totp_code(secret, at=time.time() + 30))
        self.assertEqual(code, 200, session)
        self.assertEqual(browser.req("/api/auth/me")[0], 200)
        self.assertIn("with MFA (totp)", last_audit("auth.login"))
        # Backup codes work once.
        second = Client(self.base)
        token = second.login("mfa-user", LOCAL_PASSWORD)[1]["mfa_token"]
        code, session = second.mfa(token, backups[0].upper())
        self.assertEqual(code, 200)
        self.assertIn("backup code", session["notice"])
        third = Client(self.base)
        token = third.login("mfa-user", LOCAL_PASSWORD)[1]["mfa_token"]
        self.assertEqual(third.mfa(token, backups[0])[0], 401)
        self.assertEqual(third.mfa(token, backups[1])[0], 200)

    def test_challenges_expire_after_five_wrong_codes(self):
        _, secret, _ = self.enrol("mfa-tries")
        browser = Client(self.base)
        token = browser.login("mfa-tries", LOCAL_PASSWORD)[1]["mfa_token"]
        for _ in range(5):
            self.assertEqual(browser.mfa(token, "000000")[0], 401)
        self.assertEqual(browser.mfa(token, identity.totp_code(secret, at=time.time() + 30))[0], 401)
        self.assertIn("invalid verification code", last_audit("auth.mfa_failed"))

    def test_disabling_needs_a_code_and_admin_reset_signs_the_user_out(self):
        browser, secret, backups = self.enrol("mfa-reset")
        self.assertEqual(browser.req("/api/profile/mfa/disable", "POST", {"code": "000000"})[0], 400)
        code, regenerated = browser.req("/api/profile/mfa/backup-codes", "POST", {"code": backups[0]})
        self.assertEqual(code, 200)
        self.assertNotIn(backups[1], regenerated["backup_codes"])
        uid = self.user("mfa-reset")["id"]
        code, _ = self.admin.req(f"/api/admin/users/{uid}/reset-mfa", "POST", {})
        self.assertEqual(code, 200)
        self.assertEqual(browser.req("/api/auth/me")[0], 401)
        row = self.user("mfa-reset")
        self.assertEqual((row["mfa_enabled"], row["mfa_secret_encrypted"]), (0, None))
        code, body = Client(self.base).login("mfa-reset", LOCAL_PASSWORD)
        self.assertEqual(code, 200)
        self.assertNotIn("mfa_required", body)

    def test_password_change_voids_a_pending_challenge(self):
        browser, secret, _ = self.enrol("mfa-void")
        pending = Client(self.base)
        token = pending.login("mfa-void", LOCAL_PASSWORD)[1]["mfa_token"]
        code, _ = browser.req("/api/profile/change-password", "POST",
                              {"current_password": LOCAL_PASSWORD, "new_password": "Another-Password-2026"})
        self.assertEqual(code, 200)
        self.assertEqual(pending.mfa(token, identity.totp_code(secret, at=time.time() + 30))[0], 401)


class LockoutAndPolicyTest(IdentityTestBase):
    def test_repeated_failures_lock_the_account_until_an_admin_unlocks_it(self):
        uid = self.local_user("lockout-user")
        browser = Client(self.base)
        for _ in range(5):
            self.assertEqual(browser.login("lockout-user", "wrong-password")[0], 401)
        code, body = browser.login("lockout-user", LOCAL_PASSWORD)
        self.assertEqual(code, 423)
        self.assertIn("temporarily locked", body["error"])
        self.assertIn("lockout-user locked", last_audit("auth.account_locked"))
        _, users = self.admin.req("/api/admin/users")
        listed = next(user for user in users if user["username"] == "lockout-user")
        self.assertIsNotNone(listed["locked_until"])
        self.assertEqual(self.admin.req(f"/api/admin/users/{uid}/unlock", "POST", {})[0], 200)
        self.assertEqual(browser.login("lockout-user", LOCAL_PASSWORD)[0], 200)

    def test_lockout_threshold_is_configurable_and_validated(self):
        self.assertEqual(self.admin.req("/api/admin/settings", "POST", {"login_max_attempts": "0"})[0], 400)
        self.assertEqual(self.admin.req("/api/admin/settings", "POST", {"login_max_attempts": "2"})[0], 200)
        self.local_user("lockout-two")
        browser = Client(self.base)
        browser.login("lockout-two", "wrong-password")
        browser.login("lockout-two", "wrong-password")
        self.assertEqual(browser.login("lockout-two", LOCAL_PASSWORD)[0], 423)

    def test_local_sign_in_can_be_disabled_except_for_administrators(self):
        self.local_user("local-member")
        self.assertEqual(self.admin.req("/api/admin/settings", "POST", {"local_auth_enabled": "false"})[0], 200)
        code, body = Client(self.base).login("local-member", LOCAL_PASSWORD)
        self.assertEqual(code, 403)
        self.assertIn("Local sign-in is disabled", body["error"])
        self.assertEqual(Client(self.base).login("admin", ADMIN_PASSWORD)[0], 200)


class OidcMappingTest(IdentityTestBase):
    ISSUER = "https://sso.example/realms/ops"

    def account(self, claims, **settings):
        values = {"oidc_role_claim": "realm_access.roles", "oidc_default_role": "Member",
                  "oidc_role_mappings": '{"flowops-editors":"Editor","flowops-admins":"Admin"}',
                  "oidc_team_mappings": '{"unix":"Unix"}', "oidc_auto_provision": "true", "oidc_required_acr": ""}
        values.update(settings)
        with flowops.db.connect() as db:
            user, problem = AuthRoutes.oidc_account(None, db, self.iid, values, self.ISSUER, claims)
            db.commit()
            return (dict(user) if user else None), problem

    def tearDown(self):
        with flowops.db.connect() as db:
            db.execute("DELETE FROM users WHERE auth_provider='oidc' OR username LIKE 'kc-%'")
            db.commit()
        super().tearDown()

    def test_new_identities_get_mapped_role_and_team_when_auto_provisioning(self):
        user, problem = self.account({"sub": "kc-1", "preferred_username": "kc-editor", "email": "kc@example.com",
                                      "email_verified": True, "realm_access": {"roles": ["flowops-editors", "unix"]}})
        self.assertIsNone(problem)
        self.assertEqual((user["role"], user["team"], user["auth_provider"], user["external_id"]),
                         ("Editor", "Unix", "oidc", f"{self.ISSUER}|kc-1"))
        # Same subject later gains the admin role.
        user, _ = self.account({"sub": "kc-1", "preferred_username": "kc-editor",
                                "realm_access": {"roles": ["flowops-admins"]}})
        self.assertEqual(user["role"], "Admin")

    def test_unknown_identities_are_refused_without_auto_provisioning(self):
        user, problem = self.account({"sub": "kc-2", "preferred_username": "kc-nobody"}, oidc_auto_provision="false")
        self.assertIsNone(user)
        self.assertEqual(problem, "no matching FlowOps account")

    def test_required_assurance_level_is_enforced(self):
        claims = {"sub": "kc-3", "preferred_username": "kc-acr", "acr": "1"}
        self.assertIn("assurance level 1 is not 2", self.account(claims, oidc_required_acr="2")[1])
        self.assertIsNone(self.account({**claims, "acr": "2"}, oidc_required_acr="2")[1])

    def test_verified_email_links_the_local_admin_without_changing_its_role(self):
        user, problem = self.account({"sub": "kc-4", "preferred_username": "someone-else", "email": "admin@flowops.local",
                                      "email_verified": True, "realm_access": {"roles": []}})
        self.assertIsNone(problem)
        self.assertEqual((user["username"], user["role"], user["auth_provider"]), ("admin", "Admin", "local"))
        # An unverified email never links an existing account.
        user, problem = self.account({"sub": "kc-5", "preferred_username": "kc-unverified", "email": "admin@flowops.local",
                                      "email_verified": False}, oidc_auto_provision="false")
        self.assertIsNone(user)

    def test_oidc_policy_is_saved_through_the_connections_api(self):
        code, body = self.admin.req("/api/admin/integrations", "POST", {
            "provider": "oidc", "role_mappings": '{"flowops-admins":"Admin"}', "auto_provision": True,
            "required_acr": "2", "role_claim": "groups"})
        self.assertEqual(code, 200, body)
        _, connections = self.admin.req("/api/admin/integrations")
        self.assertEqual((connections["oidc"]["auto_provision"], connections["oidc"]["required_acr"],
                          connections["oidc"]["role_claim"]), ("true", "2", "groups"))
        self.assertEqual(json.loads(connections["oidc"]["role_mappings"]), {"flowops-admins": "Admin"})


class BootstrapTest(unittest.TestCase):
    def fresh_db(self):
        path = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
        os.unlink(path)
        return path

    def test_unset_bootstrap_password_generates_a_one_time_secret(self):
        path = self.fresh_db()
        output = io.StringIO()
        with patch.object(flowops.db, "DB_PATH", path), patch("flowops.schema.DB_PATH", path), \
                patch.dict(os.environ, {"FLOWOPS_BOOTSTRAP_PASSWORD": ""}), contextlib.redirect_stdout(output):
            flowops.schema.init_db()
        printed = next(json.loads(line) for line in output.getvalue().splitlines() if "bootstrap_password" in line)
        row = sqlite3.connect(path).execute("SELECT password_hash,display_name FROM users WHERE username='admin'").fetchone()
        self.assertTrue(flowops.crypto.password_valid(printed["bootstrap_password"], row[0]))
        self.assertFalse(flowops.crypto.password_valid("FlowOps!Preview2026", row[0]))
        self.assertEqual(row[1], "Administrator")
        users = [r[0] for r in sqlite3.connect(path).execute("SELECT username FROM users")]
        self.assertEqual(users, ["admin"])
        os.unlink(path)

    def test_a_seeded_operator_with_its_published_password_is_disabled(self):
        path = self.fresh_db()
        with patch.object(flowops.db, "DB_PATH", path), patch("flowops.schema.DB_PATH", path):
            flowops.schema.init_db()
            with flowops.db.connect() as db:
                db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) "
                           "VALUES('operator','Release Operator','','Member','',?,?,(SELECT id FROM instances LIMIT 1))",
                           (flowops.crypto.password_hash("Operator!Preview2026"), flowops.db.now()))
                db.commit()
            flowops.schema.init_db()
            with flowops.db.connect() as db:
                self.assertEqual(db.execute("SELECT active FROM users WHERE username='operator'").fetchone()[0], 0)
                self.assertTrue(db.execute("SELECT 1 FROM audit WHERE action='auth.default_account_disabled'").fetchone())
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
