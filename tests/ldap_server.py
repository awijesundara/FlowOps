"""A throwaway OpenLDAP server for directory sign-in tests.

Starts slapd (if installed) on a free localhost port with an mdb database,
the memberOf overlay and a self-signed certificate for LDAPS, then loads a
small organisation. Tests skip when slapd is not available
(apt install slapd ldap-utils).
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time

SLAPD = shutil.which("slapd") or "/usr/sbin/slapd"
SLAPADD = shutil.which("slapadd") or "/usr/sbin/slapadd"
SUFFIX = "dc=flowops,dc=test"
ADMIN_DN = f"cn=admin,{SUFFIX}"
ADMIN_PASSWORD = "Directory-Admin-Test-1"
SERVICE_DN = f"cn=flowops-svc,ou=service,{SUFFIX}"
SERVICE_PASSWORD = "Service-Bind-Test-1"
USER_PASSWORD = "Directory-User-Test-1"
USERS = {
    # uid: (display name, email, groups)
    "alice": ("Alice Admin", "alice@flowops.test", ["gg_flowops_admins", "gg_unix"]),
    "erin": ("Erin Editor", "erin@flowops.test", ["gg_flowops_editors", "gg_network"]),
    "bob": ("Bob Outsider", "bob@flowops.test", []),
    # Shares the local bootstrap administrator's username.
    "admin": ("Directory Admin Lookalike", "lookalike@flowops.test", ["gg_flowops_admins"]),
}


def available() -> bool:
    return os.path.exists(SLAPD) and os.path.exists(SLAPADD) and os.path.isdir("/usr/lib/ldap")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LdapServer:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="flowops-slapd-")
        self.port = _free_port()
        self.tls_port = _free_port()
        self.url = f"ldap://127.0.0.1:{self.port}"
        self.ldaps_url = f"ldaps://127.0.0.1:{self.tls_port}"
        self.ca_file = os.path.join(self.dir, "server.crt")
        self.process = None

    def start(self):
        conf, data = os.path.join(self.dir, "slapd.d"), os.path.join(self.dir, "data")
        os.makedirs(conf)
        os.makedirs(data)
        key = os.path.join(self.dir, "server.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", key, "-out", self.ca_file], check=True, capture_output=True)
        schemas = "".join(f"include: file:///etc/ldap/schema/{name}.ldif\n" for name in ("core", "cosine", "inetorgperson"))
        config = f"""dn: cn=config
objectClass: olcGlobal
cn: config
olcPidFile: {self.dir}/slapd.pid
olcTLSCertificateFile: {self.ca_file}
olcTLSCertificateKeyFile: {key}

dn: cn=module{{0}},cn=config
objectClass: olcModuleList
cn: module{{0}}
olcModulePath: /usr/lib/ldap
olcModuleLoad: back_mdb
olcModuleLoad: memberof

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema

{schemas}
dn: olcDatabase={{1}}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {{1}}mdb
olcSuffix: {SUFFIX}
olcRootDN: {ADMIN_DN}
olcRootPW: {ADMIN_PASSWORD}
olcDbDirectory: {data}
olcAccess: {{0}}to attrs=userPassword by self auth by anonymous auth by * none
olcAccess: {{1}}to * by dn.exact="{SERVICE_DN}" read by self read by * none

dn: olcOverlay={{0}}memberof,olcDatabase={{1}}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: {{0}}memberof
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: groupOfNames
olcMemberOfMemberAD: member
olcMemberOfMemberOfAD: memberOf
"""
        ldif = os.path.join(self.dir, "config.ldif")
        with open(ldif, "w") as handle:
            handle.write(config)
        subprocess.run([SLAPADD, "-n0", "-F", conf, "-l", ldif], check=True, capture_output=True)
        self.process = subprocess.Popen(
            [SLAPD, "-d", "0", "-F", conf, "-h", f"{self.url}/ {self.ldaps_url}/"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                if self.process.poll() is not None:
                    raise RuntimeError(f"slapd exited: {self.process.stderr.read().decode()[-2000:]}")
                time.sleep(0.05)
        self._load()
        return self

    def _load(self):
        import ldap3
        conn = ldap3.Connection(ldap3.Server(self.url), ADMIN_DN, ADMIN_PASSWORD, auto_bind=True)
        conn.add(SUFFIX, ["dcObject", "organization"], {"o": "FlowOps Test", "dc": "flowops"})
        for ou in ("people", "groups", "service"):
            conn.add(f"ou={ou},{SUFFIX}", "organizationalUnit")
        conn.add(SERVICE_DN, ["inetOrgPerson"], {"cn": "flowops-svc", "sn": "svc", "userPassword": SERVICE_PASSWORD})
        for uid, (name, mail, _) in USERS.items():
            conn.add(self.user_dn(uid), ["inetOrgPerson"],
                     {"uid": uid, "cn": name, "sn": name.split()[-1], "displayName": name, "mail": mail,
                      "userPassword": USER_PASSWORD})
        groups = {}
        for uid, (_, _, member_of) in USERS.items():
            for group in member_of:
                groups.setdefault(group, []).append(self.user_dn(uid))
        for group, members in groups.items():
            conn.add(self.group_dn(group), ["groupOfNames"], {"cn": group, "member": members})
        conn.unbind()

    def user_dn(self, uid):
        return f"uid={uid},ou=people,{SUFFIX}"

    def group_dn(self, group):
        return f"cn={group},ou=groups,{SUFFIX}"

    def set_membership(self, group, uid, present):
        import ldap3
        conn = ldap3.Connection(ldap3.Server(self.url), ADMIN_DN, ADMIN_PASSWORD, auto_bind=True)
        change = ldap3.MODIFY_ADD if present else ldap3.MODIFY_DELETE
        conn.modify(self.group_dn(group), {"member": [(change, [self.user_dn(uid)])]})
        conn.unbind()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        shutil.rmtree(self.dir, ignore_errors=True)
