"""Native AD/LDAP sign-in (ldap3): service-account search, user bind, group
resolution and group-to-role/team mapping, following the same rules as
ServiceOps (serviceops_core.ldap_access).

Settings live in instance_settings under ldap_*; the bind password is the
encrypted "ldap" integration credential. Every failure that is the
directory's fault raises DirectoryError; a wrong password, unknown user,
disabled account or missing access group returns a result with user=None
and a reason for the audit trail -- never shown to the person signing in.
"""
from __future__ import annotations

import os
import ssl
from dataclasses import dataclass, field

from flowops import identity
from flowops.db import instance_settings, integration_credential

# AD's LDAP_MATCHING_RULE_IN_CHAIN: every group the user is in, at any depth.
AD_IN_CHAIN_RULE = "1.2.840.113556.1.4.1941"
MAX_GROUPS = 1000
AD_FILTER = "(&(objectClass=user)(sAMAccountName={username}))"
SETTING_KEYS = (
    "enabled", "url", "bind_dn", "base_dn", "user_filter", "group_base_dn", "group_search_filter",
    "nested_groups", "start_tls", "validate_cert", "require_access_group", "role_mappings",
    "team_mappings", "default_role", "domain",
)


class DirectoryError(RuntimeError):
    """The directory could not be used (configuration, network, TLS, service bind)."""


@dataclass
class DirectoryUser:
    username: str
    dn: str
    display_name: str
    email: str
    groups: list[str] = field(default_factory=list)
    disabled: bool = False


@dataclass
class AuthResult:
    user: DirectoryUser | None
    reason: str = ""
    role: str = identity.DEFAULT_EXTERNAL_ROLE
    role_group: str | None = None
    team: str | None = None


def directory_config(db, instance_id: int, overrides: dict | None = None) -> dict:
    values = instance_settings(db, instance_id)
    config = {key: values.get(f"ldap_{key}", "") for key in SETTING_KEYS}
    for key, value in (overrides or {}).items():
        if key in SETTING_KEYS and value not in (None, ""):
            config[key] = str(value).lower() if isinstance(value, bool) else str(value)
    config["bind_password"] = (overrides or {}).get("credential") or integration_credential(db, instance_id, "ldap")[0]
    return config


def enabled(config: dict) -> bool:
    return config.get("enabled") == "true" and bool(config.get("url", "").strip())


def _flag(config: dict, key: str, default: bool) -> bool:
    value = config.get(key, "")
    return default if value == "" else value == "true"


def server_uris(raw: str) -> list[str]:
    """ldap_url may list several servers (space or comma separated), tried in order."""
    return [uri for uri in raw.replace(",", " ").split() if uri]


def _ldap3():
    try:
        import ldap3
        from ldap3.core.exceptions import LDAPException
        from ldap3.utils.conv import escape_filter_chars
    except ImportError as exc:  # pragma: no cover - ldap3 is in requirements.txt
        raise DirectoryError("The ldap3 package is not installed") from exc
    return ldap3, LDAPException, escape_filter_chars


def _server(config: dict):
    ldap3, _, _ = _ldap3()
    uris = server_uris(config.get("url", ""))
    if not uris:
        raise DirectoryError("No LDAP server URL is configured")
    schemes = {uri.split("://", 1)[0].lower() for uri in uris}
    if not schemes <= {"ldap", "ldaps"} or len(schemes) != 1:
        raise DirectoryError("Every LDAP server URL must use the same scheme, ldap:// or ldaps://")
    use_ssl = schemes == {"ldaps"}
    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED if _flag(config, "validate_cert", True) else ssl.CERT_NONE,
        ca_certs_file=os.getenv("FLOWOPS_LDAP_CA_CERT") or None,
    )
    timeout = int(os.getenv("FLOWOPS_LDAP_TIMEOUT", "8"))
    servers = []
    for uri in uris:
        address = uri.split("://", 1)[1].split("/", 1)[0]
        host, _, port = address.rpartition(":") if address.count(":") == 1 else (address, "", "")
        servers.append(ldap3.Server(host or address, port=int(port or (636 if use_ssl else 389)), use_ssl=use_ssl,
                                    tls=tls, get_info=ldap3.NONE, connect_timeout=timeout))
    pool = servers[0] if len(servers) == 1 else ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=60)
    return pool, use_ssl


def _open(config: dict, server, use_ssl: bool, user: str | None, password: str | None):
    """An open, bound connection, or None when the server rejected the credentials."""
    ldap3, LDAPException, _ = _ldap3()
    connection = ldap3.Connection(server, user=user, password=password, auto_bind=False, read_only=True,
                                  receive_timeout=int(os.getenv("FLOWOPS_LDAP_TIMEOUT", "8")))
    try:
        connection.open()
        if not use_ssl and _flag(config, "start_tls", True) and not connection.start_tls():
            connection.unbind()
            raise DirectoryError("LDAP StartTLS negotiation failed")
        if connection.bind():
            return connection
    except LDAPException as exc:
        try:
            connection.unbind()
        except LDAPException:
            pass
        hint=" (its TLS certificate is not trusted; set FLOWOPS_LDAP_CA_CERT)" if "certificate" in str(exc).lower() else ""
        raise DirectoryError(f"LDAP server unavailable: {type(exc).__name__}{hint}") from exc
    connection.unbind()
    return None


def service_connection(config: dict):
    server, use_ssl = _server(config)
    bind_dn = config.get("bind_dn", "").strip() or None
    password = config.get("bind_password") or None
    if bind_dn and not password:
        # A configured bind DN with no password would silently become an
        # anonymous bind; refuse rather than degrade.
        raise DirectoryError("The LDAP bind password is not set")
    connection = _open(config, server, use_ssl, bind_dn, password)
    if connection is None:
        raise DirectoryError("The LDAP service-account bind was rejected")
    return server, use_ssl, connection


def _attrs(entry) -> dict[str, list]:
    return {key.lower(): value if isinstance(value, list) else [value]
            for key, value in entry.entry_attributes_as_dict.items()}


def _first(values: dict, *keys: str) -> str:
    for key in keys:
        for value in values.get(key.lower(), []):
            if value not in (None, ""):
                return str(value)
    return ""


def find_entry(config: dict, connection, username: str):
    """The single directory entry for `username`, or None (0 or >1 matches)."""
    ldap3, _, escape = _ldap3()
    template = config.get("user_filter", "").strip() or AD_FILTER
    local = identity.login_local_part(username)
    for candidate in ([local] if local == username else [local, username]):
        connection.search(config.get("base_dn", ""), template.replace("{username}", escape(candidate)),
                          search_scope=ldap3.SUBTREE, attributes=[ldap3.ALL_ATTRIBUTES, ldap3.ALL_OPERATIONAL_ATTRIBUTES],
                          size_limit=2)
        if len(connection.entries) == 1:
            return connection.entries[0]
    return None


def resolve_groups(config: dict, connection, dn: str, username: str, member_of) -> list[str]:
    """Every group DN: the entry's memberOf, AD nested groups when enabled, and
    groups found by ldap_group_search_filter ({dn} / {username}) for
    directories without memberOf. A failed lookup keeps the direct groups."""
    ldap3, LDAPException, escape = _ldap3()
    groups = [str(group) for group in member_of or []]
    base = config.get("group_base_dn", "").strip() or config.get("base_dn", "")
    filters = []
    if _flag(config, "nested_groups", False):
        filters.append(f"(member:{AD_IN_CHAIN_RULE}:={escape(dn)})")
    template = config.get("group_search_filter", "").strip()
    if template:
        filters.append(template.replace("{dn}", escape(dn)).replace("{username}", escape(username)))
    for search_filter in filters:
        try:
            connection.search(base, search_filter, search_scope=ldap3.SUBTREE, attributes=[], size_limit=MAX_GROUPS)
        except LDAPException:
            continue
        groups.extend(entry.entry_dn for entry in connection.entries)
    seen, unique = set(), []
    for group in groups:
        key = group.strip().casefold()
        if key and key not in seen:
            seen.add(key)
            unique.append(group.strip())
    return unique


def _directory_user(config: dict, connection, entry, username: str) -> DirectoryUser:
    values = _attrs(entry)
    local = identity.login_local_part(username)
    account = _first(values, "sAMAccountName", "uid") or local
    groups = resolve_groups(config, connection, entry.entry_dn, account, values.get("memberof", []))
    try:
        disabled = bool(int(_first(values, "userAccountControl") or 0) & 2)
    except ValueError:
        disabled = False
    return DirectoryUser(username=account, dn=entry.entry_dn,
                         display_name=_first(values, "displayName", "cn") or account,
                         email=_first(values, "mail", "userPrincipalName").lower(),
                         groups=groups, disabled=disabled)


def evaluate(config: dict, user: DirectoryUser) -> AuthResult:
    """Apply the access and mapping policy to a directory user."""
    roles = identity.parse_mapping(config.get("role_mappings"), "role")
    teams = identity.parse_mapping(config.get("team_mappings"), "team")
    role, role_group = identity.mapped_role(user.groups, roles, config.get("default_role") or identity.DEFAULT_EXTERNAL_ROLE)
    team = identity.mapped_team(user.groups, teams)
    if user.disabled:
        return AuthResult(None, "account disabled in the directory")
    if _flag(config, "require_access_group", False) and not (role_group or team):
        return AuthResult(None, "not in a mapped access group")
    return AuthResult(user, "", role, role_group, team)


def authenticate(config: dict, username: str, password: str) -> AuthResult:
    if not password:
        # An empty password makes an LDAP simple bind anonymous -- it would
        # "succeed" for any account. Never send it.
        return AuthResult(None, "empty password")
    if not username.strip():
        return AuthResult(None, "empty username")
    server, use_ssl, service = service_connection(config)
    try:
        entry = find_entry(config, service, username)
        if entry is None:
            return AuthResult(None, "no unique directory account")
        user = _directory_user(config, service, entry, username)
    finally:
        service.unbind()
    bound = _open(config, server, use_ssl, user.dn, password)
    if bound is None:
        return AuthResult(None, "directory rejected the password")
    bound.unbind()
    # The access policy is applied only after the password is proven, so a
    # refusal never reveals whether the account exists.
    return evaluate(config, user)


def check_user(config: dict, username: str) -> dict:
    """What sign-in would grant `username`, read with the service account only."""
    _, _, service = service_connection(config)
    try:
        entry = find_entry(config, service, username)
        if entry is None:
            return {"username": identity.login_local_part(username), "found": False}
        user = _directory_user(config, service, entry, username)
    finally:
        service.unbind()
    result = evaluate(config, user)
    return {
        "username": user.username, "found": True, "dn": user.dn, "name": user.display_name, "email": user.email,
        "groups": [group[:160] for group in user.groups[:25]], "group_count": len(user.groups),
        "disabled": user.disabled, "allowed": result.user is not None, "reason": result.reason,
        "role": result.role if result.user else None, "role_group": result.role_group, "team": result.team,
    }


def test_connection(config: dict) -> dict:
    """Bind with the service account and read the base DN."""
    ldap3, LDAPException, _ = _ldap3()
    _, use_ssl, service = service_connection(config)
    try:
        try:
            found = service.search(config.get("base_dn", ""), "(objectClass=*)", search_scope=ldap3.BASE, attributes=[])
        except LDAPException as exc:
            raise DirectoryError(f"Searching the base DN failed: {type(exc).__name__}") from exc
        if not found:
            raise DirectoryError("The base DN was not found or is not readable by the service account")
    finally:
        service.unbind()
    secured = "LDAPS" if use_ssl else ("StartTLS" if _flag(config, "start_tls", True) else "unencrypted")
    return {"ok": True, "message": f"Service account bound and base DN readable ({secured})"}
