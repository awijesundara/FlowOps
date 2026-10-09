"""Identity rules shared by local, directory and OIDC sign-in: role ranks,
group-to-role and group-to-team mappings, login-name normalisation, and
TOTP multi-factor codes. Pure functions only -- no database or network --
so every sign-in path applies the same rules (mirrors ServiceOps'
serviceops_core.identity)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
import urllib.parse

# Fixed roles a directory or OIDC group may grant, lowest to highest. Scoped
# roles (Workspace Manager, ...) are granted per workspace by an administrator
# and are never assigned by a mapping.
ROLE_RANK = {"Stakeholder": 0, "Member": 1, "Editor": 2, "Admin": 3}
DEFAULT_EXTERNAL_ROLE = "Member"

TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
BACKUP_CODE_COUNT = 10


def login_local_part(username: str) -> str:
    """Bare account name from any of the three Windows login forms:
    CORP\\jsmith, jsmith@corp.example.com or jsmith."""
    if "\\" in username:
        return username.split("\\", 1)[1]
    if "@" in username:
        return username.split("@", 1)[0]
    return username


def normalized_groups(groups) -> set[str]:
    """Case-insensitive aliases for each group: the full DN and its first CN,
    so a mapping written as either form matches."""
    normalized = set()
    for value in groups or []:
        group = str(value).strip()
        if not group:
            continue
        normalized.add(group.casefold())
        first = group.split(",", 1)[0].strip()
        if first.casefold().startswith("cn="):
            normalized.add(first[3:].strip().casefold())
    return normalized


def parse_mapping(raw: str | dict | None, kind: str) -> dict[str, str]:
    """A {group: value} mapping from its stored JSON. Role mappings may only
    name a ROLE_RANK role. Raises ValueError with a message an administrator
    can act on."""
    if raw in (None, ""):
        return {}
    try:
        mapping = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as exc:
        raise ValueError(f"The {kind} mapping must be a JSON object") from exc
    if not isinstance(mapping, dict):
        raise ValueError(f"The {kind} mapping must be a JSON object of group to value")
    cleaned = {}
    for group, value in mapping.items():
        group, value = str(group).strip(), str(value).strip()
        if not group or not value:
            raise ValueError(f"The {kind} mapping has an empty group or value")
        if kind == "role" and value not in ROLE_RANK:
            raise ValueError(f"Role mapping for {group} must be one of: {', '.join(ROLE_RANK)}")
        cleaned[group] = value
    return cleaned


def matched(groups, mapping: dict[str, str]) -> dict[str, str]:
    """The entries of `mapping` whose group the user belongs to."""
    aliases = normalized_groups(groups)
    return {group: value for group, value in mapping.items() if group.strip().casefold() in aliases}


def mapped_role(groups, mapping: dict[str, str], default: str = DEFAULT_EXTERNAL_ROLE) -> tuple[str, str | None]:
    """The highest role any of the user's groups grants, and the group that
    granted it; `default` (and None) when no mapping matches."""
    hits = matched(groups, mapping)
    if not hits:
        return (default if default in ROLE_RANK else DEFAULT_EXTERNAL_ROLE), None
    group, role = max(hits.items(), key=lambda item: ROLE_RANK[item[1]])
    return role, group


def mapped_team(groups, mapping: dict[str, str]) -> str | None:
    """The team of the first matching group in mapping order (administrators
    order the JSON object by priority), or None."""
    aliases = normalized_groups(groups)
    for group, team in mapping.items():
        if group.strip().casefold() in aliases:
            return team
    return None


# --- TOTP (RFC 6238) ---------------------------------------------------------

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_code(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // TOTP_PERIOD_SECONDS))


def totp_match(secret: str, code: str, after_step: int | None = None, at: float | None = None) -> int | None:
    """The time step `code` is valid for (current step +/- 1), or None. A step
    at or before `after_step` is refused so a code cannot be replayed."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != TOTP_DIGITS:
        return None
    step = int((time.time() if at is None else at) // TOTP_PERIOD_SECONDS)
    for candidate in (step - 1, step, step + 1):
        if after_step is not None and candidate <= after_step:
            continue
        if hmac.compare_digest(_hotp(secret, candidate), code):
            return candidate
    return None


def totp_uri(secret: str, account: str, issuer: str = "FlowOps") -> str:
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": TOTP_DIGITS,
                                    "period": TOTP_PERIOD_SECONDS})
    return f"otpauth://totp/{label}?{query}"


def new_backup_codes() -> list[str]:
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(BACKUP_CODE_COUNT)]


def hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()
