"""Account rules shared by every sign-in path: lockout after repeated
failures, multi-factor challenges, and creating or updating accounts that
come from a directory or OIDC provider."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from typing import Any

from flowops import identity
from flowops.crypto import password_hash, settings_cipher
from flowops.db import instance_settings, now

MFA_CHALLENGE_SECONDS = 300
MFA_CHALLENGE_ATTEMPTS = 5


def _int_setting(values: dict, key: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(values.get(key, default))))
    except (TypeError, ValueError):
        return default


# --- lockout -----------------------------------------------------------------

def locked_for(user) -> int:
    """Seconds until a locked account may try again, or 0."""
    until = user["locked_until"] if user and "locked_until" in user.keys() else None
    return max(0, int(until) - int(time.time())) if until else 0


def record_failure(db: sqlite3.Connection, user) -> bool:
    """Count a failed sign-in; returns True when this failure locks the account."""
    values = instance_settings(db, user["instance_id"])
    limit = _int_setting(values, "login_max_attempts", 5, 1, 50)
    minutes = _int_setting(values, "login_lockout_minutes", 15, 1, 1440)
    count = (user["failed_login_count"] or 0) + 1
    if count >= limit:
        db.execute("UPDATE users SET failed_login_count=0,locked_until=? WHERE id=?",
                   (int(time.time()) + minutes * 60, user["id"]))
        return True
    db.execute("UPDATE users SET failed_login_count=? WHERE id=?", (count, user["id"]))
    return False


def clear_failures(db: sqlite3.Connection, user_id: int) -> None:
    db.execute("UPDATE users SET failed_login_count=0,locked_until=NULL WHERE id=?", (user_id,))


# --- multi-factor ------------------------------------------------------------

def mfa_secret(user) -> str:
    return settings_cipher().decrypt(user["mfa_secret_encrypted"].encode()).decode()


def start_mfa_challenge(db: sqlite3.Connection, user, source: str) -> str:
    raw = secrets.token_urlsafe(32)
    db.execute("DELETE FROM mfa_challenges WHERE expires_at<=?", (int(time.time()),))
    db.execute("INSERT INTO mfa_challenges(token_hash,user_id,auth_version,source,attempts,expires_at,created_at) "
               "VALUES(?,?,?,?,0,?,?)",
               (hashlib.sha256(raw.encode()).hexdigest(), user["id"], user["auth_version"], source,
                int(time.time()) + MFA_CHALLENGE_SECONDS, now()))
    return raw


def verify_mfa_code(db: sqlite3.Connection, user, code: str) -> str | None:
    """'totp' or 'backup_code' when `code` is valid (consuming it), else None."""
    if user["mfa_secret_encrypted"]:
        step = identity.totp_match(mfa_secret(user), code, after_step=user["mfa_last_step"])
        if step is not None:
            db.execute("UPDATE users SET mfa_last_step=? WHERE id=?", (step, user["id"]))
            return "totp"
    remaining = json.loads(user["mfa_backup_codes"] or "[]")
    digest = identity.hash_backup_code(code)
    if digest in remaining:
        remaining.remove(digest)
        db.execute("UPDATE users SET mfa_backup_codes=? WHERE id=?", (json.dumps(remaining), user["id"]))
        return "backup_code"
    return None


# --- external accounts -------------------------------------------------------

def provision_external(db: sqlite3.Connection, instance_id: int, provider: str, external_id: str, *,
                       username: str, display_name: str, email: str, role: str | None, team: str | None,
                       create: bool, create_role: str = identity.DEFAULT_EXTERNAL_ROLE,
                       match_email: bool = False) -> tuple[Any, str]:
    """The FlowOps account for a verified directory/OIDC identity, created or
    updated to match it. Returns (row, outcome); row is None when the identity
    may not sign in, with outcome saying why.

    `role` is None when no role mapping is configured: existing accounts then
    keep the role an administrator gave them, and new ones get `create_role`. A local account found by
    username or email is linked to the provider, except a local Admin, which
    stays a separate break-glass account."""
    row = db.execute("SELECT * FROM users WHERE instance_id=? AND auth_provider=? AND external_id=?",
                     (instance_id, provider, external_id)).fetchone()
    if row is None:
        row = db.execute("SELECT * FROM users WHERE instance_id=? AND username=? COLLATE NOCASE",
                         (instance_id, username)).fetchone()
        if row is None and match_email and email:
            row = db.execute("SELECT * FROM users WHERE instance_id=? AND LOWER(email)=?",
                             (instance_id, email.lower())).fetchone()
        if row is not None and row["auth_provider"] == "local" and row["role"] == "Admin" and provider != "oidc":
            return None, "username belongs to a local administrator"
        if row is not None and row["auth_provider"] not in ("local", provider):
            return None, f"username is managed by {row['auth_provider']}"
    if row is None:
        if not create:
            return None, "no matching FlowOps account"
        if db.execute("SELECT 1 FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone():
            return None, "username is taken in another organization"
        db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id,"
                   "auth_provider,external_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (username, (display_name or username)[:160], email[:254], role or create_role,
                    (team or "")[:120], password_hash(secrets.token_urlsafe(48)), now(), instance_id, provider,
                    external_id[:512]))
        return db.execute("SELECT * FROM users WHERE instance_id=? AND auth_provider=? AND external_id=?",
                          (instance_id, provider, external_id)).fetchone(), "created"
    if not row["active"]:
        return None, "account is deactivated in FlowOps"
    linked_local_admin = row["auth_provider"] == "local" and row["role"] == "Admin"
    updates = {"external_id": external_id[:512]}
    if not linked_local_admin:
        # Directory-managed: the provider is authoritative for its own data.
        updates["auth_provider"] = provider
        if display_name:
            updates["display_name"] = display_name[:160]
        if email:
            updates["email"] = email[:254]
        if role:
            updates["role"] = role
        if team:
            updates["team"] = team[:120]
    else:
        updates["auth_provider"] = row["auth_provider"]
    assignments = ",".join(f"{column}=?" for column in updates)
    db.execute(f"UPDATE users SET {assignments} WHERE id=?", (*updates.values(), row["id"]))
    return db.execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone(), "updated"
