#!/usr/bin/env python3
"""FlowOps: dependency-aware operational runbooks with ServiceOps integration."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import smtplib
import ssl
import subprocess
import threading
import time
import base64
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class InvalidToken(ValueError):
    """Raised when an encrypted administrator setting fails authentication."""


class SettingsCipher:
    """Small OpenSSL-backed authenticated cipher for portable secret storage."""

    VERSION = b"FO1"

    def __init__(self, encoded_key: str):
        try:
            self.master_key = base64.urlsafe_b64decode(encoded_key.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid encryption key") from exc
        if len(self.master_key) != 32:
            raise ValueError("invalid encryption key")
        self.encryption_key = hmac.new(self.master_key, b"flowops:encryption", hashlib.sha256).digest()
        self.authentication_key = hmac.new(self.master_key, b"flowops:authentication", hashlib.sha256).digest()

    def _crypt(self, payload: bytes, nonce: bytes, decrypt: bool = False) -> bytes:
        command = ["openssl", "enc", "-aes-256-ctr", "-K", self.encryption_key.hex(), "-iv", nonce.hex()]
        if decrypt:
            command.append("-d")
        try:
            return subprocess.run(command, input=payload, capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("OpenSSL credential encryption failed") from exc

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        ciphertext = self._crypt(plaintext, nonce)
        authenticated = self.VERSION + nonce + ciphertext
        tag = hmac.new(self.authentication_key, authenticated, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(authenticated + tag)

    def decrypt(self, token: bytes) -> bytes:
        try:
            decoded = base64.urlsafe_b64decode(token)
        except (ValueError, TypeError) as exc:
            raise InvalidToken("invalid credential encoding") from exc
        if len(decoded) < 51 or decoded[:3] != self.VERSION:
            raise InvalidToken("invalid credential format")
        authenticated, supplied_tag = decoded[:-32], decoded[-32:]
        expected_tag = hmac.new(self.authentication_key, authenticated, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise InvalidToken("credential authentication failed")
        return self._crypt(authenticated[19:], authenticated[3:19], decrypt=True)

VERSION = (Path(__file__).with_name("VERSION").read_text().strip() if Path(__file__).with_name("VERSION").exists() else "0.0.0")
DB_PATH = os.getenv("FLOWOPS_DB", str(Path(__file__).with_name("flowops.db")))
STATIC = Path(__file__).with_name("static")
MAX_BODY = 1_000_000
SESSION_SECONDS = 8 * 60 * 60
DEFAULT_INSTANCE_SLUG = "flowops"
ROLE_PERMISSIONS = {
    "Admin": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync","admin:access","admin:users","admin:settings"},
    "Editor": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync"},
    "Member": {"runbooks:view","runbooks:execute"},
    "Stakeholder": {"runbooks:view"},
    "Workspace Manager": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync"},
    "Folder Creator": {"runbooks:view","runbooks:execute"},
    "Stream Editor": {"runbooks:view","runbooks:execute"},
}
SCOPED_ROLES = {"Workspace Manager","Folder Creator","Stream Editor"}
TOKEN_SCOPE_PERMISSIONS = {
    "runbooks:read": {"runbooks:view"},
    "runbooks:write": {"runbooks:view","runbooks:edit","runbooks:execute"},
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS runbooks (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'draft', mode TEXT NOT NULL DEFAULT 'plan',
          owner TEXT NOT NULL DEFAULT '', scheduled_at TEXT, serviceops_ticket TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT 'General',
          owner TEXT NOT NULL DEFAULT '', duration INTEGER NOT NULL DEFAULT 15,
          status TEXT NOT NULL DEFAULT 'pending', sort_order INTEGER NOT NULL DEFAULT 0,
          started_at TEXT, completed_at TEXT, automation_url TEXT
        );
        CREATE TABLE IF NOT EXISTS streams (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(runbook_id, name)
        );
        CREATE TABLE IF NOT EXISTS dependencies (
          task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          depends_on_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          PRIMARY KEY(task_id, depends_on_id), CHECK(task_id != depends_on_id)
        );
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, runbook_id INTEGER, action TEXT NOT NULL, detail TEXT NOT NULL,
          actor TEXT NOT NULL, created_at TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'Viewer',
          team TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          last_login_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, csrf_token TEXT NOT NULL,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspaces (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
          description TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#7557e8',
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS folders (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(workspace_id, name)
        );
        CREATE TABLE IF NOT EXISTS runbook_types (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '◇', color TEXT NOT NULL DEFAULT '#7557e8',
          default_description TEXT NOT NULL DEFAULT '', requires_approval INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          UNIQUE(workspace_id, name)
        );
        CREATE TABLE IF NOT EXISTS invitations (
          id INTEGER PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
          accepted_at TEXT, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS password_resets (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, used_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runbook_teams (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          name TEXT NOT NULL, created_at TEXT NOT NULL, central_team_id INTEGER, UNIQUE(runbook_id,name)
        );
        CREATE TABLE IF NOT EXISTS team_members (
          team_id INTEGER NOT NULL REFERENCES runbook_teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(team_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS central_teams (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(workspace_id,name)
        );
        CREATE TABLE IF NOT EXISTS central_team_members (
          team_id INTEGER NOT NULL REFERENCES central_teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(team_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS custom_field_definitions (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          entity_type TEXT NOT NULL CHECK(entity_type IN ('runbook','task')), name TEXT NOT NULL,
          field_type TEXT NOT NULL DEFAULT 'text' CHECK(field_type IN ('text','number','date','boolean','select')),
          options_json TEXT NOT NULL DEFAULT '[]', required INTEGER NOT NULL DEFAULT 0,
          sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(workspace_id, entity_type, name)
        );
        CREATE TABLE IF NOT EXISTS custom_field_values (
          definition_id INTEGER NOT NULL REFERENCES custom_field_definitions(id) ON DELETE CASCADE,
          entity_id INTEGER NOT NULL, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
          PRIMARY KEY(definition_id, entity_id)
        );
        CREATE TABLE IF NOT EXISTS webhooks (
          id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          name TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT 'generic' CHECK(provider IN ('generic','slack','teams')),
          events_json TEXT NOT NULL DEFAULT '["*"]', active INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
          id INTEGER PRIMARY KEY, webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
          audit_id INTEGER, event_type TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 0,
          status_code INTEGER, error TEXT, attempts INTEGER NOT NULL DEFAULT 0, attempted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_cursor (
          id INTEGER PRIMARY KEY CHECK (id=1), last_audit_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
          id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, scopes_json TEXT NOT NULL DEFAULT '[]',
          created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL,
          last_used_at TEXT, revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS instances (
          id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS templates (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'General',
          created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS template_tasks (
          id INTEGER PRIMARY KEY, template_id INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
          title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT 'General',
          duration INTEGER NOT NULL DEFAULT 15, sort_order INTEGER NOT NULL DEFAULT 0,
          automation_url TEXT, task_type TEXT NOT NULL DEFAULT 'normal', scheduled_offset INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS template_dependencies (
          template_task_id INTEGER NOT NULL REFERENCES template_tasks(id) ON DELETE CASCADE,
          depends_on_template_task_id INTEGER NOT NULL REFERENCES template_tasks(id) ON DELETE CASCADE,
          PRIMARY KEY(template_task_id, depends_on_template_task_id)
        );
        CREATE TABLE IF NOT EXISTS instance_settings (
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          key TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL,
          PRIMARY KEY(instance_id,key)
        );
        CREATE TABLE IF NOT EXISTS integration_credentials (
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          provider TEXT NOT NULL, secret_encrypted TEXT NOT NULL,
          updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL,
          PRIMARY KEY(instance_id,provider)
        );
        CREATE TABLE IF NOT EXISTS workspace_managers (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,workspace_id)
        );
        CREATE TABLE IF NOT EXISTS folder_creator_grants (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,folder_id)
        );
        CREATE TABLE IF NOT EXISTS stream_editor_grants (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,runbook_id)
        );
        """)
        db.execute("INSERT OR IGNORE INTO instances(slug,name,created_at) VALUES(?,?,?)",(DEFAULT_INSTANCE_SLUG,"FlowOps",now()))
        default_instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()[0]
        for table in ("users","workspaces","invitations","audit"):
            existing={row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if "instance_id" not in existing: db.execute(f"ALTER TABLE {table} ADD COLUMN instance_id INTEGER REFERENCES instances(id)")
            db.execute(f"UPDATE {table} SET instance_id=? WHERE instance_id IS NULL",(default_instance,))
        columns={row[1] for row in db.execute("PRAGMA table_info(runbooks)")}
        if "workspace_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id)")
        if "actual_started_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_started_at TEXT")
        if "actual_completed_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_completed_at TEXT")
        if "archived" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
        if "folder_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN folder_id INTEGER REFERENCES folders(id)")
        if "runbook_type_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN runbook_type_id INTEGER REFERENCES runbook_types(id)")
        if "parent_runbook_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN parent_runbook_id INTEGER REFERENCES runbooks(id)")
        if "approved_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN approved_at TEXT")
        if "approved_by" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN approved_by TEXT")
        type_columns={row[1] for row in db.execute("PRAGMA table_info(runbook_types)")}
        if "requires_approval" not in type_columns: db.execute("ALTER TABLE runbook_types ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0")
        rbteam_columns={row[1] for row in db.execute("PRAGMA table_info(runbook_teams)")}
        if "central_team_id" not in rbteam_columns: db.execute("ALTER TABLE runbook_teams ADD COLUMN central_team_id INTEGER REFERENCES central_teams(id)")
        webhook_columns={row[1] for row in db.execute("PRAGMA table_info(webhooks)")}
        if "provider" not in webhook_columns: db.execute("ALTER TABLE webhooks ADD COLUMN provider TEXT NOT NULL DEFAULT 'generic'")
        for column,definition in {
          "serviceops_type":"TEXT","serviceops_title":"TEXT","serviceops_state":"TEXT",
          "serviceops_priority":"TEXT","serviceops_synced_at":"TEXT","serviceops_request_id":"TEXT"
        }.items():
            if column not in columns: db.execute(f"ALTER TABLE runbooks ADD COLUMN {column} {definition}")
        task_columns={row[1] for row in db.execute("PRAGMA table_info(tasks)")}
        task_migrations={
          "task_type":"TEXT NOT NULL DEFAULT 'normal'", "scheduled_offset":"INTEGER NOT NULL DEFAULT 0",
          "owner_user_id":"INTEGER REFERENCES users(id)", "owner_team_id":"INTEGER REFERENCES runbook_teams(id)",
          "validation_result":"TEXT", "validation_comment":"TEXT", "blocked_reason":"TEXT",
          "serviceops_ctask":"TEXT"
        }
        for column,definition in task_migrations.items():
            if column not in task_columns: db.execute(f"ALTER TABLE tasks ADD COLUMN {column} {definition}")
        user_columns={row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "dashboard_widgets" not in user_columns: db.execute("ALTER TABLE users ADD COLUMN dashboard_widgets TEXT")
        session_columns={row[1] for row in db.execute("PRAGMA table_info(sessions)")}
        for column,definition in {"ip_address":"TEXT NOT NULL DEFAULT ''","user_agent":"TEXT NOT NULL DEFAULT ''"}.items():
            if column not in session_columns:db.execute(f"ALTER TABLE sessions ADD COLUMN {column} {definition}")
        db.execute("UPDATE workspaces SET color='#7557e8' WHERE color='#3158c7'")
        db.execute("UPDATE users SET role='Admin' WHERE role='Administrator'")
        db.execute("UPDATE users SET role='Editor' WHERE role='Runbook Manager'")
        db.execute("UPDATE users SET role='Member' WHERE role IN ('Operator','Viewer')")
        db.execute("INSERT OR IGNORE INTO workspaces(name,description,color,created_at,instance_id) VALUES(?,?,?,?,?)",("Resilience Operations","Production change, recovery, and release orchestration.","#7557e8",now(),default_instance))
        default_workspace=db.execute("SELECT id FROM workspaces WHERE instance_id=? ORDER BY id LIMIT 1",(default_instance,)).fetchone()[0]
        db.execute("UPDATE runbooks SET workspace_id=? WHERE workspace_id IS NULL",(default_workspace,))
        if db.execute("SELECT COUNT(*) FROM runbooks").fetchone()[0] == 0:
            stamp = now()
            cur = db.execute("INSERT INTO runbooks(name,description,status,mode,owner,scheduled_at,serviceops_ticket,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("Payments platform release", "Coordinated production release with validation and rollback gates.", "ready", "plan", "Release Management", "2026-09-08T21:00", "CHG0001042", stamp, stamp))
            rid = cur.lastrowid
            seed = [
                ("Confirm change approval", "Governance", "Maya Chen", 10),
                ("Notify stakeholders", "Communications", "Liam Park", 5),
                ("Enable maintenance mode", "Platform", "SRE Team", 10),
                ("Deploy application release", "Deployment", "Release Team", 25),
                ("Run production smoke tests", "Validation", "QA Team", 20),
                ("Restore traffic", "Platform", "SRE Team", 10),
                ("Close change and publish summary", "Governance", "Maya Chen", 10),
            ]
            ids=[]
            for pos, (title, stream, owner, duration) in enumerate(seed):
                ids.append(db.execute("INSERT INTO tasks(runbook_id,title,stream,owner,duration,sort_order) VALUES(?,?,?,?,?,?)", (rid,title,stream,owner,duration,pos)).lastrowid)
            for task_id, predecessor in zip(ids[1:], ids[:-1]):
                db.execute("INSERT INTO dependencies VALUES(?,?)", (task_id, predecessor))
            append_audit(db, rid, "runbook.created", "Sample release runbook created", "FlowOps")
        db.execute("UPDATE runbooks SET workspace_id=? WHERE workspace_id IS NULL",(default_workspace,))
        for stream_rid, stream, pos in db.execute(
            "SELECT runbook_id, stream, MIN(sort_order) FROM tasks GROUP BY runbook_id, stream ORDER BY runbook_id, MIN(sort_order)"
        ).fetchall():
            db.execute(
                "INSERT OR IGNORE INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",
                (stream_rid, stream, pos, now()),
            )
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            password=os.getenv("FLOWOPS_BOOTSTRAP_PASSWORD","FlowOps!Preview2026")
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",
                       ("admin","Anushka","admin@flowops.local","Admin","Platform Operations",password_hash(password),now(),default_instance))
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",
                       ("operator","Release Operator","operator@flowops.local","Member","Release Engineering",password_hash("Operator!Preview2026"),now(),default_instance))
        defaults={"workspace_name":"Resilience Operations","timezone":"Asia/Tokyo","require_approval":"true","session_hours":"8","serviceops_enabled":"true","directory_enabled":"false","directory_domain":"",
          "serviceops_url":os.getenv("SERVICEOPS_URL","http://host.docker.internal:8080"),"serviceops_sync_on_live":"true","serviceops_sync_on_complete":"true","serviceops_require_approved":"true","serviceops_trigger_workflow":"false",
        }
        for key,value in defaults.items(): db.execute("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",(key,value,now()))
        for key,value in defaults.items():
            legacy=db.execute("SELECT value FROM settings WHERE key=?",(key,)).fetchone()
            db.execute("INSERT OR IGNORE INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?)",(default_instance,key,legacy[0] if legacy else value,now()))


def password_hash(password: str, salt: bytes | None=None) -> str:
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def password_valid(password: str, encoded: str) -> bool:
    try: _,rounds,salt,digest=encoded.split("$"); actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),int(rounds)).hex()
    except (ValueError,TypeError): return False
    return hmac.compare_digest(actual,digest)


def instance_settings(db: sqlite3.Connection, instance_id: int) -> dict[str,str]:
    return {r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=?",(instance_id,))}


def mail_configuration() -> dict[str,Any]:
    host=os.getenv("FLOWOPS_SMTP_HOST","").strip(); sender=os.getenv("FLOWOPS_MAIL_FROM","").strip(); public_url=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
    return {"configured":bool(host and sender and public_url),"host":host,"port":int(os.getenv("FLOWOPS_SMTP_PORT","587")),"sender":sender,"public_url":public_url,"security":os.getenv("FLOWOPS_SMTP_SECURITY","starttls").strip().lower(),"username":os.getenv("FLOWOPS_SMTP_USERNAME","")}


def send_mail(recipient: str, subject: str, body: str) -> None:
    config=mail_configuration()
    if not config["configured"]: raise RuntimeError("Email delivery is not configured")
    message=EmailMessage();message["From"]=config["sender"];message["To"]=recipient;message["Subject"]=subject;message.set_content(body)
    password=os.getenv("FLOWOPS_SMTP_PASSWORD",""); security=config["security"]
    if security not in {"starttls","tls","none"}: raise RuntimeError("FLOWOPS_SMTP_SECURITY must be starttls, tls, or none")
    client_type=smtplib.SMTP_SSL if security=="tls" else smtplib.SMTP
    try:
        with client_type(config["host"],config["port"],timeout=10) as client:
            if security=="starttls": client.starttls(context=ssl.create_default_context())
            if config["username"]: client.login(config["username"],password)
            client.send_message(message)
    except (OSError,smtplib.SMTPException) as exc:
        raise RuntimeError("Email delivery failed") from exc


def settings_cipher() -> SettingsCipher:
    key=os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY","").strip()
    if not key: raise RuntimeError("FLOWOPS_SETTINGS_ENCRYPTION_KEY is required for administrator-managed credentials")
    try:return SettingsCipher(key)
    except (ValueError,TypeError) as exc:raise RuntimeError("FLOWOPS_SETTINGS_ENCRYPTION_KEY is invalid") from exc


def integration_credential(db: sqlite3.Connection, instance_id: int, provider: str) -> tuple[str,str]:
    row=db.execute("SELECT secret_encrypted FROM integration_credentials WHERE instance_id=? AND provider=?",(instance_id,provider)).fetchone()
    if row:
        try:return settings_cipher().decrypt(row[0].encode()).decode(),"Encrypted FlowOps setting"
        except (InvalidToken,RuntimeError,UnicodeDecodeError) as exc:raise RuntimeError(f"The stored {provider.title()} credential cannot be decrypted") from exc
    return "","Not configured in FlowOps"


def team_member_user_ids(db: sqlite3.Connection, team_id: int) -> set[int]:
    """A runbook team's effective roster: its own direct members plus,
    when linked to a central team, that central team's current members --
    resolved live on every call so central membership changes propagate
    to every runbook the team is linked into without any copy/sync step."""
    ids={row[0] for row in db.execute("SELECT user_id FROM team_members WHERE team_id=?",(team_id,))}
    central_team_id=db.execute("SELECT central_team_id FROM runbook_teams WHERE id=?",(team_id,)).fetchone()
    if central_team_id and central_team_id[0]:
        ids|={row[0] for row in db.execute("SELECT user_id FROM central_team_members WHERE team_id=?",(central_team_id[0],))}
    return ids


def apply_custom_field_values(db: sqlite3.Connection, workspace_id: int, entity_type: str, entity_id: int, values: dict) -> list[str]:
    """Upsert {definition_id: value} for one runbook or task, scoped to
    definitions that actually belong to this workspace and entity type.
    Returns a list of human-readable changes for the audit trail."""
    changes=[]
    for definition_id, value in values.items():
        try: definition_id=int(definition_id)
        except (TypeError, ValueError): continue
        definition=db.execute("SELECT * FROM custom_field_definitions WHERE id=? AND workspace_id=? AND entity_type=?",(definition_id,workspace_id,entity_type)).fetchone()
        if not definition: continue
        text_value=str(value)[:2000]
        if definition["field_type"]=="select" and text_value and text_value not in json.loads(definition["options_json"] or "[]"): continue
        if definition["field_type"]=="boolean": text_value="true" if value in (True,"true","1",1) else "false"
        db.execute("INSERT INTO custom_field_values(definition_id,entity_id,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(definition_id,entity_id) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(definition_id,entity_id,text_value,now()))
        changes.append(f"{definition['name']}={text_value}")
    return changes


def custom_field_values_for(db: sqlite3.Connection, workspace_id: int, entity_type: str, entity_id: int) -> dict:
    return {row["name"]: row["value"] or "" for row in db.execute("SELECT cfd.name,cfv.value FROM custom_field_definitions cfd LEFT JOIN custom_field_values cfv ON cfv.definition_id=cfd.id AND cfv.entity_id=? WHERE cfd.workspace_id=? AND cfd.entity_type=?",(entity_id,workspace_id,entity_type))}


def owns_runbook(db: sqlite3.Connection, rid: int, instance_id: int) -> bool:
    return bool(db.execute("SELECT 1 FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=? AND w.instance_id=?",(rid,instance_id)).fetchone())


TASK_CSV_TYPES={"normal","milestone","checklist","validation","sms","email","call"}


def parse_tasks_csv(csv_text: str) -> list[dict]:
    reader=csv.DictReader(io.StringIO(csv_text))
    if reader.fieldnames is None or "title" not in {f.strip().lower() for f in reader.fieldnames}:
        raise ValueError("CSV must include a 'title' column")
    field_map={f.strip().lower(): f for f in reader.fieldnames}
    rows_out=[]
    for raw in reader:
        title=str(raw.get(field_map.get("title",""),"") or "").strip()[:200]
        if not title: continue
        task_type=str(raw.get(field_map.get("task_type",""),"") or "normal").strip().lower() or "normal"
        if task_type not in TASK_CSV_TYPES: task_type="normal"
        try: duration=max(0,min(int(float(raw.get(field_map.get("duration",""),"") or 15)),10080))
        except ValueError: duration=15
        duration=0 if task_type in {"milestone","checklist","sms","email","call"} else max(1,duration)
        try: scheduled_offset=max(0,int(float(raw.get(field_map.get("scheduled_offset",""),"") or 0)))
        except ValueError: scheduled_offset=0
        rows_out.append({
            "title": title,
            "stream": str(raw.get(field_map.get("stream",""),"") or "").strip()[:80],
            "description": str(raw.get(field_map.get("description",""),"") or "").strip()[:2000],
            "automation_url": str(raw.get(field_map.get("automation_url",""),"") or "").strip()[:500],
            "task_type": task_type,
            "scheduled_offset": scheduled_offset,
            "duration": duration,
        })
    return rows_out


def tasks_to_csv(tasks: list[dict]) -> str:
    buf=io.StringIO()
    fields=["title","stream","owner","duration","task_type","scheduled_offset","status","started_at","completed_at","late","description","automation_url"]
    writer=csv.DictWriter(buf,fieldnames=fields,extrasaction="ignore")
    writer.writeheader()
    for task in tasks:
        writer.writerow({k: task[k] for k in fields})
    return buf.getvalue()


def append_audit(db: sqlite3.Connection, runbook_id: int | None, action: str, detail: str, actor: str = "Preview User", instance_id: int | None = None) -> None:
    if instance_id is None and runbook_id is not None:
        found=db.execute("SELECT w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(runbook_id,)).fetchone()
        instance_id=found[0] if found else None
    if instance_id is None:
        found=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone(); instance_id=found[0] if found else None
    previous = db.execute("SELECT event_hash FROM audit WHERE instance_id=? ORDER BY id DESC LIMIT 1",(instance_id,)).fetchone()
    previous_hash = previous[0] if previous else "GENESIS"
    stamp = now()
    digest = hashlib.sha256(f"{previous_hash}|{runbook_id}|{action}|{detail}|{actor}|{stamp}".encode()).hexdigest()
    db.execute("INSERT INTO audit(runbook_id,action,detail,actor,created_at,previous_hash,event_hash,instance_id) VALUES(?,?,?,?,?,?,?,?)",
               (runbook_id, action, detail, actor, stamp, previous_hash, digest, instance_id))


def rows(items) -> list[dict[str, Any]]:
    return [dict(row) for row in items]


def webhook_matches(events_json: str, action: str) -> bool:
    try:
        patterns = json.loads(events_json or '["*"]')
    except (TypeError, ValueError):
        return False
    return any(p == "*" or p == action for p in patterns) if isinstance(patterns, list) else False


def webhook_payload(provider: str, event: dict[str, Any]) -> dict[str, Any]:
    """Slack and Microsoft Teams incoming webhooks each expect their own
    simple message shape and authenticate via the secrecy of the URL
    itself, not a signature header -- unlike FlowOps' own generic webhook,
    which is a portable signed JSON envelope any receiver can verify."""
    summary = f"{event['action']}: {event['detail']}" if event["detail"] else event["action"]
    if provider == "slack":
        return {"text": f"*FlowOps* — {summary}\n_by {event['actor']}_"}
    if provider == "teams":
        return {"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": "FlowOps event",
                "title": "FlowOps", "text": summary, "sections": [{"facts": [{"name": "Actor", "value": event["actor"]}]}]}
    return {
        "event": event["action"], "id": event["id"], "runbook_id": event["runbook_id"],
        "detail": event["detail"], "actor": event["actor"], "created_at": event["created_at"],
    }


def deliver_webhook_once(webhook: dict[str, Any], event: dict[str, Any]) -> tuple[int | None, str | None, int]:
    """POST one audit event to one webhook, retrying up to 3 times with a
    short fixed backoff on network failure or a non-2xx response. Generic
    webhooks are HMAC-signed; Slack/Teams webhooks are not (their own
    incoming-webhook URLs are the secret, per each provider's own model)."""
    provider = webhook.get("provider", "generic")
    payload = webhook_payload(provider, event)
    body = json.dumps(payload, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if provider == "generic":
        signature = hmac.new(webhook["secret"].encode(), body, hashlib.sha256).hexdigest()
        headers["X-FlowOps-Signature"] = f"sha256={signature}"
        headers["X-FlowOps-Event"] = event["action"]
    last_error = None; status = None
    for attempt in range(1, 4):
        request = urllib.request.Request(webhook["url"], data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                return response.status, None, attempt
        except urllib.error.HTTPError as exc:
            status = exc.code; last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            status = None; last_error = str(exc)[:300]
        if attempt < 3: time.sleep(attempt * 2)
    return status, last_error, 3


def claim_new_audit_events() -> list[dict[str, Any]]:
    """Atomically claim the next batch of unprocessed audit rows and
    advance the shared cursor before any (slow, retryable) network I/O
    happens. BEGIN IMMEDIATE takes SQLite's write lock immediately, so
    when multiple FlowOps replicas share one database file (as they do in
    Kubernetes, where this pod's local PV is mounted read/write by every
    replica scheduled to the same node), only one replica's claim can
    succeed per batch -- the other blocks on the write lock (up to the
    connection's busy timeout) and then sees the cursor already advanced
    past this batch, so it correctly claims nothing rather than
    re-delivering the same events to the same webhooks."""
    db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute("SELECT last_audit_id FROM webhook_cursor WHERE id=1").fetchone()
        if not cursor:
            db.execute("INSERT OR IGNORE INTO webhook_cursor(id,last_audit_id) VALUES(1,0)"); last_id = 0
        else:
            last_id = cursor[0]
        events = rows(db.execute("SELECT * FROM audit WHERE id>? ORDER BY id LIMIT 50", (last_id,)))
        if events:
            db.execute("UPDATE webhook_cursor SET last_audit_id=?", (events[-1]["id"],))
        db.execute("COMMIT")
        return events
    except Exception:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()


def webhook_dispatcher_loop() -> None:
    """Background poller (mirrors the SSE feed's own polling design): picks
    up newly committed audit rows and delivers them to every active webhook
    subscribed to that action, so delivery never blocks a request thread."""
    while True:
        try:
            events = claim_new_audit_events()
            if events:
                with connect() as db:
                    for event in events:
                        webhooks = rows(db.execute("SELECT * FROM webhooks WHERE instance_id=? AND active=1", (event["instance_id"],)))
                        for webhook in webhooks:
                            if not webhook_matches(webhook["events_json"], event["action"]): continue
                            status, error, attempts = deliver_webhook_once(webhook, event)
                            db.execute(
                                "INSERT INTO webhook_deliveries(webhook_id,audit_id,event_type,success,status_code,error,attempts,attempted_at) VALUES(?,?,?,?,?,?,?,?)",
                                (webhook["id"], event["id"], event["action"], 1 if status and 200<=status<300 else 0, status, error, attempts, now()),
                            )
                    db.commit()
        except Exception as exc:
            print(f"webhook dispatcher error: {exc}")
        time.sleep(2)


def runbook_document(db: sqlite3.Connection, rid: int, user: dict[str,Any] | None=None) -> dict[str, Any] | None:
    if user and not owns_runbook(db,rid,user["instance_id"]):
        return None
    rb = db.execute("SELECT * FROM runbooks WHERE id=?", (rid,)).fetchone()
    if not rb:
        return None
    doc = dict(rb)
    doc["runbook_type_requires_approval"] = bool(db.execute("SELECT requires_approval FROM runbook_types WHERE id=?",(doc["runbook_type_id"],)).fetchone()[0]) if doc.get("runbook_type_id") else False
    all_tasks = rows(db.execute("SELECT t.*,u.display_name owner_user_name,rt.name owner_team_name FROM tasks t LEFT JOIN users u ON u.id=t.owner_user_id LEFT JOIN runbook_teams rt ON rt.id=t.owner_team_id WHERE t.runbook_id=? ORDER BY t.sort_order,t.id", (rid,)))
    tasks=all_tasks
    if user and user.get("role")=="Member":
        team_ids={row[0] for row in db.execute("SELECT team_id FROM team_members WHERE user_id=?",(user["id"],))}
        team_ids|={row[0] for row in db.execute("SELECT rt.id FROM runbook_teams rt JOIN central_team_members ctm ON ctm.team_id=rt.central_team_id WHERE rt.runbook_id=? AND ctm.user_id=?",(rid,user["id"]))}
        tasks=[t for t in all_tasks if t["owner_user_id"]==user["id"] or t["owner_team_id"] in team_ids]
    deps = rows(db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?", (rid,)))
    dep_map: dict[int,list[int]] = {}
    for dep in deps:
        dep_map.setdefault(dep["task_id"], []).append(dep["depends_on_id"])
    for task in tasks:
        task["depends_on"] = dep_map.get(task["id"], [])
        task["blocked"] = task["status"] == "pending" and any(next((x["status"] for x in all_tasks if x["id"] == d), "pending") not in {"complete","skipped"} for d in task["depends_on"])
        task["owner_display"] = task["owner_user_name"] or task["owner_team_name"] or task["owner"] or "Unassigned"
    # Earliest-possible-start offset per task, derived from its longest
    # predecessor chain (not the unused, always-zero scheduled_offset column):
    # a task blocked behind 90 minutes of prior work cannot be late the
    # instant the runbook's overall start time passes -- it becomes late
    # only once its own dependency chain's planned finish time passes.
    by_id = {t["id"]: t for t in tasks}
    earliest_start_memo: dict[int, int] = {}
    def earliest_start(tid: int) -> int:
        if tid in earliest_start_memo: return earliest_start_memo[tid]
        task = by_id.get(tid)
        if not task: return 0
        earliest_start_memo[tid] = 0
        offset = max((earliest_start(dep) + by_id[dep]["duration"] for dep in task["depends_on"] if dep in by_id), default=0)
        earliest_start_memo[tid] = offset
        return offset
    runbook_live = rb["mode"] == "live" or bool(rb["actual_started_at"])
    for task in tasks:
        task["late"] = False
        task["delay_minutes"] = 0
        if rb["scheduled_at"] and not task["blocked"]:
            try:
                scheduled=datetime.fromisoformat(rb["scheduled_at"])
                if scheduled.tzinfo is None: scheduled=scheduled.replace(tzinfo=timezone.utc)
                offset = earliest_start(task["id"])
                deadline = scheduled.timestamp() + (offset+task["duration"])*60
                if runbook_live and task["status"] not in {"complete","skipped"}:
                    task["late"] = datetime.now(timezone.utc).timestamp() > deadline
                elif task["status"]=="complete" and task["completed_at"]:
                    completed=datetime.fromisoformat(task["completed_at"])
                    if completed.tzinfo is None: completed=completed.replace(tzinfo=timezone.utc)
                    task["delay_minutes"] = max(0, round((completed.timestamp()-deadline)/60))
            except ValueError: pass
    doc["tasks"] = tasks
    doc["comments"] = rows(db.execute("SELECT * FROM comments WHERE runbook_id=? ORDER BY id DESC", (rid,)))
    doc["teams"] = [dict(t, member_count=len(team_member_user_ids(db, t["id"]))) for t in rows(db.execute("SELECT rt.id,rt.name,rt.central_team_id,ct.name central_team_name FROM runbook_teams rt LEFT JOIN central_teams ct ON ct.id=rt.central_team_id WHERE rt.runbook_id=? ORDER BY rt.name",(rid,)))]
    doc["streams"] = rows(db.execute("SELECT s.id,s.name,s.sort_order,COUNT(t.id) task_count FROM streams s LEFT JOIN tasks t ON t.runbook_id=s.runbook_id AND t.stream=s.name WHERE s.runbook_id=? GROUP BY s.id ORDER BY s.sort_order,s.name",(rid,)))
    doc["custom_fields"] = custom_field_values_for(db, doc["workspace_id"], "runbook", rid)
    for task in tasks: task["custom_fields"] = custom_field_values_for(db, doc["workspace_id"], "task", task["id"])
    doc["parent_runbook"] = rows(db.execute("SELECT id,name,status FROM runbooks WHERE id=?", (doc["parent_runbook_id"],)))[0] if doc.get("parent_runbook_id") else None
    children = rows(db.execute(
        "SELECT r.id,r.name,r.status,COUNT(t.id) task_count,SUM(CASE WHEN t.status='complete' THEN 1 ELSE 0 END) done_count "
        "FROM runbooks r LEFT JOIN tasks t ON t.runbook_id=r.id WHERE r.parent_runbook_id=? GROUP BY r.id ORDER BY r.name", (rid,)
    ))
    for child in children: child["progress"] = round(child["done_count"] * 100 / child["task_count"]) if child["task_count"] else 0
    doc["child_runbooks"] = children
    if children:
        total_tasks = sum(c["task_count"] for c in children)
        total_done = sum(c["done_count"] or 0 for c in children)
        doc["aggregate_progress"] = round(total_done * 100 / total_tasks) if total_tasks else 0
        doc["aggregate_status"] = "complete" if all(c["status"] == "complete" for c in children) else "cancelled" if any(c["status"] == "cancelled" for c in children) else "live" if any(c["status"] == "live" for c in children) else "in_progress"
    doc["audit"] = rows(db.execute("SELECT * FROM audit WHERE runbook_id=? ORDER BY id DESC LIMIT 100", (rid,)))
    done = sum(t["status"] == "complete" for t in tasks)
    doc["progress"] = round(done * 100 / len(tasks)) if tasks else 0
    doc["duration"] = sum(t["duration"] for t in tasks)
    doc["critical_path"] = critical_path(tasks)
    current_time = datetime.now(timezone.utc)
    def instant(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    scheduled = instant(doc.get("scheduled_at"))
    started = instant(doc.get("actual_started_at"))
    completed = instant(doc.get("actual_completed_at"))
    elapsed = max(0, int(((completed or current_time) - started).total_seconds())) if started else 0
    seconds_to_start = int((scheduled - current_time).total_seconds()) if scheduled and not started else None
    if completed:
        timing_phase = "complete"
    elif doc["status"] == "paused":
        timing_phase = "paused"
    elif started:
        timing_phase = "live"
    elif not scheduled:
        timing_phase = "unscheduled"
    elif seconds_to_start is not None and seconds_to_start < 0:
        timing_phase = "overdue"
    elif seconds_to_start is not None and seconds_to_start <= 900:
        timing_phase = "start_due"
    else:
        timing_phase = "upcoming"
    planned_seconds = doc["duration"] * 60
    doc["timing"] = {
        "server_now": current_time.isoformat(timespec="seconds"),
        "scheduled_at": doc.get("scheduled_at"),
        "actual_started_at": doc.get("actual_started_at"),
        "actual_completed_at": doc.get("actual_completed_at"),
        "seconds_to_start": seconds_to_start,
        "elapsed_seconds": elapsed,
        "planned_seconds": planned_seconds,
        "variance_seconds": elapsed - planned_seconds if started else None,
        "phase": timing_phase,
    }
    return doc


def critical_path(tasks: list[dict[str, Any]]) -> list[int]:
    by_id = {t["id"]: t for t in tasks}; memo: dict[int,tuple[int,list[int]]] = {}; visiting=set()
    def visit(tid: int) -> tuple[int,list[int]]:
        if tid in memo: return memo[tid]
        if tid in visiting: return (0, [])
        visiting.add(tid); task=by_id[tid]; best=(0,[])
        for dep in task["depends_on"]:
            if dep in by_id:
                candidate=visit(dep)
                if candidate[0] > best[0]: best=candidate
        visiting.discard(tid); memo[tid]=(best[0]+task["duration"], best[1]+[tid]); return memo[tid]
    return max((visit(t["id"]) for t in tasks), default=(0,[]), key=lambda x:x[0])[1]


class Handler(BaseHTTPRequestHandler):
    server_version = "FlowOps/0.1"

    def log_message(self, fmt, *args):
        code=args[1] if len(args)>1 else None
        print(json.dumps({
            "ts":now(),"level":"error" if code and str(code)[0] in "45" else "info",
            "client":self.address_string(),"method":self.command,"path":self.path.split("?")[0] if getattr(self,"path",None) else None,
            "status":code,"message":fmt%args,
        },separators=(",",":")))

    def log_error(self, fmt, *args):
        print(json.dumps({"ts":now(),"level":"error","client":self.address_string(),"message":fmt%args},separators=(",",":")))

    def send_json(self, payload: Any, status=200, headers: dict[str,str] | None=None):
        body=json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY")
        self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
        for key,value in (headers or {}).items(): self.send_header(key,value)
        self.end_headers(); self.wfile.write(body)

    def current_user(self, db: sqlite3.Connection) -> dict[str,Any] | None:
        auth_header=self.headers.get("Authorization","")
        if auth_header.startswith("Bearer fo_"):
            raw=auth_header[len("Bearer "):].strip()
            digest=hashlib.sha256(raw.encode()).hexdigest()
            row=db.execute("SELECT * FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL",(digest,)).fetchone()
            if not row: return None
            db.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?",(now(),row["id"]))
            scopes=json.loads(row["scopes_json"] or "[]")
            permissions=set()
            for scope in scopes: permissions|=TOKEN_SCOPE_PERMISSIONS.get(scope,set())
            return {"id":None,"username":f"api:{row['name']}","display_name":f"API token: {row['name']}","role":"ApiToken","instance_id":row["instance_id"],"permissions":sorted(permissions),"csrf_token":None,"auth_method":"token"}
        cookies={}
        for item in self.headers.get("Cookie","").split(";"):
            if "=" in item:
                key,value=item.strip().split("=",1); cookies[key]=value
        token=cookies.get("flowops_session","")
        if not token: return None
        digest=hashlib.sha256(token.encode()).hexdigest()
        row=db.execute("SELECT u.*,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",(digest,int(time.time()))).fetchone()
        if not row: return None
        user=dict(row); user["permissions"]=sorted(ROLE_PERMISSIONS.get(user["role"],set())); user.pop("password_hash",None); user["auth_method"]="session"
        return user

    def require(self, db: sqlite3.Connection, permission: str) -> dict[str,Any] | None:
        user=self.current_user(db)
        if not user:
            self.send_json({"error":"Authentication required"},401); return None
        if permission not in user["permissions"]:
            self.send_json({"error":f"Your {user['role']} role does not allow this action"},403); return None
        if user.get("auth_method")=="session" and self.command in {"POST","PATCH","PUT","DELETE"} and self.headers.get("X-CSRF-Token","") != user["csrf_token"]:
            self.send_json({"error":"Invalid or missing CSRF token"},403); return None
        return user

    def require_scoped_edit(self, db: sqlite3.Connection, workspace_id: int | None = None, folder_id: int | None = None, runbook_id: int | None = None) -> dict[str,Any] | None:
        user=self.current_user(db)
        if not user:
            self.send_json({"error":"Authentication required"},401); return None
        if user.get("auth_method")=="session" and self.command in {"POST","PATCH","PUT","DELETE"} and self.headers.get("X-CSRF-Token","") != user["csrf_token"]:
            self.send_json({"error":"Invalid or missing CSRF token"},403); return None
        role=user["role"]
        if "runbooks:edit" in user["permissions"]:
            if role=="Workspace Manager":
                wsid=workspace_id
                if wsid is None and runbook_id is not None:
                    found=db.execute("SELECT workspace_id FROM runbooks WHERE id=?",(runbook_id,)).fetchone(); wsid=found[0] if found else None
                if wsid is None or not db.execute("SELECT 1 FROM workspace_managers WHERE user_id=? AND workspace_id=?",(user["id"],wsid)).fetchone():
                    self.send_json({"error":"Your Workspace Manager role is not granted for this workspace"},403); return None
            return user
        if role=="Folder Creator" and folder_id is not None and db.execute("SELECT 1 FROM folder_creator_grants WHERE user_id=? AND folder_id=?",(user["id"],folder_id)).fetchone():
            return user
        if role=="Stream Editor" and runbook_id is not None and db.execute("SELECT 1 FROM stream_editor_grants WHERE user_id=? AND runbook_id=?",(user["id"],runbook_id)).fetchone():
            return user
        self.send_json({"error":f"Your {role} role does not allow this action"},403); return None

    def require_workspace_scoped_edit(self, db: sqlite3.Connection, runbook_id: int | None = None, workspace_id: int | None = None) -> dict[str,Any] | None:
        user=self.require(db,"runbooks:edit")
        if not user: return None
        if user["role"]=="Workspace Manager":
            wsid=workspace_id
            if wsid is None and runbook_id is not None:
                found=db.execute("SELECT workspace_id FROM runbooks WHERE id=?",(runbook_id,)).fetchone(); wsid=found[0] if found else None
            if wsid is None or not db.execute("SELECT 1 FROM workspace_managers WHERE user_id=? AND workspace_id=?",(user["id"],wsid)).fetchone():
                self.send_json({"error":"Your Workspace Manager role is not granted for this workspace"},403); return None
        return user

    def body(self) -> dict[str, Any]:
        length=int(self.headers.get("Content-Length","0"))
        if length > MAX_BODY: raise ValueError("Request is too large")
        data=json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data,dict): raise ValueError("A JSON object is required")
        return data

    def serviceops_directory_authenticate(self, db: sqlite3.Connection, instance_id: int, username: str, password: str) -> dict[str,Any]:
        values=instance_settings(db,instance_id)
        if values.get("directory_enabled","false") != "true":
            raise RuntimeError("Corporate directory sign-in is not enabled")
        base=values.get("serviceops_url",os.getenv("SERVICEOPS_URL","")).strip().rstrip("/")
        if not base: raise RuntimeError("ServiceOps is not configured")
        endpoint=(base if base.endswith("/api/v1") else f"{base}/api/v1")+"/auth/mobile/login"
        headers={"Content-Type":"application/json","Accept":"application/json","X-ServiceOps-App-Version":"FlowOps/0.1","X-ServiceOps-App-Build":"flowops","X-ServiceOps-Platform":"web","X-ServiceOps-Device":"FlowOps server"}
        request=urllib.request.Request(endpoint,data=json.dumps({"username":username,"password":password,"provider":"ldap"}).encode(),headers=headers,method="POST")
        try:
            with urllib.request.urlopen(request,timeout=8) as response:
                if "application/json" not in response.headers.get("Content-Type",""):
                    raise RuntimeError("ServiceOps returned a non-JSON response; use its internal cluster URL, not the Cloudflare Access URL")
                result=json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError("Invalid username or password" if exc.code in {401,403,423} else f"ServiceOps directory authentication returned HTTP {exc.code}") from exc
        except (urllib.error.URLError,TimeoutError,json.JSONDecodeError) as exc:
            raise RuntimeError("ServiceOps directory authentication is unavailable") from exc
        access=str(result.get("access_token", "")); remote=result.get("user") or {}
        if not access or not remote.get("username"): raise RuntimeError("ServiceOps returned an incomplete directory identity")
        logout=urllib.request.Request((base if base.endswith("/api/v1") else f"{base}/api/v1")+"/auth/mobile/logout",data=b"{}",headers={**headers,"Authorization":f"Bearer {access}"},method="POST")
        try:
            urllib.request.urlopen(logout,timeout=5).close()
        except (urllib.error.URLError,TimeoutError):
            pass
        return remote

    def static(self, name: str, content_type: str):
        try: body=(STATIC/name).read_bytes()
        except FileNotFoundError: return self.send_error(404)
        if name=="index.html":
            # Cache-Control alone only governs *future* requests -- it can't
            # invalidate a copy a browser (or an intermediate cache) already
            # stored under the old header before this fix shipped. Versioning
            # the asset URL itself, the same way ServiceOps does
            # (?v={{app_version}}), means every deploy references a URL no
            # cache anywhere has ever seen, so nothing to invalidate is ever
            # needed -- the browser has no choice but to fetch fresh.
            body=body.replace(b'href="/styles.css"', f'href="/styles.css?v={VERSION}"'.encode())
            body=body.replace(b'src="/app.js"', f'src="/app.js?v={VERSION}"'.encode())
        self.send_response(200); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(body)))
        # no-store, not no-cache: no-cache still permits a cache (browser or,
        # critically, Cloudflare's edge in front of this app) to serve a
        # stale copy without contacting the origin, since this response
        # carries no ETag/Last-Modified to revalidate against anyway.
        # no-store is the one directive every cache in the chain must obey
        # unconditionally, which matters a lot for app.js: a stale cached
        # copy silently hides every UI fix behind it, indefinitely.
        self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body)

    def do_HEAD(self):
        path=urllib.parse.urlparse(self.path).path
        if path in ("/health","/ready"):
            self.send_response(200); self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff")
            self.end_headers(); return
        static_types={"/":"text/html; charset=utf-8","/app.js":"application/javascript; charset=utf-8","/styles.css":"text/css; charset=utf-8"}
        if path in static_types:
            self.send_response(200); self.send_header("Content-Type",static_types[path])
            self.send_header("Cache-Control","no-store"); self.end_headers(); return
        self.send_error(404)

    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        if path=="/": return self.static("index.html","text/html; charset=utf-8")
        if path=="/app.js": return self.static("app.js","application/javascript; charset=utf-8")
        if path=="/styles.css": return self.static("styles.css","text/css; charset=utf-8")
        if path in ("/health","/ready"): return self.send_json({"status":"ok","service":"flowops","version":VERSION})
        if path=="/api/auth/sources":
            with connect() as db:
                instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()
                values=instance_settings(db,instance["id"]) if instance else {}
                directory_enabled=values.get("directory_enabled","false")=="true"
                domain=values.get("directory_domain","").strip()
                sources=[{"id":"local","label":"Local administrator","placeholder":"Username"}]
                if directory_enabled:
                    label=domain or "Corporate directory"
                    placeholder=f"jsmith or jsmith@{domain}" if domain else "jsmith"
                    sources.insert(0,{"id":"ldap","label":label,"placeholder":placeholder})
                return self.send_json({"data":{"sources":sources,"default":"ldap" if directory_enabled else "local"}})
        if path=="/api/events": return self.stream_events()
        with connect() as db:
            if path=="/api/auth/me":
                user=self.current_user(db)
                if not user: return self.send_json({"error":"Authentication required"},401)
                raw_widgets=user.get("dashboard_widgets")
                try: widgets=json.loads(raw_widgets) if raw_widgets else None
                except json.JSONDecodeError: widgets=None
                user["dashboard_widgets"]=widgets if widgets is not None else ["runbook_activity","today_readiness","delay_summary"]
                settings=instance_settings(db,user["instance_id"])
                return self.send_json({"data":{"user":user,"settings":settings}})
            if path=="/api/admin/users":
                actor=self.require(db,"admin:users")
                if not actor: return
                data=rows(db.execute("SELECT id,username,display_name,email,role,team,active,last_login_at,created_at FROM users WHERE instance_id=? ORDER BY display_name",(actor["instance_id"],)))
                return self.send_json({"data":data})
            if path=="/api/admin/scoped-role-grants":
                actor=self.require(db,"admin:users")
                if not actor: return
                workspace_managers=rows(db.execute("SELECT wm.user_id,u.display_name,wm.workspace_id,w.name workspace_name FROM workspace_managers wm JOIN users u ON u.id=wm.user_id JOIN workspaces w ON w.id=wm.workspace_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
                folder_creators=rows(db.execute("SELECT fc.user_id,u.display_name,fc.folder_id,f.name folder_name FROM folder_creator_grants fc JOIN users u ON u.id=fc.user_id JOIN folders f ON f.id=fc.folder_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
                stream_editors=rows(db.execute("SELECT se.user_id,u.display_name,se.runbook_id,r.name runbook_name FROM stream_editor_grants se JOIN users u ON u.id=se.user_id JOIN runbooks r ON r.id=se.runbook_id WHERE u.instance_id=? ORDER BY u.display_name",(actor["instance_id"],)))
                return self.send_json({"data":{"workspace_managers":workspace_managers,"folder_creators":folder_creators,"stream_editors":stream_editors}})
            if path=="/api/admin/api-tokens":
                actor=self.require(db,"admin:users")
                if not actor: return
                items=rows(db.execute("SELECT id,name,scopes_json,created_at,last_used_at,revoked_at FROM api_tokens WHERE instance_id=? ORDER BY created_at DESC",(actor["instance_id"],)))
                for item in items: item["scopes"]=json.loads(item.pop("scopes_json") or "[]")
                return self.send_json({"data":items})
            if path=="/api/admin/webhooks":
                actor=self.require(db,"admin:users")
                if not actor: return
                items=rows(db.execute("SELECT id,name,url,provider,events_json,active,created_at FROM webhooks WHERE instance_id=? ORDER BY created_at DESC",(actor["instance_id"],)))
                for item in items:
                    item["events"]=json.loads(item.pop("events_json") or "[]")
                    recent=rows(db.execute("SELECT success,status_code,error,attempted_at FROM webhook_deliveries WHERE webhook_id=? ORDER BY id DESC LIMIT 5",(item["id"],)))
                    item["recent_deliveries"]=recent
                return self.send_json({"data":items})
            if path=="/api/admin/settings":
                actor=self.require(db,"admin:settings")
                if not actor: return
                values=instance_settings(db,actor["instance_id"]);mail=mail_configuration()
                values.update({"mail_delivery_configured":str(mail["configured"]).lower(),"mail_sender":mail["sender"],"mail_security":mail["security"],"public_url_configured":str(bool(mail["public_url"])).lower()})
                return self.send_json({"data":values})
            if path=="/api/admin/integrations":
                actor=self.require(db,"admin:settings")
                if not actor: return
                values=instance_settings(db,actor["instance_id"])
                try:serviceops_token,serviceops_source=integration_credential(db,actor["instance_id"],"serviceops")
                except RuntimeError:serviceops_token,serviceops_source="","Encrypted credential unavailable"
                data={
                  "serviceops":{"enabled":values.get("serviceops_enabled","true"),"url":values.get("serviceops_url",os.getenv("SERVICEOPS_URL","")),"credential_configured":bool(serviceops_token),"credential_source":serviceops_source,"credential_editable":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"sync_on_live":values.get("serviceops_sync_on_live","true"),"sync_on_complete":values.get("serviceops_sync_on_complete","true"),"require_approved":values.get("serviceops_require_approved","true"),"trigger_workflow":values.get("serviceops_trigger_workflow","false"),"api_version":"v1","required_scopes":["tickets:read","tickets:update","workflows:execute"]}
                }
                return self.send_json({"data":data})
            if path=="/api/admin/workspaces":
                actor=self.require(db,"admin:settings")
                if not actor: return
                data=rows(db.execute("SELECT w.*,COUNT(r.id) runbook_count FROM workspaces w LEFT JOIN runbooks r ON r.workspace_id=w.id WHERE w.instance_id=? GROUP BY w.id ORDER BY w.name",(actor["instance_id"],)))
                return self.send_json({"data":data})
            if path=="/api/admin/sessions":
                actor=self.require(db,"admin:users")
                if not actor:return
                data=rows(db.execute("SELECT s.id,u.display_name,u.username,s.ip_address,s.user_agent,s.created_at,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.instance_id=? AND s.expires_at>? ORDER BY s.created_at DESC",(actor["instance_id"],int(time.time()))))
                return self.send_json({"data":data})
            if path=="/api/admin/audit":
                actor=self.require(db,"admin:access")
                if not actor:return
                return self.send_json({"data":rows(db.execute("SELECT id,runbook_id,action,detail,actor,created_at,event_hash FROM audit WHERE instance_id=? ORDER BY id DESC LIMIT 250",(actor["instance_id"],)))})
            if path=="/api/admin/audit/export":
                actor=self.require(db,"admin:access")
                if not actor:return
                events=rows(db.execute("SELECT id,runbook_id,action,detail,actor,created_at,previous_hash,event_hash FROM audit WHERE instance_id=? ORDER BY id ASC",(actor["instance_id"],)))
                chain_verified=True
                previous=instance_settings(db,actor["instance_id"]).get("audit_retention_checkpoint","GENESIS")
                for event in events:
                    if event["previous_hash"]!=previous: chain_verified=False; break
                    expected=hashlib.sha256(f"{previous}|{event['runbook_id']}|{event['action']}|{event['detail']}|{event['actor']}|{event['created_at']}".encode()).hexdigest()
                    if expected!=event["event_hash"]: chain_verified=False; break
                    previous=event["event_hash"]
                export_body=json.dumps(events,sort_keys=True,separators=(",",":"))
                checksum=hashlib.sha256(export_body.encode()).hexdigest()
                append_audit(db,None,"audit.exported",f"{len(events)} events, chain_verified={chain_verified}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"events":events,"count":len(events),"exported_at":now(),"chain_verified":chain_verified,"checksum":f"sha256:{checksum}"}})
            if path=="/api/admin/health":
                actor=self.require(db,"admin:access")
                if not actor:return
                counts=db.execute("SELECT (SELECT COUNT(*) FROM users WHERE instance_id=? AND active=1),(SELECT COUNT(*) FROM workspaces WHERE instance_id=? AND active=1),(SELECT COUNT(*) FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?),(SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.instance_id=? AND s.expires_at>?)",(actor["instance_id"],actor["instance_id"],actor["instance_id"],actor["instance_id"],int(time.time()))).fetchone()
                return self.send_json({"data":{"status":"healthy","version":VERSION,"database":db.execute("PRAGMA integrity_check").fetchone()[0],"active_users":counts[0],"workspaces":counts[1],"runbooks":counts[2],"active_sessions":counts[3],"email_configured":mail_configuration()["configured"],"credential_encryption_configured":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"realtime":"SSE"}})
            if path=="/api/workspaces":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                return self.send_json({"data":rows(db.execute("SELECT id,name,description,color FROM workspaces WHERE active=1 AND instance_id=? ORDER BY name",(actor["instance_id"],)))})
            if path=="/api/folders":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                items=rows(db.execute("SELECT f.*,COUNT(r.id) runbook_count FROM folders f JOIN workspaces w ON w.id=f.workspace_id LEFT JOIN runbooks r ON r.folder_id=f.id WHERE w.instance_id=? GROUP BY f.id ORDER BY f.sort_order,f.name",(actor["instance_id"],)))
                return self.send_json({"data":items})
            if path=="/api/runbook-types":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                items=rows(db.execute("SELECT rt.*,COUNT(r.id) runbook_count FROM runbook_types rt JOIN workspaces w ON w.id=rt.workspace_id LEFT JOIN runbooks r ON r.runbook_type_id=rt.id WHERE w.instance_id=? GROUP BY rt.id ORDER BY rt.name",(actor["instance_id"],)))
                return self.send_json({"data":items})
            if path=="/api/central-teams":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                teams=rows(db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE w.instance_id=? ORDER BY ct.name",(actor["instance_id"],)))
                for team in teams:
                    team["members"]=rows(db.execute("SELECT u.id,u.display_name,u.email FROM users u JOIN central_team_members ctm ON ctm.user_id=u.id WHERE ctm.team_id=? ORDER BY u.display_name",(team["id"],)))
                    team["linked_runbooks"]=db.execute("SELECT COUNT(*) FROM runbook_teams WHERE central_team_id=?",(team["id"],)).fetchone()[0]
                return self.send_json({"data":teams})
            if path=="/api/custom-fields":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                entity_type=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("entity_type",[None])[0]
                clause="AND cfd.entity_type=?" if entity_type else ""
                params=[actor["instance_id"]]+([entity_type] if entity_type else [])
                items=rows(db.execute(f"SELECT cfd.* FROM custom_field_definitions cfd JOIN workspaces w ON w.id=cfd.workspace_id WHERE w.instance_id=? {clause} ORDER BY cfd.entity_type,cfd.sort_order",params))
                for item in items: item["options"]=json.loads(item.pop("options_json") or "[]")
                return self.send_json({"data":items})
            if path=="/api/templates":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                workspace_id=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("workspace_id",[None])[0]
                clause="AND t.workspace_id=?" if workspace_id else ""
                params=[actor["instance_id"]]+([int(workspace_id)] if workspace_id else [])
                items=rows(db.execute(f"SELECT t.*,COUNT(tt.id) task_count FROM templates t JOIN workspaces w ON w.id=t.workspace_id LEFT JOIN template_tasks tt ON tt.template_id=t.id WHERE w.instance_id=? {clause} GROUP BY t.id ORDER BY t.category,t.name",params))
                return self.send_json({"data":items})
            if path=="/api/runbooks":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                include_archived=query.get("include_archived",["0"])[0]=="1"
                archived_clause="" if include_archived else "AND r.archived=0"
                folder_clause=""; params=[actor["instance_id"]]
                if query.get("folder_id"):
                    folder_clause="AND r.folder_id=?"; params.append(int(query["folder_id"][0]))
                items=rows(db.execute(f"SELECT r.*,w.name workspace_name,f.name folder_name,rt.name runbook_type_name,rt.icon runbook_type_icon,rt.color runbook_type_color,COUNT(t.id) task_count,SUM(CASE WHEN t.status='complete' THEN 1 ELSE 0 END) done_count FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id LEFT JOIN folders f ON f.id=r.folder_id LEFT JOIN runbook_types rt ON rt.id=r.runbook_type_id LEFT JOIN tasks t ON t.runbook_id=r.id WHERE w.instance_id=? {archived_clause} {folder_clause} GROUP BY r.id ORDER BY r.updated_at DESC",params))
                return self.send_json({"data":items})
            if path.startswith("/api/runbooks/"):
                user=self.require(db,"runbooks:view")
                if not user: return
                parts=path.strip("/").split("/")
                try: rid=int(parts[2])
                except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
                if not owns_runbook(db,rid,user["instance_id"]): return self.send_json({"error":"Not found"},404)
                if len(parts)==4 and parts[3]=="assignment-options":
                    users=rows(db.execute("SELECT id,display_name,email FROM users WHERE active=1 AND instance_id=? ORDER BY display_name",(user["instance_id"],))); teams=rows(db.execute("SELECT id,name FROM runbook_teams WHERE runbook_id=? ORDER BY name",(rid,)))
                    return self.send_json({"data":{"users":users,"teams":teams}})
                if len(parts)==4 and parts[3]=="teams":
                    teams=rows(db.execute("SELECT rt.id,rt.name,rt.central_team_id FROM runbook_teams rt WHERE rt.runbook_id=? ORDER BY rt.name",(rid,)))
                    for team in teams:
                        member_ids=team_member_user_ids(db, team["id"])
                        team["members"]=rows(db.execute(f"SELECT id,display_name,email FROM users WHERE id IN ({','.join('?'*len(member_ids)) or 'NULL'}) ORDER BY display_name",tuple(member_ids))) if member_ids else []
                        team["member_count"]=len(member_ids)
                    return self.send_json({"data":teams})
                if len(parts)==4 and parts[3]=="tasks.csv":
                    doc=runbook_document(db,rid,user)
                    csv_body=tasks_to_csv(doc["tasks"] if doc else [])
                    self.send_response(200); self.send_header("Content-Type","text/csv; charset=utf-8")
                    self.send_header("Content-Disposition",f'attachment; filename="runbook-{rid}-tasks.csv"')
                    self.send_header("Content-Length",str(len(csv_body.encode())))
                    self.end_headers(); self.wfile.write(csv_body.encode()); return
                if len(parts)!=3:return self.send_json({"error":"Not found"},404)
                doc=runbook_document(db,rid,user)
                return self.send_json({"data":doc} if doc else {"error":"Not found"},200 if doc else 404)
            if path in ("/api/reports/delay","/api/reports/delay.csv"):
                actor=self.require(db,"runbooks:view")
                if not actor: return
                runbook_ids=[row[0] for row in db.execute("SELECT r.id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND r.archived=0",(actor["instance_id"],))]
                report_rows=[]
                for rbid in runbook_ids:
                    doc=runbook_document(db,rbid,None)
                    if not doc: continue
                    for task in doc["tasks"]:
                        if task["late"] or task["delay_minutes"]>0:
                            report_rows.append({"runbook":doc["name"],"task":task["title"],"stream":task["stream"],"owner":task["owner_display"],"status":task["status"],"delay_minutes":task["delay_minutes"] if task["status"]=="complete" else "in progress","scheduled_at":doc["scheduled_at"] or ""})
                if path=="/api/reports/delay.csv":
                    buf=io.StringIO(); writer=csv.DictWriter(buf,fieldnames=["runbook","task","stream","owner","status","delay_minutes","scheduled_at"]); writer.writeheader()
                    for row in report_rows: writer.writerow(row)
                    body=buf.getvalue().encode()
                    self.send_response(200); self.send_header("Content-Type","text/csv; charset=utf-8")
                    self.send_header("Content-Disposition",'attachment; filename="flowops-delay-report.csv"')
                    self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
                return self.send_json({"data":report_rows,"generated_at":now()})
            if path=="/api/dashboard":
                actor=self.require(db,"runbooks:view")
                if not actor: return
                stats=dict(db.execute("SELECT COUNT(*) runbooks, SUM(r.status='live') live, SUM(r.status='complete') complete FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?",(actor["instance_id"],)).fetchone())
                stats["tasks"]=db.execute("SELECT COUNT(*) FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?",(actor["instance_id"],)).fetchone()[0]
                stats["task_completion"]=db.execute("SELECT COALESCE(ROUND(100.0*SUM(t.status='complete')/NULLIF(COUNT(*),0)),0) FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?",(actor["instance_id"],)).fetchone()[0]
                return self.send_json({"data":stats})
        self.send_json({"error":"Not found"},404)

    def stream_events(self):
        """Authenticated same-origin SSE feed backed by the durable audit sequence."""
        with connect() as db:
            user=self.current_user(db)
            if not user or "runbooks:view" not in user["permissions"]:
                return self.send_json({"error":"Authentication required"},401)
            instance_id=user["instance_id"]
            version=db.execute("SELECT COALESCE(MAX(id),0) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
        self.send_response(200); self.send_header("Content-Type","text/event-stream; charset=utf-8")
        self.send_header("Cache-Control","no-cache, no-store"); self.send_header("Connection","keep-alive")
        self.send_header("X-Accel-Buffering","no"); self.end_headers()
        try:
            self.wfile.write(f"event: connected\ndata: {{\"version\":{version}}}\n\n".encode()); self.wfile.flush()
            for tick in range(300):
                time.sleep(1)
                with connect() as db:
                    current=db.execute("SELECT COALESCE(MAX(id),0) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
                    events=rows(db.execute("SELECT id,runbook_id,action,detail,actor,created_at FROM audit WHERE instance_id=? AND id>? ORDER BY id LIMIT 25",(instance_id,version))) if current!=version else []
                if current != version:
                    for event in events:
                        event["version"]=event["id"]
                        self.wfile.write(f"event: workspace\ndata: {json.dumps(event,separators=(',',':'))}\n\n".encode())
                    version=current; self.wfile.flush()
                elif tick % 15 == 0:
                    self.wfile.write(b": heartbeat\n\n"); self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError):
            return

    def do_POST(self):
        path=urllib.parse.urlparse(self.path).path
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.send_json({"error":str(exc)},400)
        with connect() as db:
            if path=="/api/auth/register":
                organization=str(payload.get("organization","" )).strip(); slug=str(payload.get("slug","")).strip().lower()
                username=str(payload.get("username","")).strip(); display=str(payload.get("display_name","")).strip(); email=str(payload.get("email","")).strip().lower(); password=str(payload.get("password",""))
                slug="-".join(filter(None,("".join(c if c.isalnum() else " " for c in slug).split())))
                if not organization or len(slug)<3 or not username or not display or "@" not in email or len(password)<12:
                    return self.send_json({"error":"Organization, a 3-character slug, username, display name, valid email, and a password of at least 12 characters are required"},400)
                if db.execute("SELECT 1 FROM instances WHERE slug=?",(slug,)).fetchone() or db.execute("SELECT 1 FROM users WHERE username=? OR email=?",(username,email)).fetchone():
                    return self.send_json({"error":"That organization, username, or email is already registered"},409)
                stamp=now()
                try:
                    cur=db.execute("INSERT INTO instances(slug,name,created_at) VALUES(?,?,?)",(slug,organization[:160],stamp)); instance_id=cur.lastrowid
                    user_id=db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,email,"Admin","",password_hash(password),stamp,instance_id)).lastrowid
                    db.execute("INSERT INTO workspaces(name,description,color,created_at,instance_id) VALUES(?,?,?,?,?)",("Operations","Default workspace","#7557e8",stamp,instance_id))
                    defaults={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=(SELECT id FROM instances WHERE slug=?)",(DEFAULT_INSTANCE_SLUG,))}
                    for key,value in defaults.items(): db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?)",(instance_id,key,value,stamp))
                    db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value",(instance_id,"workspace_name",organization[:160],stamp))
                    append_audit(db,None,"instance.created",f"{organization} created",display,instance_id); db.commit()
                except sqlite3.IntegrityError:
                    db.rollback(); return self.send_json({"error":"That organization, username, or email is already registered"},409)
                return self.send_json({"data":{"instance_id":instance_id,"user_id":user_id,"slug":slug}},201)
            if path=="/api/auth/login":
                username=str(payload.get("username","")).strip(); password=str(payload.get("password",""));source=str(payload.get("source","local")).lower()
                instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()
                if source=="ldap":
                    if not instance:return self.send_json({"error":"FlowOps instance is unavailable"},503)
                    try:remote=self.serviceops_directory_authenticate(db,instance["id"],username,password)
                    except RuntimeError as exc:time.sleep(.2);return self.send_json({"error":str(exc)},401)
                    username=str(remote["username"]);user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=? AND active=1",(username,instance["id"])).fetchone()
                    if not user:
                        display=str(remote.get("name") or username)[:160];db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,"","Member","",password_hash(secrets.token_urlsafe(48)),now(),instance["id"]));user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=?",(username,instance["id"])).fetchone()
                else:
                    user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1",(username,username)).fetchone()
                    if not user or not password_valid(password,user["password_hash"]):time.sleep(.2);return self.send_json({"error":"Invalid username or password"},401)
                hours=max(1,min(24,int(instance_settings(db,user["instance_id"]).get("session_hours","8")))); session_seconds=hours*3600
                raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+session_seconds
                db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),)); db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now(),self.client_address[0][:64],self.headers.get("User-Agent","")[:300])); db.execute("UPDATE users SET last_login_at=? WHERE id=?",(now(),user["id"])); append_audit(db,None,"auth.login",f"{user['username']} signed in",user["display_name"],user["instance_id"]); db.commit()
                safe={k:user[k] for k in ("id","username","display_name","email","role","team")}; safe["permissions"]=sorted(ROLE_PERMISSIONS[user["role"]]); safe["csrf_token"]=csrf
                return self.send_json({"data":safe},headers={"Set-Cookie":f"flowops_session={raw}; Path=/; HttpOnly; SameSite=Strict; Max-Age={session_seconds}"})
            if path=="/api/auth/logout":
                user=self.current_user(db)
                if user:
                    cookies={i.strip().split("=",1)[0]:i.strip().split("=",1)[1] for i in self.headers.get("Cookie","").split(";") if "=" in i}; raw=cookies.get("flowops_session","")
                    db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(raw.encode()).hexdigest(),)); append_audit(db,None,"auth.logout",f"{user['username']} signed out",user["display_name"],user["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}},headers={"Set-Cookie":"flowops_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            if path=="/api/auth/invitations/accept":
                raw=str(payload.get("token","")).strip();username=str(payload.get("username","")).strip();display=str(payload.get("display_name","")).strip();password=str(payload.get("password",""))
                invite=db.execute("SELECT * FROM invitations WHERE token_hash=? AND accepted_at IS NULL AND expires_at>?",(hashlib.sha256(raw.encode()).hexdigest(),int(time.time()))).fetchone() if raw else None
                if not invite:return self.send_json({"error":"Invitation is invalid, expired, or already used"},400)
                if not username or not display or len(password)<12:return self.send_json({"error":"Username, display name, and a password of at least 12 characters are required"},400)
                if db.execute("SELECT 1 FROM users WHERE username=? OR email=?",(username,invite["email"])).fetchone():return self.send_json({"error":"An account already exists for this username or email"},409)
                try:cur=db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,invite["email"],invite["role"],"",password_hash(password),now(),invite["instance_id"]))
                except sqlite3.IntegrityError:return self.send_json({"error":"That username already exists"},409)
                db.execute("UPDATE invitations SET accepted_at=? WHERE id=?",(now(),invite["id"]));append_audit(db,None,"auth.invitation_accepted",f"{invite['email']} joined as {invite['role']}",display,invite["instance_id"]);db.commit()
                return self.send_json({"data":{"ok":True,"username":username,"role":invite["role"]}},201)
            if path=="/api/auth/password-reset/request":
                identity=str(payload.get("identity","")).strip();user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1",(identity,identity)).fetchone()
                response={"ok":True,"message":"If the account exists, password reset instructions have been issued"}
                if user:
                    raw=secrets.token_urlsafe(32);stamp=now();db.execute("UPDATE password_resets SET used_at=? WHERE user_id=? AND used_at IS NULL",(stamp,user["id"]));db.execute("INSERT INTO password_resets(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)",(user["id"],hashlib.sha256(raw.encode()).hexdigest(),int(time.time())+1800,stamp));append_audit(db,None,"auth.password_reset_requested",user["username"],"FlowOps",user["instance_id"])
                    preview=os.getenv("FLOWOPS_PREVIEW_TOKENS","false").lower()=="true"
                    if preview: response["preview_token"]=raw
                    elif mail_configuration()["configured"]:
                        try: send_mail(user["email"],"Reset your FlowOps password",f"Hello {user['display_name']},\n\nReset your FlowOps password within 30 minutes:\n{mail_configuration()['public_url']}/?reset={urllib.parse.quote(raw)}\n\nIf you did not request this, ignore this email.")
                        except RuntimeError: append_audit(db,None,"auth.password_reset_delivery_failed",user["username"],"FlowOps",user["instance_id"])
                    db.commit()
                return self.send_json({"data":response},202)
            if path=="/api/auth/password-reset/complete":
                raw=str(payload.get("token","")).strip();password=str(payload.get("password",""))
                if len(password)<12:return self.send_json({"error":"Password must be at least 12 characters"},400)
                reset=db.execute("SELECT pr.*,u.username,u.display_name,u.instance_id FROM password_resets pr JOIN users u ON u.id=pr.user_id WHERE pr.token_hash=? AND pr.used_at IS NULL AND pr.expires_at>? AND u.active=1",(hashlib.sha256(raw.encode()).hexdigest(),int(time.time()))).fetchone() if raw else None
                if not reset:return self.send_json({"error":"Reset token is invalid, expired, or already used"},400)
                stamp=now();db.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(password),reset["user_id"]));db.execute("UPDATE password_resets SET used_at=? WHERE id=?",(stamp,reset["id"]));db.execute("DELETE FROM sessions WHERE user_id=?",(reset["user_id"],));append_audit(db,None,"auth.password_reset_completed",reset["username"],reset["display_name"],reset["instance_id"]);db.commit()
                return self.send_json({"data":{"ok":True}})
            if path=="/api/admin/users":
                actor=self.require(db,"admin:users")
                if not actor:return
                username=str(payload.get("username","")).strip(); display=str(payload.get("display_name","")).strip(); role=str(payload.get("role","Member")); password=str(payload.get("password", ""))
                if not username or not display or role not in ROLE_PERMISSIONS or len(password)<12:return self.send_json({"error":"Username, display name, valid role, and password of at least 12 characters are required"},400)
                try: db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,str(payload.get("email",""))[:180],role,str(payload.get("team",""))[:120],password_hash(password),now(),actor["instance_id"]))
                except sqlite3.IntegrityError:return self.send_json({"error":"That username already exists"},409)
                append_audit(db,None,"admin.user_created",f"{username} as {role}",actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}},201)
            if path=="/api/admin/workspace-managers":
                actor=self.require(db,"admin:users")
                if not actor:return
                user_id=int(payload.get("user_id") or 0); workspace_id=int(payload.get("workspace_id") or 0)
                target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
                workspace=db.execute("SELECT name FROM workspaces WHERE id=? AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone()
                if not target or not workspace:return self.send_json({"error":"Invalid user or workspace"},400)
                db.execute("INSERT OR IGNORE INTO workspace_managers(user_id,workspace_id) VALUES(?,?)",(user_id,workspace_id))
                append_audit(db,None,"admin.workspace_manager_granted",f"{target['display_name']} → {workspace['name']}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}},201)
            if path=="/api/admin/folder-creators":
                actor=self.require(db,"admin:users")
                if not actor:return
                user_id=int(payload.get("user_id") or 0); folder_id=int(payload.get("folder_id") or 0)
                target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
                folder=db.execute("SELECT f.name FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?",(folder_id,actor["instance_id"])).fetchone()
                if not target or not folder:return self.send_json({"error":"Invalid user or folder"},400)
                db.execute("INSERT OR IGNORE INTO folder_creator_grants(user_id,folder_id) VALUES(?,?)",(user_id,folder_id))
                append_audit(db,None,"admin.folder_creator_granted",f"{target['display_name']} → {folder['name']}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}},201)
            if path=="/api/admin/stream-editors":
                actor=self.require(db,"admin:users")
                if not actor:return
                user_id=int(payload.get("user_id") or 0); runbook_id=int(payload.get("runbook_id") or 0)
                target=db.execute("SELECT display_name FROM users WHERE id=? AND instance_id=?",(user_id,actor["instance_id"])).fetchone()
                if not target or not owns_runbook(db,runbook_id,actor["instance_id"]):return self.send_json({"error":"Invalid user or runbook"},400)
                db.execute("INSERT OR IGNORE INTO stream_editor_grants(user_id,runbook_id) VALUES(?,?)",(user_id,runbook_id))
                append_audit(db,runbook_id,"admin.stream_editor_granted",f"{target['display_name']}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}},201)
            if path.startswith("/api/admin/sessions/") and path.endswith("/revoke"):
                actor=self.require(db,"admin:users")
                if not actor:return
                try:sid=int(path.strip("/").split("/")[3])
                except (ValueError,IndexError):return self.send_json({"error":"Not found"},404)
                session=db.execute("SELECT s.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND u.instance_id=?",(sid,actor["instance_id"])).fetchone()
                if not session:return self.send_json({"error":"Session not found"},404)
                db.execute("DELETE FROM sessions WHERE id=?",(sid,));append_audit(db,None,"admin.session_revoked",session["username"],actor["display_name"],actor["instance_id"]);db.commit()
                return self.send_json({"data":{"ok":True}})
            if path.startswith("/api/admin/api-tokens/") and path.endswith("/revoke"):
                actor=self.require(db,"admin:users")
                if not actor:return
                try: token_id=int(path.strip("/").split("/")[3])
                except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
                token_row=db.execute("SELECT id,name FROM api_tokens WHERE id=? AND instance_id=? AND revoked_at IS NULL",(token_id,actor["instance_id"])).fetchone()
                if not token_row: return self.send_json({"error":"Not found"},404)
                db.execute("UPDATE api_tokens SET revoked_at=? WHERE id=?",(now(),token_id)); append_audit(db,None,"api_token.revoked",token_row["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
            if path=="/api/admin/api-tokens":
                actor=self.require(db,"admin:users")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>120: return self.send_json({"error":"Token name is required (maximum 120 characters)"},400)
                scopes=[s for s in payload.get("scopes",[]) if s in TOKEN_SCOPE_PERMISSIONS]
                if not scopes: return self.send_json({"error":"Select at least one scope"},400)
                raw=f"fo_{secrets.token_urlsafe(32)}"; digest=hashlib.sha256(raw.encode()).hexdigest()
                cur=db.execute("INSERT INTO api_tokens(instance_id,name,token_hash,scopes_json,created_by,created_at) VALUES(?,?,?,?,?,?)",(actor["instance_id"],name,digest,json.dumps(scopes),actor["id"],now()))
                append_audit(db,None,"api_token.created",f"{name}: {', '.join(scopes)}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name,"token":raw,"scopes":scopes}},201)
            if path=="/api/admin/webhooks":
                actor=self.require(db,"admin:users")
                if not actor:return
                name=str(payload.get("name","")).strip()
                url=str(payload.get("url","")).strip()
                if not name or len(name)>120: return self.send_json({"error":"Webhook name is required (maximum 120 characters)"},400)
                if not (url.startswith("https://") or url.startswith("http://")) or len(url)>500:
                    return self.send_json({"error":"A valid http(s) URL is required"},400)
                events=[e for e in payload.get("events",["*"]) if isinstance(e,str)][:20] or ["*"]
                provider=str(payload.get("provider","generic"))
                if provider not in {"generic","slack","teams"}: return self.send_json({"error":"provider must be generic, slack, or teams"},400)
                secret=secrets.token_urlsafe(32)
                cur=db.execute("INSERT INTO webhooks(instance_id,name,url,secret,provider,events_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",(actor["instance_id"],name,url,secret,provider,json.dumps(events),actor["id"],now()))
                append_audit(db,None,"webhook.created",f"{name} ({provider}): {url}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name,"provider":provider,"secret":secret if provider=="generic" else None}},201)
            if path.startswith("/api/admin/webhooks/") and path.endswith("/test"):
                actor=self.require(db,"admin:users")
                if not actor:return
                try: webhook_id=int(path.strip("/").split("/")[3])
                except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
                webhook=db.execute("SELECT * FROM webhooks WHERE id=? AND instance_id=?",(webhook_id,actor["instance_id"])).fetchone()
                if not webhook: return self.send_json({"error":"Not found"},404)
                status,error,attempts=deliver_webhook_once(dict(webhook),{"id":0,"action":"webhook.test","runbook_id":None,"detail":"Test delivery","actor":actor["display_name"],"created_at":now()})
                db.execute("INSERT INTO webhook_deliveries(webhook_id,audit_id,event_type,success,status_code,error,attempts,attempted_at) VALUES(?,?,?,?,?,?,?,?)",(webhook_id,None,"webhook.test",1 if status and 200<=status<300 else 0,status,error,attempts,now())); db.commit()
                if status and 200<=status<300: return self.send_json({"data":{"ok":True,"status_code":status}})
                return self.send_json({"error":error or f"HTTP {status}"},502)
            if path=="/api/admin/invitations":
                actor=self.require(db,"admin:users")
                if not actor:return
                email=str(payload.get("email","")).strip().lower(); role=str(payload.get("role","Member"))
                if "@" not in email or role not in ROLE_PERMISSIONS:return self.send_json({"error":"A valid email and role are required"},400)
                preview=os.getenv("FLOWOPS_PREVIEW_TOKENS","false").lower()=="true";mail=mail_configuration()
                if not preview and not mail["configured"]:return self.send_json({"error":"Email delivery is not configured. Configure server-side SMTP before inviting users."},503)
                raw=secrets.token_urlsafe(28); db.execute("INSERT INTO invitations(email,role,token_hash,expires_at,created_by,created_at,instance_id) VALUES(?,?,?,?,?,?,?)",(email,role,hashlib.sha256(raw.encode()).hexdigest(),int(time.time())+7*86400,actor["id"],now(),actor["instance_id"])); append_audit(db,None,"admin.user_invited",f"{email} as {role}",actor["display_name"],actor["instance_id"])
                if not preview:
                    try: send_mail(email,"You are invited to FlowOps",f"You have been invited to FlowOps as {role}.\n\nAccept this invitation within seven days:\n{mail['public_url']}/?invite={urllib.parse.quote(raw)}\n\nIf you were not expecting this invitation, ignore this email.")
                    except RuntimeError as exc: db.rollback();return self.send_json({"error":str(exc)},502)
                db.commit();response={"email":email,"role":role,"expires_in_days":7,"delivery":"preview" if preview else "email"}
                if preview:response["invite_token"]=raw
                return self.send_json({"data":response},201)
            if path=="/api/admin/workspaces":
                actor=self.require(db,"admin:settings")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name:return self.send_json({"error":"Workspace name is required"},400)
                try: cur=db.execute("INSERT INTO workspaces(name,description,color,created_at,instance_id) VALUES(?,?,?,?,?)",(name,str(payload.get("description",""))[:500],str(payload.get("color","#7557e8"))[:20],now(),actor["instance_id"]))
                except sqlite3.IntegrityError:return self.send_json({"error":"That workspace already exists"},409)
                append_audit(db,None,"admin.workspace_created",name,actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            if path=="/api/admin/settings":
                actor=self.require(db,"admin:settings")
                if not actor:return
                allowed={"workspace_name","timezone","require_approval","session_hours","serviceops_enabled","directory_enabled","directory_domain","audit_retention_days"}
                for key,value in payload.items():
                    if key in allowed: db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(actor["instance_id"],key,str(value)[:160],now()))
                append_audit(db,None,"admin.settings_updated","Workspace configuration updated",actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}})
            if path=="/api/admin/audit/purge":
                actor=self.require(db,"admin:access")
                if not actor:return
                retention_days=int(instance_settings(db,actor["instance_id"]).get("audit_retention_days","0") or "0")
                if retention_days<=0: return self.send_json({"error":"Set a retention period in Platform settings before purging"},400)
                cutoff=(datetime.now(timezone.utc)-timedelta(days=retention_days)).isoformat(timespec="seconds")
                to_purge=rows(db.execute("SELECT id,event_hash FROM audit WHERE instance_id=? AND created_at<? ORDER BY id ASC",(actor["instance_id"],cutoff)))
                if not to_purge: return self.send_json({"data":{"purged":0}})
                remaining_after=db.execute("SELECT previous_hash FROM audit WHERE instance_id=? AND created_at>=? ORDER BY id ASC LIMIT 1",(actor["instance_id"],cutoff)).fetchone()
                checkpoint=remaining_after["previous_hash"] if remaining_after else "GENESIS"
                purge_ids=[e["id"] for e in to_purge]
                db.execute(f"DELETE FROM audit WHERE id IN ({','.join('?'*len(purge_ids))})",purge_ids)
                db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(actor["instance_id"],"audit_retention_checkpoint",checkpoint,now()))
                append_audit(db,None,"audit.retention_purged",f"Purged {len(purge_ids)} events older than {retention_days} days",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"purged":len(purge_ids)}})
            if path in {"/api/admin/integrations","/api/admin/integrations/test"}:
                actor=self.require(db,"admin:settings")
                if not actor:return
                provider=str(payload.get("provider","")).lower()
                if provider != "serviceops":return self.send_json({"error":"Provider must be serviceops"},400)
                if path.endswith("/test"):
                    return self.test_integration(db,provider,actor,payload)
                allowed={"enabled","url","sync_on_live","sync_on_complete","require_approved","trigger_workflow"}
                if "secret" in payload or "token" in payload:return self.send_json({"error":"Use the one-way credential field; secrets are never returned to the browser"},400)
                submitted=str(payload.get("credential","")).strip();revoke=payload.get("revoke_credential") is True
                if submitted and revoke:return self.send_json({"error":"Set or revoke a credential, not both"},400)
                if submitted:
                    try:encrypted=settings_cipher().encrypt(submitted.encode()).decode()
                    except RuntimeError as exc:return self.send_json({"error":str(exc)},503)
                    db.execute("INSERT INTO integration_credentials(instance_id,provider,secret_encrypted,updated_by,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id,provider) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_by=excluded.updated_by,updated_at=excluded.updated_at",(actor["instance_id"],provider,encrypted,actor["id"],now()))
                elif revoke:db.execute("DELETE FROM integration_credentials WHERE instance_id=? AND provider=?",(actor["instance_id"],provider))
                url=str(payload.get("url","")).strip().rstrip("/")
                if url and not (url.startswith("http://") or url.startswith("https://") or url.startswith("mock://")):return self.send_json({"error":"Connection URL must use http or https"},400)
                for key in allowed:
                    if key in payload:
                        value=url if key=="url" else str(payload[key]).lower() if isinstance(payload[key],bool) else str(payload[key])
                        db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(actor["instance_id"],f"{provider}_{key}",value[:500],now()))
                credential_action="; credential rotated" if submitted else "; stored credential revoked" if revoke else ""
                append_audit(db,None,"integration.configured",f"{provider} connection policy updated{credential_action}",actor["display_name"],actor["instance_id"]);db.commit()
                return self.send_json({"data":{"ok":True,"provider":provider}})
            if path=="/api/folders":
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>120: return self.send_json({"error":"Folder name is required (maximum 120 characters)"},400)
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
                if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                    return self.send_json({"error":"Select an active workspace"},400)
                order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM folders WHERE workspace_id=?",(workspace_id,)).fetchone()[0]
                try: cur=db.execute("INSERT INTO folders(workspace_id,name,sort_order,created_at) VALUES(?,?,?,?)",(workspace_id,name,order,now()))
                except sqlite3.IntegrityError: return self.send_json({"error":"That folder already exists"},409)
                append_audit(db,None,"folder.created",name,actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            if path=="/api/runbook-types":
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>80: return self.send_json({"error":"Runbook type name is required (maximum 80 characters)"},400)
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
                if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                    return self.send_json({"error":"Select an active workspace"},400)
                icon=str(payload.get("icon","◇")).strip()[:4] or "◇"
                color=str(payload.get("color","#7557e8")).strip()[:20] or "#7557e8"
                requires_approval=1 if payload.get("requires_approval") else 0
                try: cur=db.execute("INSERT INTO runbook_types(workspace_id,name,icon,color,default_description,requires_approval,created_at) VALUES(?,?,?,?,?,?,?)",(workspace_id,name,icon,color,str(payload.get("default_description",""))[:2000],requires_approval,now()))
                except sqlite3.IntegrityError: return self.send_json({"error":"That runbook type already exists"},409)
                append_audit(db,None,"runbook_type.created",name,actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            if path=="/api/central-teams":
                actor=self.require(db,"admin:users")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>120: return self.send_json({"error":"Team name is required (maximum 120 characters)"},400)
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
                if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                    return self.send_json({"error":"Select an active workspace"},400)
                try: cur=db.execute("INSERT INTO central_teams(workspace_id,name,created_at) VALUES(?,?,?)",(workspace_id,name,now()))
                except sqlite3.IntegrityError: return self.send_json({"error":"That central team already exists"},409)
                append_audit(db,None,"central_team.created",name,actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            if path=="/api/custom-fields":
                actor=self.require(db,"admin:users")
                if not actor:return
                name=str(payload.get("name","")).strip()
                entity_type=str(payload.get("entity_type",""))
                field_type=str(payload.get("field_type","text"))
                if not name or len(name)>80: return self.send_json({"error":"Field name is required (maximum 80 characters)"},400)
                if entity_type not in {"runbook","task"}: return self.send_json({"error":"entity_type must be 'runbook' or 'task'"},400)
                if field_type not in {"text","number","date","boolean","select"}: return self.send_json({"error":"Invalid field type"},400)
                options=[str(o)[:80] for o in payload.get("options",[]) if isinstance(o,str)][:30] if field_type=="select" else []
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(actor["instance_id"],)).fetchone()[0])
                if not db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,actor["instance_id"])).fetchone():
                    return self.send_json({"error":"Select an active workspace"},400)
                order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM custom_field_definitions WHERE workspace_id=? AND entity_type=?",(workspace_id,entity_type)).fetchone()[0]
                try: cur=db.execute("INSERT INTO custom_field_definitions(workspace_id,entity_type,name,field_type,options_json,required,sort_order,created_at) VALUES(?,?,?,?,?,?,?,?)",(workspace_id,entity_type,name,field_type,json.dumps(options),1 if payload.get("required") else 0,order,now()))
                except sqlite3.IntegrityError: return self.send_json({"error":"That field already exists for this entity type"},409)
                append_audit(db,None,"custom_field.created",f"{entity_type}: {name} ({field_type})",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            parts_central=path.strip("/").split("/")
            if len(parts_central)==4 and parts_central[:2]==["api","central-teams"] and parts_central[3]=="members":
                actor=self.require(db,"admin:users")
                if not actor:return
                try: central_team_id=int(parts_central[2])
                except ValueError: return self.send_json({"error":"Not found"},404)
                team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                if not team: return self.send_json({"error":"Not found"},404)
                user_id=int(payload.get("user_id",0))
                if not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(user_id,actor["instance_id"])).fetchone():
                    return self.send_json({"error":"User is invalid"},400)
                db.execute("INSERT OR IGNORE INTO central_team_members(team_id,user_id) VALUES(?,?)",(central_team_id,user_id))
                append_audit(db,None,"central_team.member_added",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}},201)
            if path=="/api/runbooks":
                precheck=self.current_user(db)
                if not precheck: return self.send_json({"error":"Authentication required"},401)
                name=str(payload.get("name","")).strip()
                if not name or len(name)>160: return self.send_json({"error":"Name is required (maximum 160 characters)"},400)
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 AND instance_id=? ORDER BY id LIMIT 1",(precheck["instance_id"],)).fetchone()[0]); workspace=db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1 AND instance_id=?",(workspace_id,precheck["instance_id"])).fetchone()
                if not workspace:return self.send_json({"error":"Select an active workspace"},400)
                folder_id=int(payload["folder_id"]) if payload.get("folder_id") else None
                if folder_id and not db.execute("SELECT 1 FROM folders WHERE id=? AND workspace_id=?",(folder_id,workspace_id)).fetchone():
                    return self.send_json({"error":"Invalid folder"},400)
                actor=self.require_scoped_edit(db,workspace_id=workspace_id,folder_id=folder_id)
                if not actor:return
                runbook_type_id=int(payload["runbook_type_id"]) if payload.get("runbook_type_id") else None
                runbook_type=db.execute("SELECT * FROM runbook_types WHERE id=? AND workspace_id=?",(runbook_type_id,workspace_id)).fetchone() if runbook_type_id else None
                if runbook_type_id and not runbook_type:
                    return self.send_json({"error":"Invalid runbook type"},400)
                description=str(payload.get("description","")).strip() or (runbook_type["default_description"] if runbook_type else "")
                stamp=now(); ticket=str(payload.get("serviceops_ticket","")).strip()[:40]
                cur=db.execute("INSERT INTO runbooks(name,description,owner,scheduled_at,serviceops_ticket,workspace_id,folder_id,runbook_type_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(name,description[:2000],str(payload.get("owner",""))[:120],payload.get("scheduled_at") or None,ticket,workspace_id,folder_id,runbook_type_id,stamp,stamp))
                rid=cur.lastrowid
                append_audit(db,rid,"runbook.created",name,actor["display_name"]); db.commit()
                if ticket:
                    try: self.apply_serviceops_sync(db,rid,ticket); db.commit()
                    except RuntimeError as exc: append_audit(db,rid,"serviceops.sync_failed",str(exc)); db.commit()
                doc=runbook_document(db,rid)
                return self.send_json({"data":doc},201)
            parts=path.strip("/").split("/")
            if len(parts)==4 and parts[:2]==["api","templates"] and parts[3]=="use":
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                try: template_id=int(parts[2])
                except ValueError: return self.send_json({"error":"Not found"},404)
                template=db.execute("SELECT t.* FROM templates t JOIN workspaces w ON w.id=t.workspace_id WHERE t.id=? AND w.instance_id=?",(template_id,actor["instance_id"])).fetchone()
                if not template: return self.send_json({"error":"Not found"},404)
                name=str(payload.get("name","")).strip() or template["name"]
                workspace_id=template["workspace_id"]
                stamp=now()
                cur=db.execute("INSERT INTO runbooks(name,description,owner,scheduled_at,workspace_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(name[:160],template["description"],str(payload.get("owner",""))[:120],payload.get("scheduled_at") or None,workspace_id,stamp,stamp))
                new_rid=cur.lastrowid
                for s in db.execute("SELECT DISTINCT stream FROM template_tasks WHERE template_id=? ORDER BY sort_order",(template_id,)):
                    order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(new_rid,)).fetchone()[0]
                    db.execute("INSERT OR IGNORE INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(new_rid,s["stream"],order,stamp))
                id_map={}
                for t in db.execute("SELECT * FROM template_tasks WHERE template_id=? ORDER BY sort_order",(template_id,)):
                    new_tid=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?,?)",(new_rid,t["title"],t["description"],t["stream"],"",t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"])).lastrowid
                    id_map[t["id"]]=new_tid
                for dep in db.execute("SELECT template_task_id,depends_on_template_task_id FROM template_dependencies td JOIN template_tasks tt ON tt.id=td.template_task_id WHERE tt.template_id=?",(template_id,)):
                    if dep["template_task_id"] in id_map and dep["depends_on_template_task_id"] in id_map:
                        db.execute("INSERT INTO dependencies VALUES(?,?)",(id_map[dep["template_task_id"]],id_map[dep["depends_on_template_task_id"]]))
                append_audit(db,new_rid,"runbook.created",f"Created from template: {template['name']}",actor["display_name"]); doc=runbook_document(db,new_rid,actor); db.commit()
                return self.send_json({"data":doc},201)
            if len(parts)>=3 and parts[:2]==["api","runbooks"]:
                try: rid=int(parts[2])
                except ValueError: return self.send_json({"error":"Not found"},404)
                actor=self.current_user(db)
                if not actor or not owns_runbook(db,rid,actor["instance_id"]): return self.send_json({"error":"Not found"},404)
                if len(parts)==4 and parts[3]=="tasks":
                    actor=self.require_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    title=str(payload.get("title","")).strip()
                    if not title: return self.send_json({"error":"Task title is required"},400)
                    order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM tasks WHERE runbook_id=?",(rid,)).fetchone()[0]
                    task_type=str(payload.get("task_type","normal")); allowed_types={"normal","milestone","checklist","validation","sms","email","call"}
                    if task_type not in allowed_types:return self.send_json({"error":"Invalid task type"},400)
                    duration=max(0,min(int(payload.get("duration",15)),10080)); duration=0 if task_type in {"milestone","checklist","sms","email","call"} else max(1,duration)
                    owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None; owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                    if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(owner_user_id,actor["instance_id"])).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                    if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,rid)).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                    stream=str(payload.get("stream","General")).strip()[:80] or "General"
                    if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(rid,stream)).fetchone():
                        stream_order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                        db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,stream,stream_order,now()))
                    cur=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset,owner_user_id,owner_team_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(rid,title,str(payload.get("description",""))[:2000],stream,"",duration,order,str(payload.get("automation_url",""))[:500] or None,task_type,max(0,int(payload.get("scheduled_offset",0))),owner_user_id,owner_team_id))
                    for dep in payload.get("depends_on",[]):
                        if db.execute("SELECT 1 FROM tasks WHERE id=? AND runbook_id=?",(dep,rid)).fetchone(): db.execute("INSERT OR IGNORE INTO dependencies VALUES(?,?)",(cur.lastrowid,dep))
                    append_audit(db,rid,"task.created",title,actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc},201)
                if len(parts)==4 and parts[3]=="tasks-import":
                    actor=self.require_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    csv_text=str(payload.get("csv",""))
                    try: parsed=parse_tasks_csv(csv_text)
                    except ValueError as exc: return self.send_json({"error":str(exc)},400)
                    if not parsed: return self.send_json({"error":"No task rows found in CSV"},400)
                    order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM tasks WHERE runbook_id=?",(rid,)).fetchone()[0]
                    created=0
                    for row in parsed:
                        stream=row["stream"] or "General"
                        if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(rid,stream)).fetchone():
                            stream_order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                            db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,stream,stream_order,now()))
                        db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?,?)",(rid,row["title"],row["description"],stream,"",row["duration"],order,row["automation_url"] or None,row["task_type"],row["scheduled_offset"]))
                        order+=1; created+=1
                    append_audit(db,rid,"task.csv_imported",f"{created} tasks",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc,"imported":created},201)
                if len(parts)==4 and parts[3]=="tasks-bulk-edit":
                    actor=self.require_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    task_ids=[int(t) for t in payload.get("task_ids",[]) if str(t).lstrip("-").isdigit()]
                    valid_ids=[row[0] for row in db.execute(f"SELECT id FROM tasks WHERE runbook_id=? AND id IN ({','.join('?'*len(task_ids)) or 'NULL'})",[rid]+task_ids)] if task_ids else []
                    if not valid_ids: return self.send_json({"error":"No matching tasks selected"},400)
                    sets=[]; values=[]; changes=[]
                    if "owner_user_id" in payload:
                        owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None
                        if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(owner_user_id,actor["instance_id"])).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                        sets.append("owner_user_id=?"); values.append(owner_user_id); sets.append("owner_team_id=NULL"); changes.append("owner")
                    elif "owner_team_id" in payload:
                        owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                        if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,rid)).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                        sets.append("owner_team_id=?"); values.append(owner_team_id); sets.append("owner_user_id=NULL"); changes.append("owner")
                    if "duration" in payload:
                        sets.append("duration=?"); values.append(max(0,min(int(payload["duration"]),10080))); changes.append("duration")
                    if "scheduled_offset" in payload:
                        sets.append("scheduled_offset=?"); values.append(max(0,int(payload["scheduled_offset"]))); changes.append("scheduled_offset")
                    if not sets: return self.send_json({"error":"No fields to update"},400)
                    db.execute(f"UPDATE tasks SET {','.join(sets)} WHERE runbook_id=? AND id IN ({','.join('?'*len(valid_ids))})",values+[rid]+valid_ids)
                    append_audit(db,rid,"task.bulk_edited",f"{len(valid_ids)} tasks: {', '.join(changes)}",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc,"updated":len(valid_ids)})
                if len(parts)==4 and parts[3]=="streams":
                    actor=self.require_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    name=str(payload.get("name","")).strip()
                    if not name or len(name)>80:return self.send_json({"error":"Stream name is required (maximum 80 characters)"},400)
                    order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                    try: cur=db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,name,order,now()))
                    except sqlite3.IntegrityError:return self.send_json({"error":"That stream already exists"},409)
                    append_audit(db,rid,"stream.created",name,actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc},201)
                if len(parts)==4 and parts[3]=="teams":
                    actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    name=str(payload.get("name","")).strip()
                    central_team_id=int(payload["central_team_id"]) if payload.get("central_team_id") else None
                    central_team=None
                    if central_team_id:
                        central_team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                        if not central_team: return self.send_json({"error":"Invalid central team"},400)
                        name=central_team["name"]
                    if not name:return self.send_json({"error":"Team name is required"},400)
                    try: cur=db.execute("INSERT INTO runbook_teams(runbook_id,name,central_team_id,created_at) VALUES(?,?,?,?)",(rid,name[:120],central_team_id,now()))
                    except sqlite3.IntegrityError:return self.send_json({"error":"That runbook team already exists"},409)
                    if not central_team_id:
                        for uid in payload.get("user_ids",[]):
                            if db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(uid,actor["instance_id"])).fetchone():db.execute("INSERT OR IGNORE INTO team_members(team_id,user_id) VALUES(?,?)",(cur.lastrowid,uid))
                    append_audit(db,rid,"team.created" if not central_team_id else "team.linked",name,actor["display_name"]);db.commit();return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
                if len(parts)==4 and parts[3]=="comments":
                    actor=self.require(db,"runbooks:view")
                    if not actor:return
                    body=str(payload.get("body","")).strip()
                    if not body: return self.send_json({"error":"Comment is required"},400)
                    db.execute("INSERT INTO comments(runbook_id,author,body,created_at) VALUES(?,?,?,?)",(rid,actor["display_name"],body[:2000],now())); append_audit(db,rid,"comment.added",body[:120],actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc},201)
                if len(parts)==4 and parts[3]=="transition":
                    actor=self.require(db,"runbooks:execute")
                    if not actor:return
                    target=str(payload.get("status","")); allowed={"draft","ready","live","paused","complete","cancelled"}
                    if target not in allowed: return self.send_json({"error":"Invalid runbook status"},400)
                    runbook_row=db.execute("SELECT status,runbook_type_id,approved_at FROM runbooks WHERE id=?",(rid,)).fetchone()
                    current=runbook_row["status"]
                    valid={"draft":{"ready","cancelled"},"ready":{"live","draft","cancelled"},"live":{"paused","complete","cancelled"},"paused":{"live","cancelled"},"complete":set(),"cancelled":set()}
                    if target not in valid[current]: return self.send_json({"error":f"Cannot transition {current} to {target}"},409)
                    if target=="live" and runbook_row["runbook_type_id"]:
                        rtype=db.execute("SELECT requires_approval,name FROM runbook_types WHERE id=?",(runbook_row["runbook_type_id"],)).fetchone()
                        if rtype and rtype["requires_approval"] and not runbook_row["approved_at"]:
                            return self.send_json({"error":f"{rtype['name']} runbooks require approval before going live"},409)
                    try:
                        serviceops_result=self.serviceops_lifecycle(db,rid,target)
                    except PermissionError as exc:
                        return self.send_json({"error":str(exc)},409)
                    except RuntimeError as exc:
                        return self.send_json({"error":str(exc)},502)
                    stamp=now()
                    if target=="live":
                        db.execute("UPDATE runbooks SET status=?,mode='live',actual_started_at=COALESCE(actual_started_at,?),updated_at=? WHERE id=?",(target,stamp,stamp,rid))
                    elif target=="complete":
                        db.execute("UPDATE runbooks SET status=?,mode='plan',actual_completed_at=?,updated_at=? WHERE id=?",(target,stamp,stamp,rid))
                    else:
                        db.execute("UPDATE runbooks SET status=?,mode=?,updated_at=? WHERE id=?",(target,"live" if target=="paused" else "plan",stamp,rid))
                    append_audit(db,rid,"runbook.transition",f"{current} → {target}",actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc,"serviceops":serviceops_result})
                if len(parts)==4 and parts[3]=="approve":
                    actor=self.require(db,"admin:access")
                    if not actor:return
                    runbook=db.execute("SELECT status,runbook_type_id,approved_at FROM runbooks WHERE id=?",(rid,)).fetchone()
                    if runbook["approved_at"]: return self.send_json({"error":"This runbook is already approved"},409)
                    stamp=now()
                    db.execute("UPDATE runbooks SET approved_at=?,approved_by=? WHERE id=?",(stamp,actor["display_name"],rid))
                    append_audit(db,rid,"runbook.approved",f"Approved by {actor['display_name']}",actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc})
                if len(parts)==4 and parts[3]=="serviceops-sync":
                    if not self.require(db,"integrations:sync"):return
                    return self.sync_serviceops(db,rid,payload)
                if len(parts)==4 and parts[3]=="duplicate":
                    actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    source=db.execute("SELECT * FROM runbooks WHERE id=?",(rid,)).fetchone()
                    stamp=now(); name=f"{source['name']} (copy)"[:160]
                    cur=db.execute("INSERT INTO runbooks(name,description,owner,workspace_id,created_at,updated_at) VALUES(?,?,?,?,?,?)",(name,source["description"],source["owner"],source["workspace_id"],stamp,stamp))
                    new_rid=cur.lastrowid
                    for s in db.execute("SELECT name,sort_order FROM streams WHERE runbook_id=? ORDER BY sort_order",(rid,)):
                        db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(new_rid,s["name"],s["sort_order"],stamp))
                    id_map={}
                    for t in db.execute("SELECT * FROM tasks WHERE runbook_id=? ORDER BY sort_order",(rid,)):
                        new_tid=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset,owner_user_id,owner_team_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(new_rid,t["title"],t["description"],t["stream"],t["owner"],t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"],t["owner_user_id"],t["owner_team_id"])).lastrowid
                        id_map[t["id"]]=new_tid
                    for dep in db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?",(rid,)):
                        if dep["task_id"] in id_map and dep["depends_on_id"] in id_map:
                            db.execute("INSERT INTO dependencies VALUES(?,?)",(id_map[dep["task_id"]],id_map[dep["depends_on_id"]]))
                    append_audit(db,new_rid,"runbook.duplicated",f"Duplicated from {source['name']}",actor["display_name"]); doc=runbook_document(db,new_rid,actor); db.commit()
                    return self.send_json({"data":doc},201)
                if len(parts)==4 and parts[3]=="save-as-template":
                    actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    name=str(payload.get("name","")).strip()
                    if not name or len(name)>160: return self.send_json({"error":"Template name is required (maximum 160 characters)"},400)
                    source=db.execute("SELECT * FROM runbooks WHERE id=?",(rid,)).fetchone()
                    stamp=now(); category=str(payload.get("category","General")).strip()[:60] or "General"
                    cur=db.execute("INSERT INTO templates(workspace_id,name,description,category,created_by,created_at) VALUES(?,?,?,?,?,?)",(source["workspace_id"],name,str(payload.get("description",source["description"]))[:2000],category,actor["display_name"],stamp))
                    template_id=cur.lastrowid
                    id_map={}
                    for t in db.execute("SELECT * FROM tasks WHERE runbook_id=? ORDER BY sort_order",(rid,)):
                        new_tid=db.execute("INSERT INTO template_tasks(template_id,title,description,stream,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?)",(template_id,t["title"],t["description"],t["stream"],t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"])).lastrowid
                        id_map[t["id"]]=new_tid
                    for dep in db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?",(rid,)):
                        if dep["task_id"] in id_map and dep["depends_on_id"] in id_map:
                            db.execute("INSERT INTO template_dependencies VALUES(?,?)",(id_map[dep["task_id"]],id_map[dep["depends_on_id"]]))
                    append_audit(db,rid,"template.saved",name,actor["display_name"]); db.commit()
                    return self.send_json({"data":{"id":template_id,"name":name}},201)
                if len(parts)==4 and parts[3]=="archive":
                    actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                    if not actor:return
                    status=db.execute("SELECT status,archived FROM runbooks WHERE id=?",(rid,)).fetchone()
                    if status["status"]!="complete": return self.send_json({"error":"Only a complete runbook can be archived"},409)
                    if status["archived"]: return self.send_json({"data":runbook_document(db,rid,actor)})
                    db.execute("UPDATE runbooks SET archived=1,updated_at=? WHERE id=?",(now(),rid))
                    append_audit(db,rid,"runbook.archived","Archived",actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc})
        self.send_json({"error":"Not found"},404)

    def do_PATCH(self):
        path=urllib.parse.urlparse(self.path).path; parts=path.strip("/").split("/")
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.send_json({"error":str(exc)},400)
        if parts==["api","me","dashboard"]:
            with connect() as db:
                actor=self.current_user(db)
                if not actor: return self.send_json({"error":"Authentication required"},401)
                widgets=payload.get("widgets")
                if not isinstance(widgets,list) or not all(isinstance(w,str) for w in widgets):
                    return self.send_json({"error":"widgets must be a list of strings"},400)
                allowed={"runbook_activity","today_readiness","delay_summary"}
                widgets=[w for w in widgets if w in allowed]
                db.execute("UPDATE users SET dashboard_widgets=? WHERE id=?",(json.dumps(widgets),actor["id"]))
                db.commit()
                return self.send_json({"data":{"widgets":widgets}})
        if len(parts)==4 and parts[:3]==["api","admin","users"]:
            try: uid=int(parts[3])
            except ValueError:return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                user=db.execute("SELECT * FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
                if not user:return self.send_json({"error":"User not found"},404)
                role=str(payload.get("role",user["role"])); active=1 if payload.get("active",bool(user["active"])) else 0
                if role not in ROLE_PERMISSIONS:return self.send_json({"error":"Invalid role"},400)
                if uid==actor["id"] and (role!="Admin" or not active):return self.send_json({"error":"You cannot remove your own administrator access"},409)
                password=payload.get("password")
                if password is not None and len(str(password))<12:return self.send_json({"error":"Password must be at least 12 characters"},400)
                db.execute("UPDATE users SET display_name=?,email=?,role=?,team=?,active=? WHERE id=?",(str(payload.get("display_name",user["display_name"]))[:120],str(payload.get("email",user["email"]))[:180],role,str(payload.get("team",user["team"]))[:120],active,uid))
                if password is not None: db.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(str(password)),uid)); db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
                append_audit(db,None,"admin.user_updated",f"{user['username']}: role={role}, active={bool(active)}",actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","runbooks"]:
            try: rid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                runbook=db.execute("SELECT r.* FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=? AND w.instance_id=?",(rid,actor["instance_id"])).fetchone()
                if not runbook: return self.send_json({"error":"Not found"},404)
                if runbook["status"] in {"complete","cancelled"}: return self.send_json({"error":f"Cannot edit a {runbook['status']} runbook"},409)
                editable={"name":160,"description":2000,"owner":120,"serviceops_ticket":40}
                changes=[]; sets=[]; values=[]
                for field,limit in editable.items():
                    if field not in payload: continue
                    value=str(payload[field]).strip()[:limit]
                    if field=="name" and not value: return self.send_json({"error":"Name is required"},400)
                    if value==runbook[field]: continue
                    changes.append(f"{field}: {runbook[field]!r} → {value!r}"); sets.append(f"{field}=?"); values.append(value)
                if "scheduled_at" in payload:
                    value=payload["scheduled_at"] or None
                    if value!=runbook["scheduled_at"]: changes.append("scheduled_at changed"); sets.append("scheduled_at=?"); values.append(value)
                if "parent_runbook_id" in payload:
                    parent_id=int(payload["parent_runbook_id"]) if payload.get("parent_runbook_id") else None
                    if parent_id==rid: return self.send_json({"error":"A runbook cannot be its own parent"},400)
                    if parent_id:
                        parent=db.execute("SELECT id,parent_runbook_id FROM runbooks WHERE id=? AND workspace_id=?",(parent_id,runbook["workspace_id"])).fetchone()
                        if not parent: return self.send_json({"error":"Invalid parent runbook"},400)
                        if parent["parent_runbook_id"]==rid: return self.send_json({"error":"That runbook is already a child of this one"},400)
                    if parent_id!=runbook["parent_runbook_id"]: changes.append("parent_runbook_id changed"); sets.append("parent_runbook_id=?"); values.append(parent_id)
                field_changes=apply_custom_field_values(db,runbook["workspace_id"],"runbook",rid,payload.get("custom_fields",{})) if isinstance(payload.get("custom_fields"),dict) else []
                if not changes and not field_changes: return self.send_json({"data":runbook_document(db,rid,actor)})
                ticket_linked="serviceops_ticket" in payload and str(payload["serviceops_ticket"]).strip()[:40]!=runbook["serviceops_ticket"] and str(payload["serviceops_ticket"]).strip()
                if changes:
                    sets.append("updated_at=?"); values.append(now()); values.append(rid)
                    db.execute(f"UPDATE runbooks SET {','.join(sets)} WHERE id=?",values)
                append_audit(db,rid,"runbook.edited","; ".join(changes+field_changes),actor["display_name"]); db.commit()
                if ticket_linked:
                    try: self.apply_serviceops_sync(db,rid,ticket_linked); db.commit()
                    except RuntimeError as exc: append_audit(db,rid,"serviceops.sync_failed",str(exc)); db.commit()
                doc=runbook_document(db,rid,actor)
                return self.send_json({"data":doc})
        if len(parts)==3 and parts[:2]==["api","streams"]:
            try: sid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                precheck=self.current_user(db)
                if not precheck: return self.send_json({"error":"Authentication required"},401)
                stream=db.execute("SELECT s.* FROM streams s JOIN runbooks r ON r.id=s.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE s.id=? AND w.instance_id=?",(sid,precheck["instance_id"])).fetchone()
                if not stream: return self.send_json({"error":"Not found"},404)
                actor=self.require_scoped_edit(db,runbook_id=stream["runbook_id"])
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>80:return self.send_json({"error":"Stream name is required (maximum 80 characters)"},400)
                if name!=stream["name"] and db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(stream["runbook_id"],name)).fetchone():
                    return self.send_json({"error":"That stream already exists"},409)
                db.execute("UPDATE tasks SET stream=? WHERE runbook_id=? AND stream=?",(name,stream["runbook_id"],stream["name"]))
                db.execute("UPDATE streams SET name=? WHERE id=?",(name,sid))
                append_audit(db,stream["runbook_id"],"stream.renamed",f"{stream['name']} → {name}",actor["display_name"]); doc=runbook_document(db,stream["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
        if len(parts)!=3 or parts[:2] != ["api","tasks"]: return self.send_json({"error":"Not found"},404)
        try: tid=int(parts[2])
        except ValueError: return self.send_json({"error":"Not found"},404)
        if "status" not in payload:
            with connect() as db:
                precheck=self.current_user(db)
                if not precheck: return self.send_json({"error":"Authentication required"},401)
                task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,precheck["instance_id"])).fetchone()
                if not task: return self.send_json({"error":"Not found"},404)
                actor=self.require_scoped_edit(db,runbook_id=task["runbook_id"])
                if not actor:return
                editable={"title":str,"description":str,"stream":str,"duration":int,"automation_url":str}
                changes=[]; sets=[]; values=[]
                for field,caster in editable.items():
                    if field not in payload: continue
                    if field=="title" and not str(payload["title"]).strip(): return self.send_json({"error":"Task title is required"},400)
                    value=caster(payload[field]) if caster is not str else str(payload[field]).strip()
                    if field in {"title","description","automation_url"}: value=value[:2000 if field=="description" else 500 if field=="automation_url" else 160]
                    if field=="stream": value=value[:80] or "General"
                    if field=="duration": value=max(0,min(int(value),10080))
                    if value==task[field]: continue
                    changes.append(f"{field}: {task[field]!r} → {value!r}"); sets.append(f"{field}=?"); values.append(value)
                if "owner_user_id" in payload:
                    owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None
                    if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(owner_user_id,actor["instance_id"])).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                    if owner_user_id!=task["owner_user_id"]: changes.append("owner_user_id changed"); sets.append("owner_user_id=?"); values.append(owner_user_id)
                if "owner_team_id" in payload:
                    owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                    if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,task["runbook_id"])).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                    if owner_team_id!=task["owner_team_id"]: changes.append("owner_team_id changed"); sets.append("owner_team_id=?"); values.append(owner_team_id)
                if "stream" in payload and payload["stream"]:
                    stream_name=str(payload["stream"]).strip()[:80]
                    if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(task["runbook_id"],stream_name)).fetchone():
                        order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(task["runbook_id"],)).fetchone()[0]
                        db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(task["runbook_id"],stream_name,order,now()))
                field_changes=[]
                if isinstance(payload.get("custom_fields"),dict):
                    workspace_id=db.execute("SELECT workspace_id FROM runbooks WHERE id=?",(task["runbook_id"],)).fetchone()[0]
                    field_changes=apply_custom_field_values(db,workspace_id,"task",tid,payload["custom_fields"])
                if not changes and not field_changes: doc=runbook_document(db,task["runbook_id"],actor); return self.send_json({"data":doc})
                if changes:
                    values.append(tid)
                    db.execute(f"UPDATE tasks SET {','.join(sets)} WHERE id=?",values)
                append_audit(db,task["runbook_id"],"task.edited",f"{task['title']}: "+"; ".join(changes+field_changes),actor["display_name"])
                db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),task["runbook_id"])); doc=runbook_document(db,task["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
        with connect() as db:
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,actor["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            runbook=db.execute("SELECT status FROM runbooks WHERE id=?",(task["runbook_id"],)).fetchone()
            if not runbook or runbook["status"]!="live":return self.send_json({"error":"Tasks can only be executed while the runbook is live"},409)
            if actor["role"]=="Member":
                assigned=task["owner_user_id"]==actor["id"] or (task["owner_team_id"] and actor["id"] in team_member_user_ids(db, task["owner_team_id"]))
                if not assigned:return self.send_json({"error":"Members may only act on tasks assigned to them or their team"},403)
            target=str(payload.get("status","")); valid={"pending":{"running","skipped","blocked"},"running":{"complete","failed","blocked","pending"},"blocked":{"running","pending","skipped"},"failed":{"running","skipped"},"complete":set(),"skipped":set()}
            if task["task_type"] in {"milestone","checklist","sms","email"}:valid["pending"].add("complete")
            if target not in valid.get(task["status"],set()): return self.send_json({"error":f"Cannot transition {task['status']} to {target}"},409)
            if target in {"running","complete"}:
                blockers=db.execute("SELECT COUNT(*) FROM dependencies d JOIN tasks p ON p.id=d.depends_on_id WHERE d.task_id=? AND p.status NOT IN ('complete','skipped')",(tid,)).fetchone()[0]
                if blockers: return self.send_json({"error":"Complete predecessor tasks first"},409)
            validation_result=str(payload.get("validation_result","")).strip()
            if task["task_type"]=="validation" and target=="complete" and validation_result not in {"Pass","Fail","Not Tested"}:return self.send_json({"error":"Validation completion requires Pass, Fail, or Not Tested"},400)
            db.execute("UPDATE tasks SET status=?,started_at=CASE WHEN ? IN ('running','complete') THEN COALESCE(started_at,?) ELSE started_at END,completed_at=CASE WHEN ? IN ('complete','skipped') THEN ? ELSE NULL END,validation_result=CASE WHEN ?!='' THEN ? ELSE validation_result END,validation_comment=CASE WHEN ?!='' THEN ? ELSE validation_comment END,blocked_reason=CASE WHEN ?='blocked' THEN ? ELSE blocked_reason END WHERE id=?",(target,target,now(),target,now(),validation_result,validation_result,str(payload.get("validation_comment","")).strip(),str(payload.get("validation_comment","")).strip(),target,str(payload.get("blocked_reason","")).strip()[:500],tid))
            append_audit(db,task["runbook_id"],"task.transition",f"{task['title']}: {task['status']} → {target}",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),task["runbook_id"]))
            if task["serviceops_ctask"]:
                self.push_serviceops_ctask_state(db,task["runbook_id"],task["serviceops_ctask"],target)
            doc=runbook_document(db,task["runbook_id"],actor); db.commit()
            return self.send_json({"data":doc})

    def do_DELETE(self):
        path=urllib.parse.urlparse(self.path).path; parts=path.strip("/").split("/")
        if len(parts)==5 and parts[:3]==["api","admin","workspace-managers"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,workspace_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM workspace_managers WHERE user_id=? AND workspace_id=? AND EXISTS(SELECT 1 FROM workspaces w WHERE w.id=? AND w.instance_id=?)",(user_id,workspace_id,workspace_id,actor["instance_id"]))
                append_audit(db,None,"admin.workspace_manager_revoked",f"user {user_id} × workspace {workspace_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:3]==["api","admin","folder-creators"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,folder_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM folder_creator_grants WHERE user_id=? AND folder_id=? AND EXISTS(SELECT 1 FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?)",(user_id,folder_id,folder_id,actor["instance_id"]))
                append_audit(db,None,"admin.folder_creator_revoked",f"user {user_id} × folder {folder_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:3]==["api","admin","stream-editors"]:
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                try: user_id,runbook_id=int(parts[3]),int(parts[4])
                except ValueError: return self.send_json({"error":"Not found"},404)
                if not owns_runbook(db,runbook_id,actor["instance_id"]):return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM stream_editor_grants WHERE user_id=? AND runbook_id=?",(user_id,runbook_id))
                append_audit(db,runbook_id,"admin.stream_editor_revoked",f"user {user_id}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","streams"]:
            try: sid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                precheck=self.current_user(db)
                if not precheck: return self.send_json({"error":"Authentication required"},401)
                stream=db.execute("SELECT s.* FROM streams s JOIN runbooks r ON r.id=s.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE s.id=? AND w.instance_id=?",(sid,precheck["instance_id"])).fetchone()
                if not stream: return self.send_json({"error":"Not found"},404)
                actor=self.require_scoped_edit(db,runbook_id=stream["runbook_id"])
                if not actor:return
                in_use=db.execute("SELECT COUNT(*) FROM tasks WHERE runbook_id=? AND stream=?",(stream["runbook_id"],stream["name"])).fetchone()[0]
                if in_use: return self.send_json({"error":"Move or remove this stream's tasks before deleting it"},409)
                db.execute("DELETE FROM streams WHERE id=?",(sid,)); append_audit(db,stream["runbook_id"],"stream.deleted",stream["name"],actor["display_name"]); doc=runbook_document(db,stream["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
        if len(parts)==4 and parts[:3]==["api","admin","webhooks"]:
            try: webhook_id=int(parts[3])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                webhook=db.execute("SELECT * FROM webhooks WHERE id=? AND instance_id=?",(webhook_id,actor["instance_id"])).fetchone()
                if not webhook: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM webhooks WHERE id=?",(webhook_id,)); append_audit(db,None,"webhook.deleted",webhook["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","templates"]:
            try: template_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                template=db.execute("SELECT t.* FROM templates t JOIN workspaces w ON w.id=t.workspace_id WHERE t.id=? AND w.instance_id=?",(template_id,actor["instance_id"])).fetchone()
                if not template: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM templates WHERE id=?",(template_id,)); append_audit(db,None,"template.deleted",template["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","folders"]:
            try: folder_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                folder=db.execute("SELECT f.* FROM folders f JOIN workspaces w ON w.id=f.workspace_id WHERE f.id=? AND w.instance_id=?",(folder_id,actor["instance_id"])).fetchone()
                if not folder: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbooks WHERE folder_id=?",(folder_id,)).fetchone()[0]:
                    return self.send_json({"error":"Move or remove this folder's runbooks before deleting it"},409)
                db.execute("DELETE FROM folders WHERE id=?",(folder_id,)); append_audit(db,None,"folder.deleted",folder["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","runbook-types"]:
            try: type_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                rtype=db.execute("SELECT rt.* FROM runbook_types rt JOIN workspaces w ON w.id=rt.workspace_id WHERE rt.id=? AND w.instance_id=?",(type_id,actor["instance_id"])).fetchone()
                if not rtype: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbooks WHERE runbook_type_id=?",(type_id,)).fetchone()[0]:
                    return self.send_json({"error":"Reassign this type's runbooks before deleting it"},409)
                db.execute("DELETE FROM runbook_types WHERE id=?",(type_id,)); append_audit(db,None,"runbook_type.deleted",rtype["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","custom-fields"]:
            try: definition_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                definition=db.execute("SELECT cfd.* FROM custom_field_definitions cfd JOIN workspaces w ON w.id=cfd.workspace_id WHERE cfd.id=? AND w.instance_id=?",(definition_id,actor["instance_id"])).fetchone()
                if not definition: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM custom_field_definitions WHERE id=?",(definition_id,)); append_audit(db,None,"custom_field.deleted",f"{definition['entity_type']}: {definition['name']}",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==5 and parts[:2]==["api","central-teams"] and parts[3]=="members":
            try: central_team_id=int(parts[2]); user_id=int(parts[4])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                if not team: return self.send_json({"error":"Not found"},404)
                db.execute("DELETE FROM central_team_members WHERE team_id=? AND user_id=?",(central_team_id,user_id))
                append_audit(db,None,"central_team.member_removed",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)==3 and parts[:2]==["api","central-teams"]:
            try: central_team_id=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                team=db.execute("SELECT ct.* FROM central_teams ct JOIN workspaces w ON w.id=ct.workspace_id WHERE ct.id=? AND w.instance_id=?",(central_team_id,actor["instance_id"])).fetchone()
                if not team: return self.send_json({"error":"Not found"},404)
                if db.execute("SELECT COUNT(*) FROM runbook_teams WHERE central_team_id=?",(central_team_id,)).fetchone()[0]:
                    return self.send_json({"error":"Unlink this team from every runbook before deleting it"},409)
                db.execute("DELETE FROM central_teams WHERE id=?",(central_team_id,)); append_audit(db,None,"central_team.deleted",team["name"],actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"ok":True}})
        if len(parts)!=4 or parts[:3]!=["api","admin","users"]:return self.send_json({"error":"Not found"},404)
        try:uid=int(parts[3])
        except ValueError:return self.send_json({"error":"Not found"},404)
        with connect() as db:
            actor=self.require(db,"admin:users")
            if not actor:return
            if uid==actor["id"]:return self.send_json({"error":"You cannot delete your own account"},409)
            user=db.execute("SELECT username FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
            if not user:return self.send_json({"error":"User not found"},404)
            db.execute("DELETE FROM users WHERE id=?",(uid,)); append_audit(db,None,"admin.user_deleted",user["username"],actor["display_name"],actor["instance_id"]); db.commit(); return self.send_json({"data":{"ok":True}})

    def serviceops_api_base(self, db, instance_id):
        row=db.execute("SELECT value FROM instance_settings WHERE instance_id=? AND key='serviceops_url'",(instance_id,)).fetchone()
        base=(row[0] if row else os.getenv("SERVICEOPS_URL","")).rstrip("/")
        return base if base.endswith("/api/v1") else f"{base}/api/v1"

    def serviceops_request(self, db, instance_id, method, resource, body=None, idempotency_key=None):
        base=self.serviceops_api_base(db,instance_id);token,_=integration_credential(db,instance_id,"serviceops")
        if not base or base=="/api/v1" or not token:raise RuntimeError("Configure the ServiceOps URL and a scoped API token in Administration → Connections")
        encoded=json.dumps(body).encode() if body is not None else None
        headers={"Authorization":f"Bearer {token}","Accept":"application/json","X-Request-ID":str(uuid.uuid4())}
        if encoded is not None:headers["Content-Type"]="application/json"
        if idempotency_key:headers["Idempotency-Key"]=idempotency_key
        request=urllib.request.Request(f"{base}/{resource.lstrip('/')}",data=encoded,method=method,headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=8) as response:
                document=json.load(response);request_id=response.headers.get("X-Request-ID",headers["X-Request-ID"])
                return document.get("data",document),request_id,response.status
        except urllib.error.HTTPError as exc:
            try: problem=json.load(exc);detail=problem.get("detail") or problem.get("error")
            except Exception:detail=None
            raise RuntimeError(f"ServiceOps returned HTTP {exc.code}{': '+str(detail) if detail else ''}") from exc
        except (urllib.error.URLError,TimeoutError) as exc:raise RuntimeError("ServiceOps is unreachable") from exc

    def store_serviceops_ticket(self,db,rid,ticket,request_id):
        db.execute("UPDATE runbooks SET serviceops_ticket=?,serviceops_type=?,serviceops_title=?,serviceops_state=?,serviceops_priority=?,serviceops_synced_at=?,serviceops_request_id=?,updated_at=? WHERE id=?",(
          str(ticket.get("number",""))[:40],str(ticket.get("type",""))[:30],str(ticket.get("title",""))[:300],str(ticket.get("state",""))[:80],str(ticket.get("priority",""))[:20],now(),request_id,now(),rid))

    def serviceops_lifecycle(self,db,rid,target):
        rb=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone();ticket_number=str(rb["serviceops_ticket"] or "").strip()
        settings={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=? AND key LIKE 'serviceops_%'",(rb["instance_id"],))}
        if not ticket_number or settings.get("serviceops_enabled","true")!="true" or target not in {"live","complete"}:return None
        ticket,request_id,_=self.serviceops_request(db,rb["instance_id"],"GET",f"tickets/{urllib.parse.quote(ticket_number)}")
        if target=="live" and settings.get("serviceops_require_approved","true")=="true" and ticket.get("type")=="change" and ticket.get("state") not in {"Approved","In Progress"}:
            raise PermissionError(f"ServiceOps change {ticket_number} is {ticket.get('state','not approved')}; approval is required before Live")
        should_update=(target=="live" and settings.get("serviceops_sync_on_live","true")=="true") or (target=="complete" and settings.get("serviceops_sync_on_complete","true")=="true")
        if should_update:
            desired="In Progress" if target=="live" else "Resolved"
            ticket,request_id,_=self.serviceops_request(db,rb["instance_id"],"PATCH",f"tickets/{urllib.parse.quote(ticket_number)}",{"state":desired},f"flowops-{rid}-{target}")
        workflow=None
        if target=="live" and settings.get("serviceops_trigger_workflow","false")=="true":
            workflow,_,_=self.serviceops_request(db,rb["instance_id"],"POST",f"tickets/{urllib.parse.quote(ticket_number)}/workflow-events",{},f"flowops-{rid}-workflow-live")
        self.store_serviceops_ticket(db,rid,ticket,request_id)
        append_audit(db,rid,"serviceops.lifecycle",f"{ticket_number} → {ticket.get('state')}","FlowOps API")
        return {"ticket":ticket,"workflow":workflow,"request_id":request_id}

    def sync_serviceops_ctasks(self, db, rid, instance_id, ticket_number, ticket_type):
        if ticket_type != "change": return []
        try:
            ctasks,_,_=self.serviceops_request(db,instance_id,"GET",f"tickets/{urllib.parse.quote(ticket_number)}/ctasks")
        except RuntimeError:
            return []
        existing={row["serviceops_ctask"]:row["id"] for row in db.execute("SELECT id,serviceops_ctask FROM tasks WHERE runbook_id=? AND serviceops_ctask IS NOT NULL",(rid,))}
        max_order=db.execute("SELECT COALESCE(MAX(sort_order),0) FROM tasks WHERE runbook_id=?",(rid,)).fetchone()[0]
        if ctasks and not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name='Change tasks'",(rid,)).fetchone():
            stream_order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
            db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,"Change tasks",stream_order,now()))
        created=[];previous_id=None
        for ctask in ctasks:
            number=str(ctask.get("number") or "").strip()
            if not number: continue
            if number in existing:
                previous_id=existing[number];continue
            max_order+=1
            owner=str(ctask.get("assignee") or ctask.get("assignmentGroup") or "")[:120]
            description=str(ctask.get("workNotes") or "")[:2000]
            title=str(ctask.get("title") or number)[:200]
            cur=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,status,sort_order,serviceops_ctask) VALUES(?,?,?,?,?,?,?,?,?)",
                (rid,title,description,"Change tasks",owner,15,"pending",max_order,number))
            task_id=cur.lastrowid;created.append(task_id)
            if previous_id: db.execute("INSERT OR IGNORE INTO dependencies(task_id,depends_on_id) VALUES(?,?)",(task_id,previous_id))
            previous_id=task_id
        if created: append_audit(db,rid,"serviceops.ctasks_imported",f"Imported {len(created)} change task(s) from {ticket_number}")
        return created

    def push_serviceops_ctask_state(self, db, rid, ctask_number, target):
        """Best-effort: reflect a FlowOps task's completion back onto the
        matching ServiceOps CTASK, so the change's own required-task gate
        (which blocks Resolve while a required CTASK stays open) doesn't
        surface a confusing conflict once every FlowOps task is done.
        Never raises -- a ServiceOps outage must not block local task
        execution, only get audited."""
        state = {"running": "Work in Progress", "complete": "Closed Complete", "skipped": "Cancelled"}.get(target)
        if not state: return
        rb=db.execute("SELECT r.serviceops_ticket,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone()
        ticket=str(rb["serviceops_ticket"] or "").strip() if rb else ""
        if not ticket: return
        try:
            self.serviceops_request(db,rb["instance_id"],"PATCH",f"tickets/{urllib.parse.quote(ticket)}/ctasks/{urllib.parse.quote(ctask_number)}",{"state":state},f"flowops-ctask-{ctask_number}-{target}")
            append_audit(db,rid,"serviceops.ctask_synced",f"{ctask_number} → {state}")
        except RuntimeError as exc:
            append_audit(db,rid,"serviceops.ctask_sync_failed",f"{ctask_number}: {exc}")

    def apply_serviceops_sync(self, db, rid, ticket):
        """Fetch a linked change ticket, store its status, and import its CTASKs
        into this runbook's task list. Raises RuntimeError on any ServiceOps
        failure; callers on a best-effort path (e.g. runbook creation) should
        catch that and proceed without blocking on ServiceOps availability."""
        rb=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone()
        remote,request_id,_=self.serviceops_request(db,rb["instance_id"],"GET",f"tickets/{urllib.parse.quote(ticket)}")
        self.store_serviceops_ticket(db,rid,remote,request_id);append_audit(db,rid,"serviceops.synced",f"Linked {ticket}")
        created=self.sync_serviceops_ctasks(db,rid,rb["instance_id"],ticket,remote.get("type"))
        return remote,request_id,created

    def sync_serviceops(self, db, rid, payload):
        rb=db.execute("SELECT serviceops_ticket FROM runbooks WHERE id=?",(rid,)).fetchone()
        ticket=str(payload.get("ticket") or (rb["serviceops_ticket"] if rb else "") or "").strip()
        if not ticket: return self.send_json({"error":"Link a ServiceOps ticket first"},400)
        try:
            remote,request_id,created=self.apply_serviceops_sync(db,rid,ticket)
        except RuntimeError as exc:return self.send_json({"error":str(exc)},502)
        doc=runbook_document(db,rid);db.commit()
        return self.send_json({"data":doc,"serviceops":remote,"request_id":request_id,"ctasks_imported":len(created)})

    def test_integration(self, db, provider, actor, overrides=None):
        overrides=overrides or {}
        values={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=? AND key LIKE ?",(actor["instance_id"],f"{provider}_%"))}
        base=str(overrides.get("url") or values.get(f"{provider}_url","")).strip().rstrip("/")
        token=str(overrides.get("credential") or "").strip()
        testing_unsaved_credential=bool(token)
        if not token:
            try:token,_=integration_credential(db,actor["instance_id"],provider)
            except RuntimeError as exc:return self.send_json({"error":str(exc)},503)
        if not base:return self.send_json({"error":"Configure the ServiceOps connection URL first"},400)
        if not token:return self.send_json({"error":"Paste a ServiceOps API key, save the connection, then test again"},400)
        if base.startswith("mock://"):
            result={"ok":True,"provider":provider,"latency_ms":12,"message":"ServiceOps REST API v1 verified","credential_configured":True,"tested_unsaved_credential":testing_unsaved_credential,"verified_scopes":["tickets:read"]}
        else:
            endpoint=(base if base.endswith("/api/v1") else f"{base}/api/v1")+"/tickets?limit=1"
            headers={"Accept":"application/json","Authorization":f"Bearer {token}"}
            started=time.monotonic()
            try:
                with urllib.request.urlopen(urllib.request.Request(endpoint,headers=headers),timeout=5) as response:
                    content_type=response.headers.get("Content-Type","")
                    if "application/json" not in content_type:return self.send_json({"error":"ServiceOps returned HTML instead of JSON. In MicroK8s use http://serviceops.operations.svc.cluster.local, not the Cloudflare Access URL."},502)
                    document=json.loads(response.read())
                    if not isinstance(document.get("data"),list):return self.send_json({"error":"ServiceOps returned an incompatible REST API response"},502)
            except urllib.error.HTTPError as exc:
                if exc.code in {401,403}:return self.send_json({"error":"ServiceOps rejected the API key. Create an active API client with tickets:read in ServiceOps Administration → API access."},502)
                return self.send_json({"error":f"ServiceOps returned HTTP {exc.code}"},502)
            except (urllib.error.URLError,TimeoutError):return self.send_json({"error":"ServiceOps is unreachable from FlowOps"},502)
            except json.JSONDecodeError:return self.send_json({"error":"ServiceOps returned invalid JSON"},502)
            result={"ok":True,"provider":provider,"latency_ms":round((time.monotonic()-started)*1000),"message":"ServiceOps REST API v1 and tickets:read verified","credential_configured":True,"tested_unsaved_credential":testing_unsaved_credential,"verified_scopes":["tickets:read"],"required_for_lifecycle":["tickets:update"],"required_for_workflows":["workflows:execute"]}
        append_audit(db,None,"integration.tested",f"{provider}: {result['message']}",actor["display_name"],actor["instance_id"]);db.commit()
        return self.send_json({"data":result})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=webhook_dispatcher_loop, daemon=True).start()
    host=os.getenv("FLOWOPS_HOST","127.0.0.1"); port=int(os.getenv("FLOWOPS_PORT","8080"))
    print(f"FlowOps listening on http://{host}:{port}")
    ThreadingHTTPServer((host,port),Handler).serve_forever()
