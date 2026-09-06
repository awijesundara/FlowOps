#!/usr/bin/env python3
"""FlowOps: dependency-aware operational runbooks with ServiceOps integration."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import base64
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DB_PATH = os.getenv("FLOWOPS_DB", str(Path(__file__).with_name("flowops.db")))
STATIC = Path(__file__).with_name("static")
MAX_BODY = 1_000_000
SESSION_SECONDS = 8 * 60 * 60
ROLE_PERMISSIONS = {
    "Admin": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync","admin:access","admin:users","admin:settings"},
    "Editor": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync"},
    "Member": {"runbooks:view","runbooks:execute"},
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
          description TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#3158c7',
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invitations (
          id INTEGER PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
          accepted_at TEXT, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runbook_teams (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(runbook_id,name)
        );
        CREATE TABLE IF NOT EXISTS team_members (
          team_id INTEGER NOT NULL REFERENCES runbook_teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(team_id,user_id)
        );
        """)
        columns={row[1] for row in db.execute("PRAGMA table_info(runbooks)")}
        if "workspace_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id)")
        if "actual_started_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_started_at TEXT")
        if "actual_completed_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_completed_at TEXT")
        for column,definition in {
          "serviceops_type":"TEXT","serviceops_title":"TEXT","serviceops_state":"TEXT",
          "serviceops_priority":"TEXT","serviceops_synced_at":"TEXT","serviceops_request_id":"TEXT"
        }.items():
            if column not in columns: db.execute(f"ALTER TABLE runbooks ADD COLUMN {column} {definition}")
        task_columns={row[1] for row in db.execute("PRAGMA table_info(tasks)")}
        task_migrations={
          "task_type":"TEXT NOT NULL DEFAULT 'normal'", "scheduled_offset":"INTEGER NOT NULL DEFAULT 0",
          "owner_user_id":"INTEGER REFERENCES users(id)", "owner_team_id":"INTEGER REFERENCES runbook_teams(id)",
          "validation_result":"TEXT", "validation_comment":"TEXT", "blocked_reason":"TEXT"
        }
        for column,definition in task_migrations.items():
            if column not in task_columns: db.execute(f"ALTER TABLE tasks ADD COLUMN {column} {definition}")
        db.execute("UPDATE users SET role='Admin' WHERE role='Administrator'")
        db.execute("UPDATE users SET role='Editor' WHERE role='Runbook Manager'")
        db.execute("UPDATE users SET role='Member' WHERE role IN ('Operator','Viewer')")
        db.execute("INSERT OR IGNORE INTO workspaces(name,description,color,created_at) VALUES(?,?,?,?)",("Resilience Operations","Production change, recovery, and release orchestration.","#3158c7",now()))
        default_workspace=db.execute("SELECT id FROM workspaces ORDER BY id LIMIT 1").fetchone()[0]
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
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            password=os.getenv("FLOWOPS_BOOTSTRAP_PASSWORD","FlowOps!Preview2026")
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at) VALUES(?,?,?,?,?,?,?)",
                       ("admin","Anushka","admin@flowops.local","Admin","Platform Operations",password_hash(password),now()))
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at) VALUES(?,?,?,?,?,?,?)",
                       ("operator","Release Operator","operator@flowops.local","Member","Release Engineering",password_hash("Operator!Preview2026"),now()))
        defaults={"workspace_name":"Resilience Operations","timezone":"Asia/Tokyo","require_approval":"true","session_hours":"8","serviceops_enabled":"true",
          "serviceops_url":os.getenv("SERVICEOPS_URL","http://host.docker.internal:8080"),"serviceops_sync_on_live":"true","serviceops_sync_on_complete":"true","serviceops_require_approved":"true","serviceops_trigger_workflow":"false",
          "jenkins_enabled":"false","jenkins_url":os.getenv("JENKINS_URL",""),"jenkins_live_only":"true","jenkins_auto_complete":"true","jenkins_allow_parameters":"true"}
        for key,value in defaults.items(): db.execute("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",(key,value,now()))


def password_hash(password: str, salt: bytes | None=None) -> str:
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"


def password_valid(password: str, encoded: str) -> bool:
    try: _,rounds,salt,digest=encoded.split("$"); actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),int(rounds)).hex()
    except (ValueError,TypeError): return False
    return hmac.compare_digest(actual,digest)


def append_audit(db: sqlite3.Connection, runbook_id: int | None, action: str, detail: str, actor: str = "Preview User") -> None:
    previous = db.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    previous_hash = previous[0] if previous else "GENESIS"
    stamp = now()
    digest = hashlib.sha256(f"{previous_hash}|{runbook_id}|{action}|{detail}|{actor}|{stamp}".encode()).hexdigest()
    db.execute("INSERT INTO audit(runbook_id,action,detail,actor,created_at,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?)",
               (runbook_id, action, detail, actor, stamp, previous_hash, digest))


def rows(items) -> list[dict[str, Any]]:
    return [dict(row) for row in items]


def runbook_document(db: sqlite3.Connection, rid: int, user: dict[str,Any] | None=None) -> dict[str, Any] | None:
    rb = db.execute("SELECT * FROM runbooks WHERE id=?", (rid,)).fetchone()
    if not rb:
        return None
    doc = dict(rb)
    all_tasks = rows(db.execute("SELECT t.*,u.display_name owner_user_name,rt.name owner_team_name FROM tasks t LEFT JOIN users u ON u.id=t.owner_user_id LEFT JOIN runbook_teams rt ON rt.id=t.owner_team_id WHERE t.runbook_id=? ORDER BY t.sort_order,t.id", (rid,)))
    tasks=all_tasks
    if user and user.get("role")=="Member":
        team_ids={row[0] for row in db.execute("SELECT team_id FROM team_members WHERE user_id=?",(user["id"],))}
        tasks=[t for t in all_tasks if t["owner_user_id"]==user["id"] or t["owner_team_id"] in team_ids]
    deps = rows(db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?", (rid,)))
    dep_map: dict[int,list[int]] = {}
    for dep in deps:
        dep_map.setdefault(dep["task_id"], []).append(dep["depends_on_id"])
    for task in tasks:
        task["depends_on"] = dep_map.get(task["id"], [])
        task["blocked"] = task["status"] == "pending" and any(next((x["status"] for x in all_tasks if x["id"] == d), "pending") not in {"complete","skipped"} for d in task["depends_on"])
        task["owner_display"] = task["owner_user_name"] or task["owner_team_name"] or task["owner"] or "Unassigned"
        task["late"] = False
        if rb["scheduled_at"] and task["status"] not in {"complete","skipped"}:
            try:
                scheduled=datetime.fromisoformat(rb["scheduled_at"])
                if scheduled.tzinfo is None: scheduled=scheduled.replace(tzinfo=timezone.utc)
                task["late"] = datetime.now(timezone.utc).timestamp() > scheduled.timestamp() + (task["scheduled_offset"]+task["duration"])*60
            except ValueError: pass
    doc["tasks"] = tasks
    doc["comments"] = rows(db.execute("SELECT * FROM comments WHERE runbook_id=? ORDER BY id DESC", (rid,)))
    doc["teams"] = rows(db.execute("SELECT rt.id,rt.name,COUNT(tm.user_id) member_count FROM runbook_teams rt LEFT JOIN team_members tm ON tm.team_id=rt.id WHERE rt.runbook_id=? GROUP BY rt.id ORDER BY rt.name",(rid,)))
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
        print(f"{self.address_string()} {fmt % args}")

    def send_json(self, payload: Any, status=200, headers: dict[str,str] | None=None):
        body=json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(body))); self.send_header("Cache-Control","no-store")
        self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY")
        self.send_header("Content-Security-Policy","default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'")
        for key,value in (headers or {}).items(): self.send_header(key,value)
        self.end_headers(); self.wfile.write(body)

    def current_user(self, db: sqlite3.Connection) -> dict[str,Any] | None:
        cookies={}
        for item in self.headers.get("Cookie","").split(";"):
            if "=" in item:
                key,value=item.strip().split("=",1); cookies[key]=value
        token=cookies.get("flowops_session","")
        if not token: return None
        digest=hashlib.sha256(token.encode()).hexdigest()
        row=db.execute("SELECT u.*,s.csrf_token,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",(digest,int(time.time()))).fetchone()
        if not row: return None
        user=dict(row); user["permissions"]=sorted(ROLE_PERMISSIONS.get(user["role"],set())); user.pop("password_hash",None)
        return user

    def require(self, db: sqlite3.Connection, permission: str) -> dict[str,Any] | None:
        user=self.current_user(db)
        if not user:
            self.send_json({"error":"Authentication required"},401); return None
        if permission not in user["permissions"]:
            self.send_json({"error":f"Your {user['role']} role does not allow this action"},403); return None
        if self.command in {"POST","PATCH","PUT","DELETE"} and self.headers.get("X-CSRF-Token","") != user["csrf_token"]:
            self.send_json({"error":"Invalid or missing CSRF token"},403); return None
        return user

    def body(self) -> dict[str, Any]:
        length=int(self.headers.get("Content-Length","0"))
        if length > MAX_BODY: raise ValueError("Request is too large")
        data=json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(data,dict): raise ValueError("A JSON object is required")
        return data

    def static(self, name: str, content_type: str):
        try: body=(STATIC/name).read_bytes()
        except FileNotFoundError: return self.send_error(404)
        self.send_response(200); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(body)))
        self.send_header("Cache-Control","no-cache"); self.end_headers(); self.wfile.write(body)

    def do_HEAD(self):
        path=urllib.parse.urlparse(self.path).path
        if path in ("/health","/ready"):
            self.send_response(200); self.send_header("Content-Type","application/json; charset=utf-8")
            self.send_header("Cache-Control","no-store"); self.send_header("X-Content-Type-Options","nosniff")
            self.end_headers(); return
        if path=="/":
            self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Cache-Control","no-cache"); self.end_headers(); return
        self.send_error(404)

    def do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        if path=="/": return self.static("index.html","text/html; charset=utf-8")
        if path=="/app.js": return self.static("app.js","application/javascript; charset=utf-8")
        if path=="/styles.css": return self.static("styles.css","text/css; charset=utf-8")
        if path in ("/health","/ready"): return self.send_json({"status":"ok","service":"flowops"})
        if path=="/api/events": return self.stream_events()
        with connect() as db:
            if path=="/api/auth/me":
                user=self.current_user(db)
                if not user: return self.send_json({"error":"Authentication required"},401)
                settings={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings")}
                return self.send_json({"data":{"user":user,"settings":settings}})
            if path=="/api/admin/users":
                if not self.require(db,"admin:users"): return
                data=rows(db.execute("SELECT id,username,display_name,email,role,team,active,last_login_at,created_at FROM users ORDER BY display_name"))
                return self.send_json({"data":data})
            if path=="/api/admin/settings":
                if not self.require(db,"admin:settings"): return
                return self.send_json({"data":{r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings")}})
            if path=="/api/admin/integrations":
                if not self.require(db,"admin:settings"): return
                values={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings")}
                data={
                  "serviceops":{"enabled":values.get("serviceops_enabled","true"),"url":values.get("serviceops_url",os.getenv("SERVICEOPS_URL","")),"credential_configured":bool(os.getenv("SERVICEOPS_TOKEN")),"credential_source":"SERVICEOPS_TOKEN","sync_on_live":values.get("serviceops_sync_on_live","true"),"sync_on_complete":values.get("serviceops_sync_on_complete","true"),"require_approved":values.get("serviceops_require_approved","true"),"trigger_workflow":values.get("serviceops_trigger_workflow","false"),"api_version":"v1"},
                  "jenkins":{"enabled":values.get("jenkins_enabled","false"),"url":values.get("jenkins_url",os.getenv("JENKINS_URL","")),"credential_configured":bool(os.getenv("JENKINS_TOKEN")),"credential_source":"JENKINS_TOKEN","live_only":values.get("jenkins_live_only","true"),"auto_complete":values.get("jenkins_auto_complete","true"),"allow_parameters":values.get("jenkins_allow_parameters","true")}
                }
                return self.send_json({"data":data})
            if path=="/api/admin/workspaces":
                if not self.require(db,"admin:settings"): return
                data=rows(db.execute("SELECT w.*,COUNT(r.id) runbook_count FROM workspaces w LEFT JOIN runbooks r ON r.workspace_id=w.id GROUP BY w.id ORDER BY w.name"))
                return self.send_json({"data":data})
            if path=="/api/workspaces":
                if not self.require(db,"runbooks:view"): return
                return self.send_json({"data":rows(db.execute("SELECT id,name,description,color FROM workspaces WHERE active=1 ORDER BY name"))})
            if path=="/api/runbooks":
                if not self.require(db,"runbooks:view"): return
                items=rows(db.execute("SELECT r.*,w.name workspace_name,COUNT(t.id) task_count,SUM(CASE WHEN t.status='complete' THEN 1 ELSE 0 END) done_count FROM runbooks r LEFT JOIN workspaces w ON w.id=r.workspace_id LEFT JOIN tasks t ON t.runbook_id=r.id GROUP BY r.id ORDER BY r.updated_at DESC"))
                return self.send_json({"data":items})
            if path.startswith("/api/runbooks/"):
                user=self.require(db,"runbooks:view")
                if not user: return
                parts=path.strip("/").split("/")
                try: rid=int(parts[2])
                except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
                if len(parts)==4 and parts[3]=="assignment-options":
                    users=rows(db.execute("SELECT id,display_name,email FROM users WHERE active=1 ORDER BY display_name")); teams=rows(db.execute("SELECT id,name FROM runbook_teams WHERE runbook_id=? ORDER BY name",(rid,)))
                    return self.send_json({"data":{"users":users,"teams":teams}})
                if len(parts)==4 and parts[3]=="teams":
                    teams=rows(db.execute("SELECT rt.id,rt.name,COUNT(tm.user_id) member_count FROM runbook_teams rt LEFT JOIN team_members tm ON tm.team_id=rt.id WHERE rt.runbook_id=? GROUP BY rt.id ORDER BY rt.name",(rid,)))
                    for team in teams: team["members"]=rows(db.execute("SELECT u.id,u.display_name,u.email FROM users u JOIN team_members tm ON tm.user_id=u.id WHERE tm.team_id=? ORDER BY u.display_name",(team["id"],)))
                    return self.send_json({"data":teams})
                if len(parts)!=3:return self.send_json({"error":"Not found"},404)
                doc=runbook_document(db,rid,user)
                return self.send_json({"data":doc} if doc else {"error":"Not found"},200 if doc else 404)
            if path=="/api/dashboard":
                if not self.require(db,"runbooks:view"): return
                stats=dict(db.execute("SELECT COUNT(*) runbooks, SUM(status='live') live, SUM(status='complete') complete FROM runbooks").fetchone())
                stats["tasks"]=db.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
                stats["task_completion"]=db.execute("SELECT COALESCE(ROUND(100.0*SUM(status='complete')/NULLIF(COUNT(*),0)),0) FROM tasks").fetchone()[0]
                return self.send_json({"data":stats})
        self.send_json({"error":"Not found"},404)

    def stream_events(self):
        """Authenticated same-origin SSE feed backed by the durable audit sequence."""
        with connect() as db:
            user=self.current_user(db)
            if not user or "runbooks:view" not in user["permissions"]:
                return self.send_json({"error":"Authentication required"},401)
            version=db.execute("SELECT COALESCE(MAX(id),0) FROM audit").fetchone()[0]
        self.send_response(200); self.send_header("Content-Type","text/event-stream; charset=utf-8")
        self.send_header("Cache-Control","no-cache, no-store"); self.send_header("Connection","keep-alive")
        self.send_header("X-Accel-Buffering","no"); self.end_headers()
        try:
            self.wfile.write(f"event: connected\ndata: {{\"version\":{version}}}\n\n".encode()); self.wfile.flush()
            for tick in range(300):
                time.sleep(1)
                with connect() as db:
                    current=db.execute("SELECT COALESCE(MAX(id),0) FROM audit").fetchone()[0]
                    events=rows(db.execute("SELECT id,runbook_id,action,detail,actor,created_at FROM audit WHERE id>? ORDER BY id LIMIT 25",(version,))) if current!=version else []
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
            if path=="/api/auth/login":
                username=str(payload.get("username","")).strip(); password=str(payload.get("password",""))
                user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1",(username,username)).fetchone()
                if not user or not password_valid(password,user["password_hash"]):
                    time.sleep(.2); return self.send_json({"error":"Invalid username or password"},401)
                raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+SESSION_SECONDS
                db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),)); db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at) VALUES(?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now())); db.execute("UPDATE users SET last_login_at=? WHERE id=?",(now(),user["id"])); append_audit(db,None,"auth.login",f"{user['username']} signed in",user["display_name"]); db.commit()
                safe={k:user[k] for k in ("id","username","display_name","email","role","team")}; safe["permissions"]=sorted(ROLE_PERMISSIONS[user["role"]]); safe["csrf_token"]=csrf
                return self.send_json({"data":safe},headers={"Set-Cookie":f"flowops_session={raw}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"})
            if path=="/api/auth/logout":
                user=self.current_user(db)
                if user:
                    cookies={i.strip().split("=",1)[0]:i.strip().split("=",1)[1] for i in self.headers.get("Cookie","").split(";") if "=" in i}; raw=cookies.get("flowops_session","")
                    db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(raw.encode()).hexdigest(),)); append_audit(db,None,"auth.logout",f"{user['username']} signed out",user["display_name"]); db.commit()
                return self.send_json({"data":{"ok":True}},headers={"Set-Cookie":"flowops_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            if path=="/api/admin/users":
                actor=self.require(db,"admin:users")
                if not actor:return
                username=str(payload.get("username","")).strip(); display=str(payload.get("display_name","")).strip(); role=str(payload.get("role","Member")); password=str(payload.get("password", ""))
                if not username or not display or role not in ROLE_PERMISSIONS or len(password)<12:return self.send_json({"error":"Username, display name, valid role, and password of at least 12 characters are required"},400)
                try: db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at) VALUES(?,?,?,?,?,?,?)",(username,display,str(payload.get("email",""))[:180],role,str(payload.get("team",""))[:120],password_hash(password),now()))
                except sqlite3.IntegrityError:return self.send_json({"error":"That username already exists"},409)
                append_audit(db,None,"admin.user_created",f"{username} as {role}",actor["display_name"]); db.commit(); return self.send_json({"data":{"ok":True}},201)
            if path=="/api/admin/invitations":
                actor=self.require(db,"admin:users")
                if not actor:return
                email=str(payload.get("email","")).strip().lower(); role=str(payload.get("role","Member"))
                if "@" not in email or role not in ROLE_PERMISSIONS:return self.send_json({"error":"A valid email and role are required"},400)
                raw=secrets.token_urlsafe(28); db.execute("INSERT INTO invitations(email,role,token_hash,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?)",(email,role,hashlib.sha256(raw.encode()).hexdigest(),int(time.time())+7*86400,actor["id"],now())); append_audit(db,None,"admin.user_invited",f"{email} as {role}",actor["display_name"]); db.commit()
                return self.send_json({"data":{"email":email,"role":role,"invite_token":raw,"expires_in_days":7}},201)
            if path=="/api/admin/workspaces":
                actor=self.require(db,"admin:settings")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name:return self.send_json({"error":"Workspace name is required"},400)
                try: cur=db.execute("INSERT INTO workspaces(name,description,color,created_at) VALUES(?,?,?,?)",(name,str(payload.get("description",""))[:500],str(payload.get("color","#3158c7"))[:20],now()))
                except sqlite3.IntegrityError:return self.send_json({"error":"That workspace already exists"},409)
                append_audit(db,None,"admin.workspace_created",name,actor["display_name"]); db.commit(); return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
            if path=="/api/admin/settings":
                actor=self.require(db,"admin:settings")
                if not actor:return
                allowed={"workspace_name","timezone","require_approval","session_hours","serviceops_enabled"}
                for key,value in payload.items():
                    if key in allowed: db.execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(key,str(value)[:160],now()))
                append_audit(db,None,"admin.settings_updated","Workspace configuration updated",actor["display_name"]); db.commit(); return self.send_json({"data":{"ok":True}})
            if path in {"/api/admin/integrations","/api/admin/integrations/test"}:
                actor=self.require(db,"admin:settings")
                if not actor:return
                provider=str(payload.get("provider","")).lower()
                if provider not in {"serviceops","jenkins"}:return self.send_json({"error":"Provider must be serviceops or jenkins"},400)
                if path.endswith("/test"):
                    return self.test_integration(db,provider,actor)
                allowed={
                  "serviceops":{"enabled","url","sync_on_live","sync_on_complete","require_approved","trigger_workflow"},
                  "jenkins":{"enabled","url","live_only","auto_complete","allow_parameters"}
                }[provider]
                if "secret" in payload or "token" in payload:return self.send_json({"error":"Credentials must be supplied through the server environment, never the browser"},400)
                url=str(payload.get("url","")).strip().rstrip("/")
                if url and not (url.startswith("http://") or url.startswith("https://") or url.startswith("mock://")):return self.send_json({"error":"Connection URL must use http or https"},400)
                for key in allowed:
                    if key in payload:
                        value=url if key=="url" else str(payload[key]).lower() if isinstance(payload[key],bool) else str(payload[key])
                        db.execute("INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(f"{provider}_{key}",value[:500],now()))
                append_audit(db,None,"integration.configured",f"{provider} connection policy updated",actor["display_name"]);db.commit()
                return self.send_json({"data":{"ok":True,"provider":provider}})
            if path=="/api/runbooks":
                actor=self.require(db,"runbooks:edit")
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>160: return self.send_json({"error":"Name is required (maximum 160 characters)"},400)
                workspace_id=int(payload.get("workspace_id") or db.execute("SELECT id FROM workspaces WHERE active=1 ORDER BY id LIMIT 1").fetchone()[0]); workspace=db.execute("SELECT 1 FROM workspaces WHERE id=? AND active=1",(workspace_id,)).fetchone()
                if not workspace:return self.send_json({"error":"Select an active workspace"},400)
                stamp=now(); cur=db.execute("INSERT INTO runbooks(name,description,owner,scheduled_at,serviceops_ticket,workspace_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(name,str(payload.get("description",""))[:2000],str(payload.get("owner",""))[:120],payload.get("scheduled_at") or None,str(payload.get("serviceops_ticket",""))[:40],workspace_id,stamp,stamp))
                append_audit(db,cur.lastrowid,"runbook.created",name,actor["display_name"]); doc=runbook_document(db,cur.lastrowid); db.commit()
                return self.send_json({"data":doc},201)
            parts=path.strip("/").split("/")
            if len(parts)>=3 and parts[:2]==["api","runbooks"]:
                try: rid=int(parts[2])
                except ValueError: return self.send_json({"error":"Not found"},404)
                if not db.execute("SELECT 1 FROM runbooks WHERE id=?",(rid,)).fetchone(): return self.send_json({"error":"Not found"},404)
                if len(parts)==4 and parts[3]=="tasks":
                    actor=self.require(db,"runbooks:edit")
                    if not actor:return
                    title=str(payload.get("title","")).strip()
                    if not title: return self.send_json({"error":"Task title is required"},400)
                    order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM tasks WHERE runbook_id=?",(rid,)).fetchone()[0]
                    task_type=str(payload.get("task_type","normal")); allowed_types={"normal","milestone","checklist","validation","sms","email","call"}
                    if task_type not in allowed_types:return self.send_json({"error":"Invalid task type"},400)
                    duration=max(0,min(int(payload.get("duration",15)),10080)); duration=0 if task_type in {"milestone","checklist","sms","email","call"} else max(1,duration)
                    owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None; owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                    if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1",(owner_user_id,)).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                    if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,rid)).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                    cur=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset,owner_user_id,owner_team_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(rid,title,str(payload.get("description",""))[:2000],str(payload.get("stream","General"))[:80],"",duration,order,str(payload.get("automation_url",""))[:500] or None,task_type,max(0,int(payload.get("scheduled_offset",0))),owner_user_id,owner_team_id))
                    for dep in payload.get("depends_on",[]):
                        if db.execute("SELECT 1 FROM tasks WHERE id=? AND runbook_id=?",(dep,rid)).fetchone(): db.execute("INSERT OR IGNORE INTO dependencies VALUES(?,?)",(cur.lastrowid,dep))
                    append_audit(db,rid,"task.created",title,actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc},201)
                if len(parts)==4 and parts[3]=="teams":
                    actor=self.require(db,"runbooks:edit")
                    if not actor:return
                    name=str(payload.get("name","")).strip()
                    if not name:return self.send_json({"error":"Team name is required"},400)
                    try: cur=db.execute("INSERT INTO runbook_teams(runbook_id,name,created_at) VALUES(?,?,?)",(rid,name[:120],now()))
                    except sqlite3.IntegrityError:return self.send_json({"error":"That runbook team already exists"},409)
                    for uid in payload.get("user_ids",[]):
                        if db.execute("SELECT 1 FROM users WHERE id=? AND active=1",(uid,)).fetchone():db.execute("INSERT OR IGNORE INTO team_members(team_id,user_id) VALUES(?,?)",(cur.lastrowid,uid))
                    append_audit(db,rid,"team.created",name,actor["display_name"]);db.commit();return self.send_json({"data":{"id":cur.lastrowid,"name":name}},201)
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
                    current=db.execute("SELECT status FROM runbooks WHERE id=?",(rid,)).fetchone()[0]
                    valid={"draft":{"ready","cancelled"},"ready":{"live","draft","cancelled"},"live":{"paused","complete","cancelled"},"paused":{"live","cancelled"},"complete":set(),"cancelled":set()}
                    if target not in valid[current]: return self.send_json({"error":f"Cannot transition {current} to {target}"},409)
                    stamp=now()
                    if target=="live":
                        db.execute("UPDATE runbooks SET status=?,mode='live',actual_started_at=COALESCE(actual_started_at,?),updated_at=? WHERE id=?",(target,stamp,stamp,rid))
                    elif target=="complete":
                        db.execute("UPDATE runbooks SET status=?,mode='plan',actual_completed_at=?,updated_at=? WHERE id=?",(target,stamp,stamp,rid))
                    else:
                        db.execute("UPDATE runbooks SET status=?,mode=?,updated_at=? WHERE id=?",(target,"live" if target=="paused" else "plan",stamp,rid))
                    append_audit(db,rid,"runbook.transition",f"{current} → {target}",actor["display_name"]); doc=runbook_document(db,rid,actor); db.commit()
                    return self.send_json({"data":doc})
                if len(parts)==4 and parts[3]=="serviceops-sync":
                    if not self.require(db,"integrations:sync"):return
                    return self.sync_serviceops(db,rid,payload)
        self.send_json({"error":"Not found"},404)

    def do_PATCH(self):
        path=urllib.parse.urlparse(self.path).path; parts=path.strip("/").split("/")
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.send_json({"error":str(exc)},400)
        if len(parts)==4 and parts[:3]==["api","admin","users"]:
            try: uid=int(parts[3])
            except ValueError:return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:users")
                if not actor:return
                user=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                if not user:return self.send_json({"error":"User not found"},404)
                role=str(payload.get("role",user["role"])); active=1 if payload.get("active",bool(user["active"])) else 0
                if role not in ROLE_PERMISSIONS:return self.send_json({"error":"Invalid role"},400)
                if uid==actor["id"] and (role!="Admin" or not active):return self.send_json({"error":"You cannot remove your own administrator access"},409)
                password=payload.get("password")
                if password is not None and len(str(password))<12:return self.send_json({"error":"Password must be at least 12 characters"},400)
                db.execute("UPDATE users SET display_name=?,email=?,role=?,team=?,active=? WHERE id=?",(str(payload.get("display_name",user["display_name"]))[:120],str(payload.get("email",user["email"]))[:180],role,str(payload.get("team",user["team"]))[:120],active,uid))
                if password is not None: db.execute("UPDATE users SET password_hash=? WHERE id=?",(password_hash(str(password)),uid)); db.execute("DELETE FROM sessions WHERE user_id=?",(uid,))
                append_audit(db,None,"admin.user_updated",f"{user['username']}: role={role}, active={bool(active)}",actor["display_name"]); db.commit(); return self.send_json({"data":{"ok":True}})
        if len(parts)!=3 or parts[:2] != ["api","tasks"]: return self.send_json({"error":"Not found"},404)
        try: tid=int(parts[2])
        except ValueError: return self.send_json({"error":"Not found"},404)
        with connect() as db:
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            task=db.execute("SELECT * FROM tasks WHERE id=?",(tid,)).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            runbook=db.execute("SELECT status FROM runbooks WHERE id=?",(task["runbook_id"],)).fetchone()
            if not runbook or runbook["status"]!="live":return self.send_json({"error":"Tasks can only be executed while the runbook is live"},409)
            if actor["role"]=="Member":
                assigned=task["owner_user_id"]==actor["id"] or (task["owner_team_id"] and db.execute("SELECT 1 FROM team_members WHERE team_id=? AND user_id=?",(task["owner_team_id"],actor["id"])).fetchone())
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
            append_audit(db,task["runbook_id"],"task.transition",f"{task['title']}: {task['status']} → {target}",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),task["runbook_id"])); doc=runbook_document(db,task["runbook_id"],actor); db.commit()
            return self.send_json({"data":doc})

    def do_DELETE(self):
        path=urllib.parse.urlparse(self.path).path; parts=path.strip("/").split("/")
        if len(parts)!=4 or parts[:3]!=["api","admin","users"]:return self.send_json({"error":"Not found"},404)
        try:uid=int(parts[3])
        except ValueError:return self.send_json({"error":"Not found"},404)
        with connect() as db:
            actor=self.require(db,"admin:users")
            if not actor:return
            if uid==actor["id"]:return self.send_json({"error":"You cannot delete your own account"},409)
            user=db.execute("SELECT username FROM users WHERE id=?",(uid,)).fetchone()
            if not user:return self.send_json({"error":"User not found"},404)
            db.execute("DELETE FROM users WHERE id=?",(uid,)); append_audit(db,None,"admin.user_deleted",user["username"],actor["display_name"]); db.commit(); return self.send_json({"data":{"ok":True}})

    def sync_serviceops(self, db, rid, payload):
        rb=db.execute("SELECT * FROM runbooks WHERE id=?",(rid,)).fetchone(); row=db.execute("SELECT value FROM settings WHERE key='serviceops_url'").fetchone(); base=(row[0] if row else os.getenv("SERVICEOPS_URL","")).rstrip("/"); token=os.getenv("SERVICEOPS_TOKEN","")
        ticket=str(payload.get("ticket") or rb["serviceops_ticket"] or "").strip()
        if not base or not token: return self.send_json({"error":"Configure SERVICEOPS_URL and SERVICEOPS_TOKEN in .env"},503)
        if not ticket: return self.send_json({"error":"Link a ServiceOps ticket first"},400)
        url=f"{base}/api/v1/tickets/{urllib.parse.quote(ticket)}"; req=urllib.request.Request(url,headers={"Authorization":f"Bearer {token}","Accept":"application/json"})
        try:
            with urllib.request.urlopen(req,timeout=8) as response: remote=json.load(response)
        except urllib.error.HTTPError as exc: return self.send_json({"error":f"ServiceOps returned HTTP {exc.code}"},502)
        except (urllib.error.URLError,TimeoutError): return self.send_json({"error":"ServiceOps is unreachable"},502)
        db.execute("UPDATE runbooks SET serviceops_ticket=?,updated_at=? WHERE id=?",(ticket,now(),rid)); append_audit(db,rid,"serviceops.synced",f"Linked {ticket}"); doc=runbook_document(db,rid); db.commit()
        return self.send_json({"data":doc,"serviceops":remote.get("data",remote)})

    def test_integration(self, db, provider, actor):
        values={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings WHERE key LIKE ?",(f"{provider}_%",))}
        base=values.get(f"{provider}_url","").rstrip("/")
        token=os.getenv("SERVICEOPS_TOKEN" if provider=="serviceops" else "JENKINS_TOKEN","")
        if not base:return self.send_json({"error":"Configure a connection URL first"},400)
        if base.startswith("mock://"):
            result={"ok":True,"provider":provider,"latency_ms":12,"message":"Preview connection verified","credential_configured":bool(token)}
        else:
            endpoint=f"{base}/health" if provider=="serviceops" else f"{base}/api/json"
            headers={"Accept":"application/json"}
            if token:
                if provider=="serviceops":headers["Authorization"]=f"Bearer {token}"
                else:headers["Authorization"]="Basic "+base64.b64encode(f"{os.getenv('JENKINS_USER','flowops')}:{token}".encode()).decode()
            started=time.monotonic()
            try:
                with urllib.request.urlopen(urllib.request.Request(endpoint,headers=headers),timeout=5) as response: ok=200 <= response.status < 400
            except urllib.error.HTTPError as exc:return self.send_json({"error":f"{provider.title()} returned HTTP {exc.code}"},502)
            except (urllib.error.URLError,TimeoutError):return self.send_json({"error":f"{provider.title()} is unreachable"},502)
            result={"ok":ok,"provider":provider,"latency_ms":round((time.monotonic()-started)*1000),"message":"Connection verified","credential_configured":bool(token)}
        append_audit(db,None,"integration.tested",f"{provider}: {result['message']}",actor["display_name"]);db.commit()
        return self.send_json({"data":result})


if __name__ == "__main__":
    init_db()
    host=os.getenv("FLOWOPS_HOST","127.0.0.1"); port=int(os.getenv("FLOWOPS_PORT","8080"))
    print(f"FlowOps listening on http://{host}:{port}")
    ThreadingHTTPServer((host,port),Handler).serve_forever()
