"""Request plumbing shared by every route: JSON responses, sessions, permission checks."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler
from typing import Any

from flowops.config import MAX_BODY, ROLE_PERMISSIONS, STATIC, TOKEN_SCOPE_PERMISSIONS, VERSION
from flowops.db import instance_settings, now
from flowops.ratelimit import check_rate_limit


# Returned by a route group that did not match the request path.
NOT_HANDLED = object()


class BaseHandler(BaseHTTPRequestHandler):
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

    def _handle_unexpected_error(self, exc: Exception):
        error_id=uuid.uuid4().hex[:12]
        print(json.dumps({
            "ts":now(),"level":"error","error_id":error_id,"client":self.address_string(),
            "method":self.command,"path":self.path.split("?")[0] if getattr(self,"path",None) else None,
            "exception":f"{type(exc).__name__}: {exc}",
            "traceback":traceback.format_exc(),
        },separators=(",",":")))
        try:
            if not self.wfile.closed:
                self.send_json({"error":"An unexpected error occurred.","error_id":error_id},500)
        except Exception:
            pass

    def request_is_over_tls(self) -> bool:
        """This process only ever speaks plain HTTP itself; in every real
        deployment (the MicroK8s Cloudflare Tunnel, or any other reverse
        proxy) TLS is terminated upstream and the proxy sets
        X-Forwarded-Proto so the origin can tell. Falls back to an explicit
        env var for a reverse proxy that doesn't set that header. Session
        cookies were previously never marked Secure at all -- this is only
        used to decide whether to add that flag, so the one thing it must
        never do is force it on in the local Docker preview (plain HTTP),
        which would make the browser silently refuse to store the cookie
        and break login."""
        return (self.headers.get("X-Forwarded-Proto","").strip().lower()=="https"
                or os.getenv("FLOWOPS_FORCE_SECURE_COOKIES","").strip().lower()=="true")

    def session_cookie(self, raw: str, max_age: int) -> str:
        secure=" Secure;" if self.request_is_over_tls() else ""
        return f"flowops_session={raw}; Path=/;{secure} HttpOnly; SameSite=Strict; Max-Age={max_age}"

    def start_session(self, db: sqlite3.Connection, user) -> tuple[dict[str,Any], str]:
        """Create a browser session for `user` (the caller audits and commits).
        Returns the signed-in user payload and its Set-Cookie header."""
        hours=max(1,min(24,int(instance_settings(db,user["instance_id"]).get("session_hours","8")))); session_seconds=hours*3600
        raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+session_seconds
        db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),))
        db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now(),self.client_address[0][:64],self.headers.get("User-Agent","")[:300]))
        db.execute("UPDATE users SET last_login_at=?,failed_login_count=0,locked_until=NULL WHERE id=?",(now(),user["id"]))
        safe={k:user[k] for k in ("id","username","display_name","email","role","team")}; safe["permissions"]=sorted(ROLE_PERMISSIONS[user["role"]]); safe["csrf_token"]=csrf
        return safe,self.session_cookie(raw,session_seconds)

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
        user=dict(row); user["permissions"]=sorted(ROLE_PERMISSIONS.get(user["role"],set())); user["mfa_backup_codes_remaining"]=len(json.loads(user.get("mfa_backup_codes") or "[]"))
        for secret_column in ("password_hash","mfa_secret_encrypted","mfa_pending_secret_encrypted","mfa_backup_codes","mfa_last_step"): user.pop(secret_column,None)
        user["auth_method"]="session"
        return user

    def require(self, db: sqlite3.Connection, permission: str) -> dict[str,Any] | None:
        return self.require_any(db, {permission})

    def require_any(self, db: sqlite3.Connection, permissions: set[str]) -> dict[str,Any] | None:
        """Like require(), but passes if the actor holds any one of several
        permissions -- e.g. the backup listing endpoint is useful to both a
        full admin:access session and a narrowly-scoped backups:read
        automation token, and neither should have to be granted the other's
        (broader, for the token; differently-shaped, for the admin) grant
        just to read a list of filenames and sizes."""
        user=self.current_user(db)
        if not user:
            self.send_json({"error":"Authentication required"},401); return None
        if user.get("auth_method")=="token":
            retry_after=check_rate_limit(f"token:{user['username']}")
            if retry_after:
                self.send_json({"error":"Rate limit exceeded. Slow down and try again shortly."},429,{"Retry-After":str(retry_after)}); return None
        if not permissions & set(user["permissions"]):
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
            body=body.replace(b'src="/identity.js"', f'src="/identity.js?v={VERSION}"'.encode())
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
