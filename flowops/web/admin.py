"""Administration: settings, sessions, API tokens, webhooks, audit and backups."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

import flowops.config
from flowops.audit import append_audit, verify_audit_chain
from flowops.backups import backup_database, list_backups
from flowops.config import BACKUP_INTERVAL_HOURS, TOKEN_SCOPE_PERMISSIONS, VERSION, WEBHOOK_EVENT_ACTIONS
from flowops.db import connect, instance_settings, now, rows
from flowops.mail import mail_configuration
from flowops.web.base import BaseHandler, NOT_HANDLED
from flowops.webhooks import deliver_webhook_once


class AdminRoutes(BaseHandler):
    def _get_admin_db(self, db, path):
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
            return self.send_json({"data":items,"available_events":list(WEBHOOK_EVENT_ACTIONS)})
        if path=="/api/admin/settings":
            actor=self.require(db,"admin:settings")
            if not actor: return
            values=instance_settings(db,actor["instance_id"]);mail=mail_configuration()
            values.update({"mail_delivery_configured":str(mail["configured"]).lower(),"mail_sender":mail["sender"],"mail_security":mail["security"],"public_url_configured":str(bool(mail["public_url"])).lower()})
            return self.send_json({"data":values})
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
            query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            filters={key:query[key][0].strip() for key in ("since","until","actor","action","runbook_id") if query.get(key) and query[key][0].strip()}
            clauses=["instance_id=?"]; params: list[Any]=[actor["instance_id"]]
            if "since" in filters: clauses.append("created_at>=?"); params.append(filters["since"])
            if "until" in filters: clauses.append("created_at<=?"); params.append(filters["until"])
            if "actor" in filters: clauses.append("actor LIKE ?"); params.append(f"%{filters['actor']}%")
            if "action" in filters: clauses.append("action LIKE ?"); params.append(f"{filters['action']}%")
            if "runbook_id" in filters:
                try: params.append(int(filters["runbook_id"]))
                except ValueError: return self.send_json({"error":"runbook_id must be a number"},400)
                clauses.append("runbook_id=?")
            events=rows(db.execute(f"SELECT id,runbook_id,action,detail,actor,created_at,previous_hash,event_hash FROM audit WHERE {' AND '.join(clauses)} ORDER BY id ASC",params))
            # Chain integrity is always verified over the full history, even for a filtered extract.
            chain_verified,_=verify_audit_chain(db,actor["instance_id"])
            export_body=json.dumps(events,sort_keys=True,separators=(",",":"))
            checksum=hashlib.sha256(export_body.encode()).hexdigest()
            append_audit(db,None,"audit.exported",f"{len(events)} events, chain_verified={chain_verified}"+(f", filters={json.dumps(filters,sort_keys=True)}" if filters else ""),actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"events":events,"count":len(events),"exported_at":now(),"chain_verified":chain_verified,"checksum":f"sha256:{checksum}","filters":filters}})
        if path=="/api/admin/audit/verify":
            actor=self.require(db,"admin:access")
            if not actor:return
            chain_verified,events_checked=verify_audit_chain(db,actor["instance_id"])
            return self.send_json({"data":{"chain_verified":chain_verified,"events_checked":events_checked,"verified_at":now()}})
        if path=="/api/admin/health":
            actor=self.require(db,"admin:access")
            if not actor:return
            counts=db.execute("SELECT (SELECT COUNT(*) FROM users WHERE instance_id=? AND active=1),(SELECT COUNT(*) FROM workspaces WHERE instance_id=? AND active=1),(SELECT COUNT(*) FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?),(SELECT COUNT(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.instance_id=? AND s.expires_at>?)",(actor["instance_id"],actor["instance_id"],actor["instance_id"],actor["instance_id"],int(time.time()))).fetchone()
            return self.send_json({"data":{"status":"healthy","version":VERSION,"database":db.execute("PRAGMA integrity_check").fetchone()[0],"active_users":counts[0],"workspaces":counts[1],"runbooks":counts[2],"active_sessions":counts[3],"email_configured":mail_configuration()["configured"],"credential_encryption_configured":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"realtime":"SSE"}})
        if path=="/api/admin/backups":
            actor=self.require_any(db,{"admin:access","backups:read"})
            if not actor:return
            return self.send_json({"data":{"backups":list_backups(),"retain":flowops.config.BACKUP_RETAIN,"interval_hours":BACKUP_INTERVAL_HOURS}})
        if path.startswith("/api/admin/backups/"):
            # Scoped to its own backups:read permission (see
            # TOKEN_SCOPE_PERMISSIONS) rather than admin:access, so an
            # off-host backup-sync token can't also manage users or
            # settings if it were ever leaked. The filename is matched
            # against list_backups()'s own real directory listing rather
            # than trusted from the URL directly, so a crafted filename
            # (e.g. containing "..") can never resolve outside BACKUP_DIR
            # -- it just won't be found.
            actor=self.require(db,"backups:read")
            if not actor:return
            requested_name=path[len("/api/admin/backups/"):]
            match=next((item for item in list_backups() if item["filename"]==requested_name),None)
            if not match:return self.send_json({"error":"Not found"},404)
            file_path=flowops.config.BACKUP_DIR/match["filename"]
            body=file_path.read_bytes()
            self.send_response(200); self.send_header("Content-Type","application/octet-stream")
            self.send_header("Content-Disposition",f'attachment; filename="{match["filename"]}"')
            self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        return NOT_HANDLED

    def _post_admin_db(self, db, path, payload):
        if path=="/api/admin/backups":
            actor=self.require(db,"admin:access")
            if not actor:return
            try: result=backup_database()
            except Exception as exc:return self.send_json({"error":f"Backup failed: {exc}"},500)
            append_audit(db,None,"admin.backup_created",result["filename"],actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":result},201)
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
            allowed={"workspace_name","timezone","require_approval","session_hours","serviceops_enabled","directory_enabled","directory_domain","audit_retention_days","dashboard_email_frequency","dashboard_email_hour","dashboard_email_recipients"}
            if "dashboard_email_frequency" in payload and payload["dashboard_email_frequency"] not in {"off","daily","weekly"}:
                return self.send_json({"error":"dashboard_email_frequency must be off, daily, or weekly"},400)
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
            db.execute("UPDATE audit_purge_lock SET active=1 WHERE id=1")
            db.execute(f"DELETE FROM audit WHERE id IN ({','.join('?'*len(purge_ids))})",purge_ids)
            db.execute("UPDATE audit_purge_lock SET active=0 WHERE id=1")
            db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(actor["instance_id"],"audit_retention_checkpoint",checkpoint,now()))
            append_audit(db,None,"audit.retention_purged",f"Purged {len(purge_ids)} events older than {retention_days} days",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"purged":len(purge_ids)}})
        return NOT_HANDLED

    def _delete_admin(self, path, parts, parsed):
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
        return NOT_HANDLED
