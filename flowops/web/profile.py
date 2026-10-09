"""Self-service profile, avatar, password change and push subscriptions."""
from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from flowops import identity, ldap_auth
from flowops.accounts import verify_mfa_code
from flowops.audit import append_audit
from flowops.config import AVATAR_DIR, SUPPORTED_LOCALES
from flowops.crypto import password_hash, password_valid, settings_cipher
from flowops.ratelimit import check_rate_limit
from flowops.db import connect, now, rows
from flowops.push import vapid_keypair
from flowops.web.base import BaseHandler, NOT_HANDLED

PROVIDER_LABELS={"ldap":"your corporate directory","oidc":"your single sign-on provider"}


class ProfileRoutes(BaseHandler):
    def _get_profile(self, path):
        if path.startswith("/avatar/"):
            with connect() as db:
                actor=self.current_user(db)
                if not actor: return self.send_json({"error":"Authentication required"},401)
                try: uid=int(path.rsplit("/",1)[-1])
                except ValueError: return self.send_error(404)
                row=db.execute("SELECT avatar_path FROM users WHERE id=? AND instance_id=?",(uid,actor["instance_id"])).fetchone()
            if not row or not row["avatar_path"]: return self.send_error(404)
            avatar_path=AVATAR_DIR/row["avatar_path"]
            try: data=avatar_path.read_bytes()
            except FileNotFoundError: return self.send_error(404)
            content_type="image/png" if row["avatar_path"].endswith(".png") else "image/jpeg"
            self.send_response(200); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","private, max-age=3600"); self.end_headers(); self.wfile.write(data); return
        if path=="/api/profile/export":
            with connect() as db:
                actor=self.current_user(db)
                if not actor: return self.send_json({"error":"Authentication required"},401)
                profile={k:actor[k] for k in ("id","username","display_name","email","role","team","title","timezone","date_format","created_at","last_login_at") if k in actor.keys()}
                audit_entries=rows(db.execute("SELECT action,detail,created_at FROM audit WHERE actor=? ORDER BY created_at DESC LIMIT 500",(actor["display_name"],)))
                owned_tasks=rows(db.execute("SELECT t.title,t.status,r.name runbook_name FROM tasks t JOIN runbooks r ON r.id=t.runbook_id WHERE t.owner_user_id=? ORDER BY t.id DESC LIMIT 500",(actor["id"],)))
                export={"profile":profile,"audit_history":audit_entries,"assigned_tasks":owned_tasks,"exported_at":now()}
                body=json.dumps(export,indent=2).encode()
                self.send_response(200); self.send_header("Content-Type","application/json; charset=utf-8")
                self.send_header("Content-Disposition",f'attachment; filename="flowops-my-data-{actor["username"]}.json"')
                self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        return NOT_HANDLED

    def _get_profile_db(self, db, path):
        if path=="/api/push/vapid-public-key":
            actor=self.current_user(db)
            if not actor: return self.send_json({"error":"Authentication required"},401)
            _,public_key=vapid_keypair(db,actor["instance_id"]); db.commit()
            return self.send_json({"data":{"public_key":public_key}})
        return NOT_HANDLED

    def _post_profile_db(self, db, path, payload):
        if path=="/api/push/subscribe":
            actor=self.current_user(db)
            if not actor: return self.send_json({"error":"Authentication required"},401)
            if actor.get("auth_method")=="session" and self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
            endpoint=str(payload.get("endpoint","")).strip()
            keys=payload.get("keys") or {}
            p256dh=str(keys.get("p256dh","")).strip(); auth_key=str(keys.get("auth","")).strip()
            if not endpoint or not (endpoint.startswith("http://") or endpoint.startswith("https://")): return self.send_json({"error":"A valid push subscription endpoint is required"},400)
            if not p256dh or not auth_key: return self.send_json({"error":"Subscription is missing its p256dh/auth keys"},400)
            db.execute("INSERT INTO push_subscriptions(user_id,instance_id,endpoint,p256dh,auth,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth=excluded.auth",
                (actor["id"],actor["instance_id"],endpoint[:1000],p256dh[:400],auth_key[:400],now()))
            db.commit()
            return self.send_json({"data":{"ok":True}},201)
        if path=="/api/profile/avatar":
            actor=self.current_user(db)
            if not actor: return self.send_json({"error":"Authentication required"},401)
            if actor.get("auth_method")=="session" and self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
            raw_b64=str(payload.get("avatar_base64",""))
            if "," in raw_b64: raw_b64=raw_b64.split(",",1)[1]
            try: data=base64.b64decode(raw_b64, validate=True)
            except Exception: return self.send_json({"error":"Invalid image data"},400)
            if len(data) > 5*1024*1024: return self.send_json({"error":"Profile picture must be smaller than 5 MB"},400)
            if data[:8]==b"\x89PNG\r\n\x1a\n": ext="png"
            elif data[:3]==b"\xff\xd8\xff": ext="jpg"
            else: return self.send_json({"error":"Profile picture must be a PNG or JPEG image"},400)
            AVATAR_DIR.mkdir(parents=True, exist_ok=True)
            stored=f"user-{actor['id']}.{ext}"
            (AVATAR_DIR/stored).write_bytes(data)
            db.execute("UPDATE users SET avatar_path=? WHERE id=?",(stored,actor["id"]))
            append_audit(db,None,"profile.avatar_updated","Profile picture updated",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"avatar_path":stored}})
        if path=="/api/profile/change-password":
            actor=self.current_user(db)
            if not actor: return self.send_json({"error":"Authentication required"},401)
            if actor.get("auth_method")=="session" and self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
            current_password=str(payload.get("current_password","")); new_password=str(payload.get("new_password",""))
            user=db.execute("SELECT * FROM users WHERE id=?",(actor["id"],)).fetchone()
            if user["auth_provider"]!="local": return self.send_json({"error":f"Your password is managed by {PROVIDER_LABELS.get(user['auth_provider'],user['auth_provider'])}"},409)
            if not password_valid(current_password,user["password_hash"]): return self.send_json({"error":"Current password is incorrect"},401)
            if len(new_password)<12: return self.send_json({"error":"New password must be at least 12 characters"},400)
            db.execute("UPDATE users SET password_hash=?,auth_version=auth_version+1 WHERE id=?",(password_hash(new_password),actor["id"]))
            current_token=next((item.strip().split("=",1)[1] for item in self.headers.get("Cookie","").split(";") if item.strip().startswith("flowops_session=")),"")
            db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?",(actor["id"],hashlib.sha256(current_token.encode()).hexdigest()))
            append_audit(db,None,"profile.password_changed","Password changed via self-service",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}})
        if path.startswith("/api/profile/mfa/"):
            return self.profile_mfa(db,path.rsplit("/",1)[-1],payload)
        return NOT_HANDLED

    def profile_mfa(self, db, action, payload):
        """Self-service TOTP enrolment: setup (re-authenticate, get a secret)
        -> enable (prove a code, receive backup codes once) -> disable or
        regenerate backup codes (prove a current code)."""
        actor=self.current_user(db)
        if not actor or actor.get("auth_method")!="session": return self.send_json({"error":"Authentication required"},401)
        if self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
        user=db.execute("SELECT * FROM users WHERE id=?",(actor["id"],)).fetchone()
        if user["auth_provider"]=="oidc": return self.send_json({"error":"Multi-factor sign-in for single sign-on accounts is managed by your identity provider"},409)
        retry_after=check_rate_limit(f"mfa-profile:{user['id']}",limit=10,window_seconds=300)
        if retry_after: return self.send_json({"error":"Too many attempts. Try again later."},429,headers={"Retry-After":str(retry_after)})
        if action=="setup":
            if user["mfa_enabled"]: return self.send_json({"error":"Multi-factor sign-in is already on. Turn it off first to enrol a new device."},409)
            if not self.reauthenticate(db,user,str(payload.get("password",""))): return self.send_json({"error":"Your password is incorrect"},401)
            secret=identity.new_totp_secret()
            try: encrypted=settings_cipher().encrypt(secret.encode()).decode()
            except RuntimeError as exc: return self.send_json({"error":str(exc)},503)
            db.execute("UPDATE users SET mfa_pending_secret_encrypted=? WHERE id=?",(encrypted,user["id"])); db.commit()
            return self.send_json({"data":{"secret":secret,"otpauth_uri":identity.totp_uri(secret,user["username"])}})
        if action=="enable":
            if user["mfa_enabled"] or not user["mfa_pending_secret_encrypted"]: return self.send_json({"error":"Start multi-factor setup first"},409)
            secret=settings_cipher().decrypt(user["mfa_pending_secret_encrypted"].encode()).decode()
            step=identity.totp_match(secret,str(payload.get("code","")))
            if step is None: return self.send_json({"error":"That code does not match. Check the time on your device and try again."},400)
            codes=identity.new_backup_codes()
            db.execute("UPDATE users SET mfa_enabled=1,mfa_secret_encrypted=mfa_pending_secret_encrypted,mfa_pending_secret_encrypted=NULL,mfa_backup_codes=?,mfa_last_step=?,auth_version=auth_version+1 WHERE id=?",
                       (json.dumps([identity.hash_backup_code(c) for c in codes]),step,user["id"]))
            append_audit(db,None,"auth.mfa_enabled",f"{user['username']} turned on multi-factor sign-in",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"enabled":True,"backup_codes":codes}})
        if action in {"disable","backup-codes"}:
            if not user["mfa_enabled"]: return self.send_json({"error":"Multi-factor sign-in is not on"},409)
            if not verify_mfa_code(db,user,str(payload.get("code",""))):
                db.commit(); return self.send_json({"error":"Invalid verification code"},400)
            if action=="disable":
                db.execute("UPDATE users SET mfa_enabled=0,mfa_secret_encrypted=NULL,mfa_backup_codes=NULL,mfa_last_step=NULL,auth_version=auth_version+1 WHERE id=?",(user["id"],))
                append_audit(db,None,"auth.mfa_disabled",f"{user['username']} turned off multi-factor sign-in",actor["display_name"],actor["instance_id"]); db.commit()
                return self.send_json({"data":{"enabled":False}})
            codes=identity.new_backup_codes()
            db.execute("UPDATE users SET mfa_backup_codes=? WHERE id=?",(json.dumps([identity.hash_backup_code(c) for c in codes]),user["id"]))
            append_audit(db,None,"auth.mfa_backup_codes_regenerated",f"{user['username']} generated new backup codes",actor["display_name"],actor["instance_id"]); db.commit()
            return self.send_json({"data":{"enabled":True,"backup_codes":codes}})
        return self.send_json({"error":"Not found"},404)

    def reauthenticate(self, db, user, password) -> bool:
        """Prove the signed-in person knows their password: the local hash, or
        a fresh directory bind for directory accounts."""
        if user["auth_provider"]=="local": return password_valid(password,user["password_hash"])
        if user["auth_provider"]=="ldap":
            config=ldap_auth.directory_config(db,user["instance_id"])
            if not ldap_auth.enabled(config): return False
            try: return ldap_auth.authenticate(config,user["username"],password).user is not None
            except ldap_auth.DirectoryError: return False
        return False

    def _patch_profile(self, path, parts, payload):
        if parts==["api","profile"]:
            with connect() as db:
                actor=self.current_user(db)
                if not actor: return self.send_json({"error":"Authentication required"},401)
                if actor.get("auth_method")=="session" and self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
                editable={"display_name":120,"email":180,"title":120}
                sets=[]; values=[]
                for field,limit in editable.items():
                    if field not in payload: continue
                    value=str(payload[field]).strip()[:limit]
                    if field=="display_name" and not value: return self.send_json({"error":"Display name is required"},400)
                    sets.append(f"{field}=?"); values.append(value)
                if "timezone" in payload:
                    tz=str(payload["timezone"]).strip()[:80] or "Asia/Tokyo"
                    sets.append("timezone=?"); values.append(tz)
                if "date_format" in payload:
                    date_format=str(payload["date_format"]).strip()
                    if date_format not in {"system","day_first","month_first"}: return self.send_json({"error":"Invalid date format"},400)
                    sets.append("date_format=?"); values.append(date_format)
                if "locale" in payload:
                    # Unsupported locales fall back to "en" rather than erroring --
                    # matches the same fallback the frontend's t() helper applies.
                    locale=str(payload["locale"]).strip()
                    if locale not in SUPPORTED_LOCALES: locale="en"
                    sets.append("locale=?"); values.append(locale)
                if sets:
                    values.append(actor["id"])
                    db.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?",values)
                    append_audit(db,None,"profile.updated","Self-service profile updated",actor["display_name"],actor["instance_id"])
                    db.commit()
                updated=db.execute("SELECT * FROM users WHERE id=?",(actor["id"],)).fetchone()
                safe={k:updated[k] for k in ("id","username","display_name","email","role","team","title","timezone","date_format","locale","avatar_path")}
                return self.send_json({"data":safe})
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
        return NOT_HANDLED

    def _delete_profile(self, path, parts, parsed):
        if path=="/api/push/subscribe":
            with connect() as db:
                actor=self.current_user(db)
                if not actor: return self.send_json({"error":"Authentication required"},401)
                if actor.get("auth_method")=="session" and self.headers.get("X-CSRF-Token","") != actor["csrf_token"]: return self.send_json({"error":"Invalid or missing CSRF token"},403)
                endpoint=(urllib.parse.parse_qs(parsed.query).get("endpoint") or [""])[0]
                db.execute("DELETE FROM push_subscriptions WHERE endpoint=? AND user_id=?",(endpoint,actor["id"])); db.commit()
                return self.send_json({"data":{"ok":True}})
        return NOT_HANDLED
