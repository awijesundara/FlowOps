"""Sign-in, sign-out, invitations, password reset, directory sign-in and OIDC."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import flowops.config
import flowops.mail
import flowops.net
import flowops.ratelimit
from flowops.audit import append_audit
from flowops.config import DEFAULT_INSTANCE_SLUG, ROLE_PERMISSIONS
from flowops.crypto import password_hash, password_valid
from flowops.db import connect, instance_settings, integration_credential, now
from flowops.mail import mail_configuration
from flowops.ratelimit import LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS, LOGIN_RATE_WINDOW_PER_IP_SECONDS, check_rate_limit, rate_limit_lockout, record_rate_limit_failure, reset_rate_limit_failures
from flowops.sso import _b64url_decode, _cf_access_jwks, _fetch_jwks, oidc_discovery_document, verify_cf_access_jwt, verify_oidc_id_token
from flowops.web.base import BaseHandler, NOT_HANDLED


class AuthRoutes(BaseHandler):
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

    # --- OIDC SSO (authorization-code + PKCE) ----------------------------
    # State is stored in the shared `oidc_states` table (not an in-memory
    # dict) because the MicroK8s deployment runs 2 pod replicas behind one
    # Service with no guaranteed session affinity between /auth/oidc/login
    # and /auth/oidc/callback -- both pods share the same SQLite file, so
    # a DB row is replica-safe where an in-process dict would not be.
    def oidc_login(self):
        with connect() as db:
            instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()
            if not instance: return self.send_json({"error":"FlowOps instance is unavailable"},503)
            values=instance_settings(db,instance["id"])
            if values.get("oidc_enabled","false")!="true": return self.send_json({"error":"OIDC sign-in is not enabled"},404)
            issuer=values.get("oidc_url","").strip().rstrip("/"); client_id=values.get("oidc_client_id","").strip()
            if not issuer or not client_id: return self.send_json({"error":"OIDC is enabled but not fully configured"},503)
            try: document=oidc_discovery_document(issuer)
            except Exception as exc: return self.send_json({"error":f"OIDC discovery failed: {exc}"},502)
            redirect_to=urllib.parse.urlparse(self.path).query
            qs=urllib.parse.parse_qs(redirect_to)
            requested=(qs.get("redirect_to") or ["/"])[0]
            redirect_target=requested if requested.startswith("/") and not requested.startswith("//") else "/"
            code_verifier=secrets.token_urlsafe(64)
            code_challenge=base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
            state=secrets.token_urlsafe(24)
            db.execute("DELETE FROM oidc_states WHERE expires_at<=?",(int(time.time()),))
            db.execute("INSERT INTO oidc_states(state,code_verifier,redirect_to,instance_id,expires_at,created_at) VALUES(?,?,?,?,?,?)",(state,code_verifier,redirect_target,instance["id"],int(time.time())+600,now()))
            db.commit()
            public_url=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
            redirect_uri=f"{public_url}/auth/oidc/callback"
            params={"response_type":"code","client_id":client_id,"redirect_uri":redirect_uri,"scope":"openid email profile","state":state,"code_challenge":code_challenge,"code_challenge_method":"S256"}
            auth_url=document["authorization_endpoint"]+"?"+urllib.parse.urlencode(params)
        self.send_response(302); self.send_header("Location",auth_url); self.end_headers()

    def oidc_callback(self):
        query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        provider_error=(query.get("error") or [""])[0]
        if provider_error: return self.send_json({"error":f"OIDC provider returned an error: {provider_error}"},400)
        code=(query.get("code") or [""])[0]; state=(query.get("state") or [""])[0]
        if not code or not state: return self.send_json({"error":"Missing code or state on OIDC callback"},400)
        with connect() as db:
            row=db.execute("SELECT * FROM oidc_states WHERE state=? AND expires_at>?",(state,int(time.time()))).fetchone()
            db.execute("DELETE FROM oidc_states WHERE state=?",(state,)); db.commit()
            if not row: return self.send_json({"error":"OIDC sign-in expired or was already used. Try signing in again."},400)
            instance_id=row["instance_id"]; values=instance_settings(db,instance_id)
            issuer=values.get("oidc_url","").strip().rstrip("/"); client_id=values.get("oidc_client_id","").strip()
            if not issuer or not client_id: return self.send_json({"error":"OIDC is not fully configured"},503)
            try: client_secret,_=integration_credential(db,instance_id,"oidc")
            except RuntimeError as exc: return self.send_json({"error":str(exc)},503)
            try: document=oidc_discovery_document(issuer)
            except Exception as exc: return self.send_json({"error":f"OIDC discovery failed: {exc}"},502)
            public_url=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
            redirect_uri=f"{public_url}/auth/oidc/callback"
            token_body=urllib.parse.urlencode({"grant_type":"authorization_code","code":code,"redirect_uri":redirect_uri,"client_id":client_id,"client_secret":client_secret,"code_verifier":row["code_verifier"]}).encode()
            try:
                with flowops.net.safe_urlopen(document["token_endpoint"],data=token_body,headers={"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},method="POST",timeout=8,allow_private_network=True) as response:
                    token_response=json.loads(response.read())
            except RuntimeError as exc: return self.send_json({"error":f"OIDC token exchange failed: {exc}"},502)
            id_token=token_response.get("id_token")
            if not id_token: return self.send_json({"error":"OIDC provider did not return an id_token"},502)
            claims=verify_oidc_id_token(document.get("jwks_uri",""),issuer,client_id,id_token)
            if not claims or not claims.get("email"): return self.send_json({"error":"Could not verify the OIDC identity token"},401)
            email=str(claims["email"]).strip().lower()
            user=db.execute("SELECT * FROM users WHERE LOWER(email)=? AND active=1",(email,)).fetchone()
            if not user: return self.send_json({"error":"No active FlowOps account matches your OIDC identity"},404)
            hours=max(1,min(24,int(instance_settings(db,user["instance_id"]).get("session_hours","8")))); session_seconds=hours*3600
            raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+session_seconds
            db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),)); db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now(),self.client_address[0][:64],self.headers.get("User-Agent","")[:300]))
            db.execute("UPDATE users SET last_login_at=? WHERE id=?",(now(),user["id"]))
            append_audit(db,None,"auth.oidc_login",f"{user['username']} signed in via OIDC ({email})",user["display_name"],user["instance_id"]); db.commit()
            redirect_to=row["redirect_to"] or "/"
        self.send_response(302)
        self.send_header("Location",redirect_to)
        self.send_header("Set-Cookie",self.session_cookie(raw,session_seconds))
        self.end_headers()

    def test_oidc_integration(self, db, actor, overrides=None):
        overrides=overrides or {}
        values=instance_settings(db,actor["instance_id"])
        issuer=str(overrides.get("url") or values.get("oidc_url","")).strip().rstrip("/")
        client_id=str(overrides.get("client_id") or values.get("oidc_client_id","")).strip()
        if not issuer:return self.send_json({"error":"Configure the OIDC issuer URL first"},400)
        if not client_id:return self.send_json({"error":"Configure the OIDC client ID first"},400)
        started=time.monotonic()
        try:
            document=oidc_discovery_document(issuer)
        except Exception as exc:return self.send_json({"error":f"OIDC discovery failed: {exc}"},502)
        missing=[key for key in ("authorization_endpoint","token_endpoint","jwks_uri","issuer") if not document.get(key)]
        if missing:return self.send_json({"error":f"OIDC discovery document is missing: {', '.join(missing)}"},502)
        if document["issuer"].rstrip("/")!=issuer:return self.send_json({"error":f"Discovery document issuer ({document['issuer']}) does not match the configured issuer"},502)
        try:
            keys=_fetch_jwks(document["jwks_uri"])
        except Exception as exc:return self.send_json({"error":f"JWKS fetch failed: {exc}"},502)
        if not keys:return self.send_json({"error":"OIDC provider's JWKS contains no usable RSA keys"},502)
        result={"ok":True,"provider":"oidc","latency_ms":round((time.monotonic()-started)*1000),"message":"OIDC discovery document and JWKS verified","authorization_endpoint":document["authorization_endpoint"],"rsa_keys_found":len(keys)}
        append_audit(db,None,"integration.tested",f"oidc: {result['message']}",actor["display_name"],actor["instance_id"]);db.commit()
        return self.send_json({"data":result})

    def _get_auth(self, path):
        if path=="/auth/oidc/login": return self.oidc_login()
        if path=="/auth/oidc/callback": return self.oidc_callback()
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
        return NOT_HANDLED

    def _get_auth_db(self, db, path):
        if path=="/api/auth/me":
            user=self.current_user(db)
            if not user: return self.send_json({"error":"Authentication required"},401)
            raw_widgets=user.get("dashboard_widgets")
            try: widgets=json.loads(raw_widgets) if raw_widgets else None
            except json.JSONDecodeError: widgets=None
            user["dashboard_widgets"]=widgets if widgets is not None else ["runbook_activity","today_readiness","delay_summary"]
            settings=instance_settings(db,user["instance_id"])
            return self.send_json({"data":{"user":user,"settings":settings}})
        return NOT_HANDLED

    def _post_auth_db(self, db, path, payload):
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
        if path=="/api/auth/sso":
            token=self.headers.get("Cf-Access-Jwt-Assertion","")
            claims=verify_cf_access_jwt(token) if token else None
            if os.getenv("FLOWOPS_SSO_DEBUG")=="1":
                debug={"header_present":bool(token),"header_len":len(token)}
                if token:
                    try:
                        h,p,_=token.split(".")
                        debug["unverified_header"]=json.loads(_b64url_decode(h))
                        uc=json.loads(_b64url_decode(p))
                        debug["unverified_claims"]={"email":uc.get("email"),"aud":uc.get("aud"),"exp":uc.get("exp"),"now":int(time.time())}
                    except Exception as exc: debug["decode_error"]=repr(exc)
                debug["verified"]=bool(claims); debug["team_domain"]=flowops.config.CF_ACCESS_TEAM_DOMAIN; debug["configured_aud"]=flowops.config.CF_ACCESS_AUD
                try:
                    jwks_keys=_cf_access_jwks(); debug["jwks_kids"]=list(jwks_keys.keys())
                except Exception as exc: debug["jwks_error"]=repr(exc)
                print("FLOWOPS_SSO_DEBUG",json.dumps(debug),flush=True)
            if not claims or not claims.get("email"):
                return self.send_json({"error":"No verified Cloudflare Access identity on this request"},401)
            email=str(claims["email"]).strip().lower()
            user=db.execute("SELECT * FROM users WHERE LOWER(email)=? AND active=1",(email,)).fetchone()
            if not user:
                return self.send_json({"error":"No active FlowOps account matches your Cloudflare Access identity"},404)
            hours=max(1,min(24,int(instance_settings(db,user["instance_id"]).get("session_hours","8")))); session_seconds=hours*3600
            raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+session_seconds
            db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),)); db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now(),self.client_address[0][:64],self.headers.get("User-Agent","")[:300])); db.execute("UPDATE users SET last_login_at=? WHERE id=?",(now(),user["id"])); append_audit(db,None,"auth.sso_login",f"{user['username']} signed in via Cloudflare Access ({email})",user["display_name"],user["instance_id"]); db.commit()
            safe={k:user[k] for k in ("id","username","display_name","email","role","team")}; safe["permissions"]=sorted(ROLE_PERMISSIONS[user["role"]]); safe["csrf_token"]=csrf
            return self.send_json({"data":safe},headers={"Set-Cookie":self.session_cookie(raw,session_seconds)})
        if path=="/api/auth/login":
            username=str(payload.get("username","")).strip(); password=str(payload.get("password",""));source=str(payload.get("source","local")).lower()
            # Every other password/token entry point in this file is rate
            # limited (API tokens via check_rate_limit, password reset
            # implicitly single-use); this one previously had only a
            # fixed 200ms sleep on failure -- serial, not per-caller, so
            # ThreadingHTTPServer's one-thread-per-connection model let an
            # attacker trivially parallelize past it. Two independent
            # gates: per-IP is a simple attempt-based flood limit (catches
            # one attacker trying many usernames); per-account is a
            # failure-based lockout (catches distributed attempts against
            # one account from many IPs) -- it must only accumulate on
            # actual failures, never on successes, or a legitimately busy
            # user gets locked out of their own account.
            account_key=f"login-fail:{username.lower()}"
            retry_after=(check_rate_limit(f"login-ip:{self.client_address[0][:64]}",limit=flowops.ratelimit.LOGIN_RATE_LIMIT_PER_IP,window_seconds=LOGIN_RATE_WINDOW_PER_IP_SECONDS)
                         or rate_limit_lockout(account_key,flowops.ratelimit.LOGIN_RATE_LIMIT_PER_ACCOUNT,LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS))
            if retry_after:
                return self.send_json({"error":"Too many sign-in attempts. Try again later."},429,headers={"Retry-After":str(retry_after)})
            instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()
            if source=="ldap":
                if not instance:return self.send_json({"error":"FlowOps instance is unavailable"},503)
                try:remote=self.serviceops_directory_authenticate(db,instance["id"],username,password)
                except RuntimeError as exc:record_rate_limit_failure(account_key,LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS);time.sleep(.2);return self.send_json({"error":str(exc)},401)
                username=str(remote["username"]);user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=? AND active=1",(username,instance["id"])).fetchone()
                if not user:
                    display=str(remote.get("name") or username)[:160];db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,"","Member","",password_hash(secrets.token_urlsafe(48)),now(),instance["id"]));user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=?",(username,instance["id"])).fetchone()
            else:
                user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1",(username,username)).fetchone()
                if not user or not password_valid(password,user["password_hash"]):record_rate_limit_failure(account_key,LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS);time.sleep(.2);return self.send_json({"error":"Invalid username or password"},401)
            reset_rate_limit_failures(account_key)
            hours=max(1,min(24,int(instance_settings(db,user["instance_id"]).get("session_hours","8")))); session_seconds=hours*3600
            raw=secrets.token_urlsafe(36); csrf=secrets.token_urlsafe(24); expires=int(time.time())+session_seconds
            db.execute("DELETE FROM sessions WHERE expires_at<=?",(int(time.time()),)); db.execute("INSERT INTO sessions(token_hash,csrf_token,user_id,expires_at,created_at,ip_address,user_agent) VALUES(?,?,?,?,?,?,?)",(hashlib.sha256(raw.encode()).hexdigest(),csrf,user["id"],expires,now(),self.client_address[0][:64],self.headers.get("User-Agent","")[:300])); db.execute("UPDATE users SET last_login_at=? WHERE id=?",(now(),user["id"])); append_audit(db,None,"auth.login",f"{user['username']} signed in",user["display_name"],user["instance_id"]); db.commit()
            safe={k:user[k] for k in ("id","username","display_name","email","role","team")}; safe["permissions"]=sorted(ROLE_PERMISSIONS[user["role"]]); safe["csrf_token"]=csrf
            return self.send_json({"data":safe},headers={"Set-Cookie":self.session_cookie(raw,session_seconds)})
        if path=="/api/auth/logout":
            user=self.current_user(db)
            if user:
                cookies={i.strip().split("=",1)[0]:i.strip().split("=",1)[1] for i in self.headers.get("Cookie","").split(";") if "=" in i}; raw=cookies.get("flowops_session","")
                db.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(raw.encode()).hexdigest(),)); append_audit(db,None,"auth.logout",f"{user['username']} signed out",user["display_name"],user["instance_id"]); db.commit()
            return self.send_json({"data":{"ok":True}},headers={"Set-Cookie":self.session_cookie("",0)})
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
                    try: flowops.mail.send_mail(user["email"],"Reset your FlowOps password",f"Hello {user['display_name']},\n\nReset your FlowOps password within 30 minutes:\n{mail_configuration()['public_url']}/?reset={urllib.parse.quote(raw)}\n\nIf you did not request this, ignore this email.")
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
        return NOT_HANDLED
