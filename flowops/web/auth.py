"""Sign-in, sign-out, invitations, password reset, directory sign-in and OIDC."""
from __future__ import annotations

import base64
import hashlib
import hmac
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
from flowops import identity, ldap_auth
from flowops.accounts import MFA_CHALLENGE_ATTEMPTS, clear_failures, locked_for, provision_external, record_failure, start_mfa_challenge, verify_mfa_code
import flowops.mail
import flowops.net
import flowops.ratelimit
from flowops.audit import append_audit
from flowops.config import DEFAULT_INSTANCE_SLUG
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

    def locked_response(self, user):
        seconds=locked_for(user)
        return self.send_json({"error":"This account is temporarily locked after repeated failed sign-ins. Try again later."},423,headers={"Retry-After":str(seconds)})

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
            state=secrets.token_urlsafe(24); nonce=secrets.token_urlsafe(24)
            db.execute("DELETE FROM oidc_states WHERE expires_at<=?",(int(time.time()),))
            db.execute("INSERT INTO oidc_states(state,code_verifier,redirect_to,instance_id,expires_at,created_at,nonce) VALUES(?,?,?,?,?,?,?)",(state,code_verifier,redirect_target,instance["id"],int(time.time())+600,now(),nonce))
            db.commit()
            public_url=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
            redirect_uri=f"{public_url}/auth/oidc/callback"
            params={"response_type":"code","client_id":client_id,"redirect_uri":redirect_uri,"scope":"openid email profile","state":state,"nonce":nonce,"code_challenge":code_challenge,"code_challenge_method":"S256"}
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
            if not claims or not claims.get("sub"): return self.send_json({"error":"Could not verify the OIDC identity token"},401)
            if row["nonce"] and not hmac.compare_digest(str(claims.get("nonce","")),row["nonce"]):
                return self.send_json({"error":"The OIDC identity token was not issued for this sign-in"},401)
            user,problem=self.oidc_account(db,instance_id,values,issuer,claims)
            if problem:
                append_audit(db,None,"auth.login_blocked",f"OIDC {claims.get('preferred_username') or claims.get('email') or claims['sub']}: {problem}","FlowOps",instance_id); db.commit()
                return self.send_json({"error":"Your identity provider account cannot sign in to FlowOps. Ask an administrator for access."},403)
            safe,cookie=self.start_session(db,user)
            append_audit(db,None,"auth.oidc_login",f"{user['username']} signed in via OIDC ({user['email'] or claims['sub']})",user["display_name"],user["instance_id"]); db.commit()
            redirect_to=row["redirect_to"] or "/"
        self.send_response(302)
        self.send_header("Location",redirect_to)
        self.send_header("Set-Cookie",cookie)
        self.end_headers()

    def oidc_account(self, db, instance_id, values, issuer, claims):
        """(user, None) for a verified OIDC identity, or (None, reason). Applies
        the required assurance level, role/team claim mappings and optional
        account creation (ServiceOps Keycloak parity)."""
        required_acr=values.get("oidc_required_acr","").strip()
        if required_acr and str(claims.get("acr",""))!=required_acr:
            return None,f"assurance level {claims.get('acr') or 'none'} is not {required_acr}"
        try:
            role_map=identity.parse_mapping(values.get("oidc_role_mappings"),"role")
            team_map=identity.parse_mapping(values.get("oidc_team_mappings"),"team")
        except ValueError as exc: return None,f"invalid mapping: {exc}"
        groups=claims
        for part in (values.get("oidc_role_claim") or "realm_access.roles").split("."):
            groups=groups.get(part) if isinstance(groups,dict) else None
        groups=[str(g) for g in groups] if isinstance(groups,list) else []
        default_role=values.get("oidc_default_role") or identity.DEFAULT_EXTERNAL_ROLE
        role,_=identity.mapped_role(groups,role_map,default_role)
        email=str(claims.get("email","")).strip().lower()
        email_verified=claims.get("email_verified",True) is not False
        username=str(claims.get("preferred_username") or (email.split("@")[0] if email else claims["sub"])).strip()[:120]
        user,outcome=provision_external(db,instance_id,"oidc",f"{issuer}|{claims['sub']}",username=username,
            display_name=str(claims.get("name") or "").strip(),email=email if email_verified else "",
            role=role if role_map else None,team=identity.mapped_team(groups,team_map),
            create=values.get("oidc_auto_provision","false")=="true",create_role=role,match_email=email_verified)
        if user is None: return None,outcome
        if locked_for(user): return None,"account is locked"
        if outcome=="created":
            append_audit(db,None,"auth.user_provisioned",f"{user['username']} created from OIDC as {user['role']}","FlowOps",instance_id)
        return user,None

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
                native=values.get("ldap_enabled","false")=="true" and bool(values.get("ldap_url","").strip())
                directory_enabled=native or values.get("directory_enabled","false")=="true"
                domain=(values.get("ldap_domain","") if native else "").strip() or values.get("directory_domain","").strip()
                sources=[{"id":"local","label":"Local account","placeholder":"Username"}]
                if directory_enabled:
                    label=domain or "Corporate directory"
                    placeholder=f"jsmith or jsmith@{domain}" if domain else "jsmith"
                    sources.insert(0,{"id":"ldap","label":label,"placeholder":placeholder})
                sso=None
                if values.get("oidc_enabled","false")=="true" and values.get("oidc_url","").strip() and values.get("oidc_client_id","").strip():
                    sso={"label":"Sign in with single sign-on","url":"/auth/oidc/login"}
                return self.send_json({"data":{"sources":sources,"default":"ldap" if directory_enabled else "local","sso":sso}})
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
            # A verified Access identity is a sign-in shortcut into an existing
            # account, not a bypass of its own controls: lockout and MFA apply.
            if locked_for(user):
                append_audit(db,None,"auth.login_blocked",f"{user['username']}: account locked (Cloudflare Access)","FlowOps",user["instance_id"]); db.commit()
                return self.send_json({"error":"This account is temporarily locked after repeated failed sign-ins. Try again later."},423)
            if user["mfa_enabled"]:
                token=start_mfa_challenge(db,user,"cloudflare_access"); db.commit()
                return self.send_json({"data":{"mfa_required":True,"mfa_token":token}})
            safe,cookie=self.start_session(db,user)
            append_audit(db,None,"auth.sso_login",f"{user['username']} signed in via Cloudflare Access ({email})",user["display_name"],user["instance_id"]); db.commit()
            return self.send_json({"data":safe},headers={"Set-Cookie":cookie})
        if path=="/api/auth/login":
            username=str(payload.get("username","")).strip(); password=str(payload.get("password",""));source=str(payload.get("source","local")).lower()
            # Two in-memory gates before any credential check: a per-IP flood
            # limit (one attacker, many usernames) and a per-name failure
            # limit that also covers names with no FlowOps account. The
            # per-account lockout stored on the user row (login_max_attempts /
            # login_lockout_minutes) survives restarts, like ServiceOps.
            account_key=f"login-fail:{username.lower()}"
            retry_after=(check_rate_limit(f"login-ip:{self.client_address[0][:64]}",limit=flowops.ratelimit.LOGIN_RATE_LIMIT_PER_IP,window_seconds=LOGIN_RATE_WINDOW_PER_IP_SECONDS)
                         or rate_limit_lockout(account_key,flowops.ratelimit.LOGIN_RATE_LIMIT_PER_ACCOUNT,LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS))
            if retry_after:
                return self.send_json({"error":"Too many sign-in attempts. Try again later."},429,headers={"Retry-After":str(retry_after)})
            instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()
            if not instance:return self.send_json({"error":"FlowOps instance is unavailable"},503)
            values=instance_settings(db,instance["id"])
            def failed(row,reason):
                record_rate_limit_failure(account_key,LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS)
                locked=record_failure(db,row) if row else False
                append_audit(db,None,"auth.login_failed",f"{username[:120]} ({source}): {reason}","FlowOps",instance["id"])
                if locked: append_audit(db,None,"auth.account_locked",f"{row['username']} locked after repeated failed sign-ins","FlowOps",row["instance_id"])
                db.commit(); time.sleep(.2)
                return self.send_json({"error":"Invalid username or password"},401)
            if source=="ldap":
                config=ldap_auth.directory_config(db,instance["id"])
                existing=db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND instance_id=? AND auth_provider IN ('ldap','local')",(identity.login_local_part(username),instance["id"])).fetchone()
                if existing and locked_for(existing): return self.locked_response(existing)
                if ldap_auth.enabled(config):
                    try: result=ldap_auth.authenticate(config,username,password)
                    except ldap_auth.DirectoryError as exc:
                        print(json.dumps({"ts":now(),"level":"error","message":f"Directory sign-in unavailable: {exc}"},separators=(",",":")),flush=True)
                        return self.send_json({"error":"The corporate directory is unavailable. Try again shortly."},503)
                    if not result.user: return failed(existing,result.reason)
                    try: roles_configured=bool(identity.parse_mapping(config.get("role_mappings"),"role"))
                    except ValueError: roles_configured=False
                    user,outcome=provision_external(db,instance["id"],"ldap",result.user.dn,username=result.user.username,
                        display_name=result.user.display_name,email=result.user.email,role=result.role if roles_configured else None,
                        team=result.team,create=True,create_role=result.role)
                    if user is None:
                        append_audit(db,None,"auth.login_blocked",f"{result.user.username} (directory): {outcome}","FlowOps",instance["id"]); db.commit()
                        return self.send_json({"error":"Invalid username or password"},401)
                    if outcome=="created":
                        append_audit(db,None,"auth.user_provisioned",f"{user['username']} created from the directory as {user['role']}","FlowOps",instance["id"])
                elif values.get("directory_enabled","false")=="true":
                    try:remote=self.serviceops_directory_authenticate(db,instance["id"],username,password)
                    except RuntimeError as exc:
                        if "unavailable" in str(exc) or "not configured" in str(exc) or "HTTP" in str(exc): return self.send_json({"error":str(exc)},503)
                        return failed(existing,"ServiceOps directory rejected the credentials")
                    username=str(remote["username"]);user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=? AND active=1",(username,instance["id"])).fetchone()
                    if not user:
                        display=str(remote.get("name") or username)[:160];db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",(username,display,"","Member","",password_hash(secrets.token_urlsafe(48)),now(),instance["id"]));user=db.execute("SELECT * FROM users WHERE username=? AND instance_id=?",(username,instance["id"])).fetchone()
                else:
                    return self.send_json({"error":"Directory sign-in is not enabled"},400)
            else:
                user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1",(username,username)).fetchone()
                if user and locked_for(user): return self.locked_response(user)
                if not user or not password_valid(password,user["password_hash"]): return failed(user,"wrong password or unknown account")
                if user["auth_provider"]!="local": return failed(user,f"account signs in through {user['auth_provider']}")
                if values.get("local_auth_enabled","true")!="true" and user["role"]!="Admin":
                    # Local sign-in can be switched off once a directory is in
                    # place; local administrators stay as break-glass accounts.
                    append_audit(db,None,"auth.login_blocked",f"{user['username']}: local sign-in is disabled","FlowOps",user["instance_id"]); db.commit()
                    return self.send_json({"error":"Local sign-in is disabled. Use your directory account."},403)
            reset_rate_limit_failures(account_key)
            clear_failures(db,user["id"])
            if user["mfa_enabled"]:
                token=start_mfa_challenge(db,user,source); db.commit()
                return self.send_json({"data":{"mfa_required":True,"mfa_token":token}})
            safe,cookie=self.start_session(db,user)
            append_audit(db,None,"auth.login",f"{user['username']} signed in"+(" (directory)" if source=="ldap" else ""),user["display_name"],user["instance_id"]); db.commit()
            return self.send_json({"data":safe},headers={"Set-Cookie":cookie})
        if path=="/api/auth/mfa":
            raw=str(payload.get("mfa_token","")); code=str(payload.get("code","")).strip()
            retry_after=check_rate_limit(f"mfa-ip:{self.client_address[0][:64]}",limit=flowops.ratelimit.LOGIN_RATE_LIMIT_PER_IP,window_seconds=LOGIN_RATE_WINDOW_PER_IP_SECONDS)
            if retry_after: return self.send_json({"error":"Too many attempts. Try again later."},429,headers={"Retry-After":str(retry_after)})
            digest=hashlib.sha256(raw.encode()).hexdigest()
            challenge=db.execute("SELECT * FROM mfa_challenges WHERE token_hash=? AND expires_at>?",(digest,int(time.time()))).fetchone() if raw else None
            user=db.execute("SELECT * FROM users WHERE id=? AND active=1",(challenge["user_id"],)).fetchone() if challenge else None
            # A password change, MFA reset or deactivation since the password
            # step voids the half-finished sign-in.
            if not challenge or not user or not user["mfa_enabled"] or user["auth_version"]!=challenge["auth_version"] or locked_for(user):
                if challenge: db.execute("DELETE FROM mfa_challenges WHERE token_hash=?",(digest,)); db.commit()
                return self.send_json({"error":"This sign-in has expired. Sign in again."},401)
            method=verify_mfa_code(db,user,code)
            if not method:
                attempts=challenge["attempts"]+1
                if attempts>=MFA_CHALLENGE_ATTEMPTS: db.execute("DELETE FROM mfa_challenges WHERE token_hash=?",(digest,))
                else: db.execute("UPDATE mfa_challenges SET attempts=? WHERE token_hash=?",(attempts,digest))
                append_audit(db,None,"auth.mfa_failed",f"{user['username']}: invalid verification code","FlowOps",user["instance_id"]); db.commit()
                return self.send_json({"error":"Invalid verification code" if attempts<MFA_CHALLENGE_ATTEMPTS else "Too many invalid codes. Sign in again."},401)
            db.execute("DELETE FROM mfa_challenges WHERE token_hash=?",(digest,))
            safe,cookie=self.start_session(db,user)
            action="auth.sso_login" if challenge["source"]=="cloudflare_access" else "auth.login"
            append_audit(db,None,action,f"{user['username']} signed in with MFA ({method.replace('_',' ')})",user["display_name"],user["instance_id"]); db.commit()
            if method=="backup_code": safe["notice"]="Signed in with a backup code. Generate new codes from your profile."
            return self.send_json({"data":safe},headers={"Set-Cookie":cookie})
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
            requested=str(payload.get("identity","")).strip();user=db.execute("SELECT * FROM users WHERE (username=? OR email=?) AND active=1 AND auth_provider='local'",(requested,requested)).fetchone()
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
            stamp=now();db.execute("UPDATE users SET password_hash=?,auth_version=auth_version+1,failed_login_count=0,locked_until=NULL WHERE id=?",(password_hash(password),reset["user_id"]));db.execute("UPDATE password_resets SET used_at=? WHERE id=?",(stamp,reset["id"]));db.execute("DELETE FROM sessions WHERE user_id=?",(reset["user_id"],));append_audit(db,None,"auth.password_reset_completed",reset["username"],reset["display_name"],reset["instance_id"]);db.commit()
            return self.send_json({"data":{"ok":True}})
        return NOT_HANDLED
