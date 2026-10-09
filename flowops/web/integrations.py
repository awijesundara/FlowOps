"""ServiceOps and ServiceNow connections, sync and inbound events."""
from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import flowops.net
import flowops.runbooks
from flowops import identity, ldap_auth
from flowops.audit import append_audit
from flowops.config import MAX_BODY
from flowops.crypto import settings_cipher
from flowops.db import connect, instance_settings, integration_credential, now, rows
from flowops.ratelimit import check_rate_limit
from flowops.runbooks import notify_task_ready
from flowops.serviceops import apply_serviceops_change_event, apply_serviceops_ctask_event, flush_serviceops_writes_for_runbook, serviceops_endpoint, serviceops_http, verify_serviceops_signature
from flowops.web.base import BaseHandler, NOT_HANDLED

# Keycloak/OIDC sign-in policy, stored as oidc_<key>.
OIDC_POLICY_KEYS=("auto_provision","role_claim","role_mappings","team_mappings","default_role","required_acr")


class IntegrationRoutes(BaseHandler):
    def serviceops_request(self, db, instance_id, method, resource, body=None, idempotency_key=None):
        base,token=serviceops_endpoint(db,instance_id)
        return serviceops_http(base,token,method,resource,body,idempotency_key)

    def serviceops_events_status(self, db, instance_id):
        slug=db.execute("SELECT slug FROM instances WHERE id=?",(instance_id,)).fetchone()[0]
        configured=bool(db.execute("SELECT 1 FROM integration_credentials WHERE instance_id=? AND provider='serviceops_events'",(instance_id,)).fetchone())
        last=db.execute("SELECT event_type,outcome,received_at FROM serviceops_inbound_events WHERE instance_id=? ORDER BY received_at DESC,rowid DESC LIMIT 1",(instance_id,)).fetchone()
        public=os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")
        receiver=f"/api/integrations/serviceops/events/{slug}"
        return {"configured":configured,"receiver_path":receiver,"receiver_url":f"{public}{receiver}" if public else None,
                "subscribed_events":["change.state_changed","change_task.state_changed"],
                "last_event":dict(last) if last else None}

    def receive_serviceops_event(self, path):
        """Signed ServiceOps webhook receiver. Authenticated by HMAC, not by
        a session or token, so it sits outside the CSRF-protected API. Only
        events for this FlowOps instance's own runbooks are applied."""
        slug=urllib.parse.unquote(path.rsplit("/",1)[-1]).strip().lower()
        retry=check_rate_limit(f"serviceops-events:{self.client_address[0]}",600,60)
        if retry:return self.send_json({"error":"Too many requests"},429,{"Retry-After":str(retry)})
        try:length=int(self.headers.get("Content-Length","0"))
        except ValueError:return self.send_json({"error":"Invalid Content-Length"},400)
        if length<=0 or length>MAX_BODY:return self.send_json({"error":"A JSON body is required"},400 if length<=0 else 413)
        raw=self.rfile.read(length)
        with connect() as db:
            instance=db.execute("SELECT id FROM instances WHERE slug=? AND active=1",(slug,)).fetchone()
            try:secret=integration_credential(db,instance["id"],"serviceops_events")[0] if instance else ""
            except RuntimeError:secret=""
            if not verify_serviceops_signature(secret,self.headers.get("X-ServiceOps-Timestamp",""),self.headers.get("X-ServiceOps-Signature",""),raw):
                return self.send_json({"error":"Invalid or expired ServiceOps signature"},401)
            try:event=json.loads(raw)
            except (ValueError,UnicodeDecodeError):return self.send_json({"error":"Invalid JSON"},400)
            if not isinstance(event,dict) or not isinstance(event.get("data"),dict):return self.send_json({"error":"Expected a ServiceOps event envelope"},400)
            event_id=str(self.headers.get("X-ServiceOps-Event-ID") or event.get("id") or "").strip()[:64]
            event_type=str(event.get("type") or "").strip()[:80]
            if not event_id or not event_type:return self.send_json({"error":"Event id and type are required"},400)
            instance_id=instance["id"]
            if db.execute("SELECT 1 FROM serviceops_inbound_events WHERE instance_id=? AND event_id=?",(instance_id,event_id)).fetchone():
                return self.send_json({"data":{"event_id":event_id,"duplicate":True}})
            ready=[]
            try:
                if event_type=="change.state_changed":
                    result=apply_serviceops_change_event(db,instance_id,event["data"])
                elif event_type=="change_task.state_changed":
                    result,ready=apply_serviceops_ctask_event(db,instance_id,event["data"])
                else:
                    result={"ignored":True}
            except ValueError as exc:
                db.rollback();return self.send_json({"error":str(exc)},400)
            outcome="ignored" if result.get("ignored") else "applied"
            try:db.execute("INSERT INTO serviceops_inbound_events(instance_id,event_id,event_type,outcome,received_at) VALUES(?,?,?,?,?)",(instance_id,event_id,event_type,outcome,now()))
            except sqlite3.IntegrityError:
                # A concurrent delivery of the same event won the race.
                db.rollback();return self.send_json({"data":{"event_id":event_id,"duplicate":True}})
            db.execute("DELETE FROM serviceops_inbound_events WHERE instance_id=? AND received_at<?",(instance_id,(datetime.now(timezone.utc)-timedelta(days=30)).isoformat(timespec="seconds")))
            db.commit()
            for ready_instance,successor in ready: notify_task_ready(db,ready_instance,successor)
            return self.send_json({"data":{"event_id":event_id,"type":event_type,**result}},202 if outcome=="ignored" else 200)

    def store_serviceops_ticket(self,db,rid,ticket,request_id):
        db.execute("UPDATE runbooks SET serviceops_ticket=?,serviceops_type=?,serviceops_title=?,serviceops_state=?,serviceops_priority=?,serviceops_synced_at=?,serviceops_request_id=?,updated_at=? WHERE id=?",(
          str(ticket.get("number",""))[:40],str(ticket.get("type",""))[:30],str(ticket.get("title",""))[:300],str(ticket.get("state",""))[:80],str(ticket.get("priority",""))[:20],now(),request_id,now(),rid))

    def serviceops_lifecycle(self,db,rid,target):
        rb=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone();ticket_number=str(rb["serviceops_ticket"] or "").strip()
        settings={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=? AND key LIKE 'serviceops_%'",(rb["instance_id"],))}
        if not ticket_number or settings.get("serviceops_enabled","true")!="true" or target not in {"live","complete"}:return None
        if target=="complete": flush_serviceops_writes_for_runbook(db,rid)
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
        created=[];updated=[];previous_id=None
        for ctask in ctasks:
            number=str(ctask.get("number") or "").strip()
            if not number: continue
            team=str(ctask.get("assignmentGroup") or "")[:120]
            assignee=str(ctask.get("assignee") or "")[:120]
            description=str(ctask.get("workNotes") or "")[:2000]
            title=str(ctask.get("title") or number)[:200]
            if number in existing:
                task_id=existing[number]
                db.execute("UPDATE tasks SET title=?,description=?,owner=?,serviceops_ctask_team=? WHERE id=?",
                    (title,description,assignee,team,task_id))
                updated.append(task_id);previous_id=task_id;continue
            max_order+=1
            cur=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,serviceops_ctask_team,duration,status,sort_order,serviceops_ctask) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (rid,title,description,"Change tasks",assignee,team,15,"pending",max_order,number))
            task_id=cur.lastrowid;created.append(task_id)
            if previous_id: db.execute("INSERT OR IGNORE INTO dependencies(task_id,depends_on_id) VALUES(?,?)",(task_id,previous_id))
            previous_id=task_id
        if created: append_audit(db,rid,"serviceops.ctasks_imported",f"Imported {len(created)} change task(s) from {ticket_number}")
        if updated: append_audit(db,rid,"serviceops.ctasks_synced",f"Updated {len(updated)} change task(s) from {ticket_number}")
        return created

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
        doc=flowops.runbooks.runbook_document(db,rid);db.commit()
        return self.send_json({"data":doc,"serviceops":remote,"request_id":request_id,"ctasks_imported":len(created)})

    # --- ServiceNow change-tracking connector ---------------------------
    # Modeled on the ServiceOps connector's shape above, not copied: the
    # credential store, response envelope, and state model all differ.
    # Credential storage reuses the existing integration_credentials table
    # (provider='servicenow') -- the same one-secret-per-provider model
    # ServiceOps already uses -- rather than a named connection (deferred,
    # see PRODUCT_BACKLOG.md Epic 3.1). ServiceNow's Table API uses Basic
    # Auth (username + password, not a bearer token); the password is the
    # value stored in integration_credentials, the username is a plain
    # instance_settings value (servicenow_username) since it isn't secret.
    SERVICENOW_STATE_MAP = {"live": "-1", "complete": "3"}

    def servicenow_request(self, db, instance_id, method, resource, body=None):
        base_row=db.execute("SELECT value FROM instance_settings WHERE instance_id=? AND key='servicenow_url'",(instance_id,)).fetchone()
        base=(base_row[0] if base_row else "").rstrip("/")
        username_row=db.execute("SELECT value FROM instance_settings WHERE instance_id=? AND key='servicenow_username'",(instance_id,)).fetchone()
        username=username_row[0] if username_row else ""
        password,_=integration_credential(db,instance_id,"servicenow")
        if not base or not username or not password:
            raise RuntimeError("Configure the ServiceNow URL, username, and password in Administration → Connections")
        encoded=json.dumps(body).encode() if body is not None else None
        auth=base64.b64encode(f"{username}:{password}".encode()).decode()
        headers={"Authorization":f"Basic {auth}","Accept":"application/json"}
        if encoded is not None: headers["Content-Type"]="application/json"
        try:
            response=flowops.net.safe_urlopen(f"{base}/api/now/table/{resource.lstrip('/')}",data=encoded,headers=headers,method=method,timeout=10,allow_private_network=True)
        except RuntimeError as exc:
            raise RuntimeError(f"ServiceNow is unreachable: {exc}") from exc
        with response:
            body_bytes=response.read()
            if response.status>=400:
                raise RuntimeError(f"ServiceNow returned HTTP {response.status}")
            try: document=json.loads(body_bytes)
            except json.JSONDecodeError as exc: raise RuntimeError("ServiceNow returned invalid JSON") from exc
            return document.get("result",document)

    def store_servicenow_ticket(self, db, rid, ticket):
        db.execute("UPDATE runbooks SET servicenow_change_number=?,servicenow_sys_id=?,servicenow_state=?,servicenow_synced_at=?,updated_at=? WHERE id=?",
            (str(ticket.get("number",""))[:40],str(ticket.get("sys_id",""))[:40],str(ticket.get("state",""))[:20],now(),now(),rid))

    def apply_servicenow_sync(self, db, rid, change_number):
        rb=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone()
        result=self.servicenow_request(db,rb["instance_id"],"GET",f"change_request?sysparm_query=number={urllib.parse.quote(change_number)}&sysparm_limit=1")
        ticket=(result[0] if isinstance(result,list) and result else result if isinstance(result,dict) else None)
        if not ticket: raise RuntimeError(f"ServiceNow change {change_number} was not found")
        self.store_servicenow_ticket(db,rid,ticket)
        append_audit(db,rid,"servicenow.synced",f"Linked {change_number}")
        return ticket

    def servicenow_lifecycle(self, db, rid, target):
        rb=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone()
        change_number=str(rb["servicenow_change_number"] or "").strip()
        settings={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=? AND key LIKE 'servicenow_%'",(rb["instance_id"],))}
        if not change_number or settings.get("servicenow_enabled","false")!="true" or target not in self.SERVICENOW_STATE_MAP: return None
        should_update=(target=="live" and settings.get("servicenow_sync_on_live","true")=="true") or (target=="complete" and settings.get("servicenow_sync_on_complete","true")=="true")
        if not should_update: return None
        sys_id=rb["servicenow_sys_id"]
        if not sys_id:
            ticket=self.apply_servicenow_sync(db,rid,change_number); sys_id=ticket.get("sys_id")
        desired_state=self.SERVICENOW_STATE_MAP[target]
        ticket=self.servicenow_request(db,rb["instance_id"],"PATCH",f"change_request/{sys_id}",{"state":desired_state})
        self.store_servicenow_ticket(db,rid,ticket)
        append_audit(db,rid,"servicenow.lifecycle",f"{change_number} → state {desired_state}","FlowOps API")
        return {"ticket":ticket}

    def sync_servicenow(self, db, rid, payload):
        rb=db.execute("SELECT servicenow_change_number FROM runbooks WHERE id=?",(rid,)).fetchone()
        change_number=str(payload.get("ticket") or (rb["servicenow_change_number"] if rb else "") or "").strip()
        if not change_number: return self.send_json({"error":"Link a ServiceNow change number first"},400)
        try:
            ticket=self.apply_servicenow_sync(db,rid,change_number)
        except RuntimeError as exc: return self.send_json({"error":str(exc)},502)
        doc=flowops.runbooks.runbook_document(db,rid);db.commit()
        return self.send_json({"data":doc,"servicenow":ticket})

    def test_servicenow_integration(self, db, actor, overrides=None):
        overrides=overrides or {}
        values=instance_settings(db,actor["instance_id"])
        base=str(overrides.get("url") or values.get("servicenow_url","")).strip().rstrip("/")
        username=str(overrides.get("username") or values.get("servicenow_username","")).strip()
        password=str(overrides.get("credential") or "").strip()
        testing_unsaved_credential=bool(password)
        if not password:
            try:password,_=integration_credential(db,actor["instance_id"],"servicenow")
            except RuntimeError as exc:return self.send_json({"error":str(exc)},503)
        if not base:return self.send_json({"error":"Configure the ServiceNow instance URL first"},400)
        if not username:return self.send_json({"error":"Configure the ServiceNow username first"},400)
        if not password:return self.send_json({"error":"Paste a ServiceNow password, save the connection, then test again"},400)
        auth=base64.b64encode(f"{username}:{password}".encode()).decode()
        headers={"Accept":"application/json","Authorization":f"Basic {auth}"}
        started=time.monotonic()
        try:
            response=flowops.net.safe_urlopen(f"{base}/api/now/table/change_request?sysparm_limit=1",headers=headers,timeout=8,allow_private_network=True)
        except RuntimeError as exc:
            return self.send_json({"error":str(exc)},502)
        with response:
            if response.status in (401,403):return self.send_json({"error":"ServiceNow rejected the username/password. Verify the account has read access to change_request."},502)
            if response.status>=400:return self.send_json({"error":f"ServiceNow returned HTTP {response.status}"},502)
            try: document=json.loads(response.read())
            except json.JSONDecodeError:return self.send_json({"error":"ServiceNow returned invalid JSON"},502)
            if "result" not in document:return self.send_json({"error":"ServiceNow returned an incompatible Table API response"},502)
        result={"ok":True,"provider":"servicenow","latency_ms":round((time.monotonic()-started)*1000),"message":"ServiceNow Table API verified","credential_configured":True,"tested_unsaved_credential":testing_unsaved_credential}
        append_audit(db,None,"integration.tested",f"servicenow: {result['message']}",actor["display_name"],actor["instance_id"]);db.commit()
        return self.send_json({"data":result})

    def test_ldap_integration(self, db, actor, overrides=None):
        started=time.monotonic()
        config=ldap_auth.directory_config(db,actor["instance_id"],overrides)
        if not config.get("url","").strip():return self.send_json({"error":"Enter the directory server URL first"},400)
        try:result=ldap_auth.test_connection(config)
        except ldap_auth.DirectoryError as exc:return self.send_json({"error":str(exc)},502)
        result.update({"provider":"ldap","latency_ms":round((time.monotonic()-started)*1000),"tested_unsaved_credential":bool((overrides or {}).get("credential"))})
        append_audit(db,None,"integration.tested",f"ldap: {result['message']}",actor["display_name"],actor["instance_id"]);db.commit()
        return self.send_json({"data":result})

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

    def _get_integrations_db(self, db, path):
        if path=="/api/admin/integrations":
            actor=self.require(db,"admin:settings")
            if not actor: return
            values=instance_settings(db,actor["instance_id"])
            try:serviceops_token,serviceops_source=integration_credential(db,actor["instance_id"],"serviceops")
            except RuntimeError:serviceops_token,serviceops_source="","Encrypted credential unavailable"
            try:servicenow_token,servicenow_source=integration_credential(db,actor["instance_id"],"servicenow")
            except RuntimeError:servicenow_token,servicenow_source="","Encrypted credential unavailable"
            try:oidc_token,oidc_source=integration_credential(db,actor["instance_id"],"oidc")
            except RuntimeError:oidc_token,oidc_source="","Encrypted credential unavailable"
            try:ldap_token,ldap_source=integration_credential(db,actor["instance_id"],"ldap")
            except RuntimeError:ldap_token,ldap_source="","Encrypted credential unavailable"
            data={
              "serviceops":{"enabled":values.get("serviceops_enabled","true"),"url":values.get("serviceops_url",os.getenv("SERVICEOPS_URL","")),"credential_configured":bool(serviceops_token),"credential_source":serviceops_source,"credential_editable":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"sync_on_live":values.get("serviceops_sync_on_live","true"),"sync_on_complete":values.get("serviceops_sync_on_complete","true"),"require_approved":values.get("serviceops_require_approved","true"),"trigger_workflow":values.get("serviceops_trigger_workflow","false"),"api_version":"v1","required_scopes":["tickets:read","tickets:update","workflows:execute"]},
              "servicenow":{"enabled":values.get("servicenow_enabled","false"),"url":values.get("servicenow_url",""),"username":values.get("servicenow_username",""),"credential_configured":bool(servicenow_token),"credential_source":servicenow_source,"credential_editable":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"sync_on_live":values.get("servicenow_sync_on_live","true"),"sync_on_complete":values.get("servicenow_sync_on_complete","true")},
              "oidc":{"enabled":values.get("oidc_enabled","false"),"url":values.get("oidc_url",""),"client_id":values.get("oidc_client_id",""),"credential_configured":bool(oidc_token),"credential_source":oidc_source,"credential_editable":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY")),"login_url":"/auth/oidc/login",
                      **{key:values.get(f"oidc_{key}","") for key in OIDC_POLICY_KEYS},"redirect_uri":os.getenv("FLOWOPS_PUBLIC_URL","").strip().rstrip("/")+"/auth/oidc/callback"},
              "ldap":{**{key:values.get(f"ldap_{key}","") for key in ldap_auth.SETTING_KEYS},"credential_configured":bool(ldap_token),"credential_source":ldap_source,"credential_editable":bool(os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY"))},
              "local":{"local_auth_enabled":values.get("local_auth_enabled","true"),"login_max_attempts":values.get("login_max_attempts","5"),"login_lockout_minutes":values.get("login_lockout_minutes","15")},
            }
            data["serviceops"]["record_evidence"]=values.get("serviceops_record_evidence","true")
            data["serviceops"]["events"]=self.serviceops_events_status(db,actor["instance_id"])
            counts=db.execute("SELECT SUM(status='pending'),SUM(status='failed'),SUM(status='delivered') FROM serviceops_outbox WHERE instance_id=?",(actor["instance_id"],)).fetchone()
            data["serviceops"]["writeback"]={"pending":counts[0] or 0,"failed":counts[1] or 0,"delivered":counts[2] or 0}
            return self.send_json({"data":data})
        if path=="/api/admin/integrations/serviceops/outbox":
            actor=self.require(db,"admin:settings")
            if not actor: return
            items=rows(db.execute("SELECT o.id,o.runbook_id,r.name runbook_name,o.kind,o.label,o.status,o.attempts,o.last_error,o.created_at,o.delivered_at,o.next_attempt_at FROM serviceops_outbox o LEFT JOIN runbooks r ON r.id=o.runbook_id WHERE o.instance_id=? ORDER BY o.status='delivered',o.id DESC LIMIT 100",(actor["instance_id"],)))
            for item in items:
                item["next_attempt_at"]=datetime.fromtimestamp(item["next_attempt_at"],timezone.utc).isoformat(timespec="seconds") if item["status"]=="pending" else None
            return self.send_json({"data":items})
        return NOT_HANDLED

    def _post_integrations(self, path):
        if path.startswith("/api/integrations/serviceops/events/"): return self.receive_serviceops_event(path)
        return NOT_HANDLED

    def _post_integrations_db(self, db, path, payload):
        outbox_retry=re.fullmatch(r"/api/admin/integrations/serviceops/outbox/(\d+)/retry",path)
        if path=="/api/admin/integrations/serviceops/events-secret":
            actor=self.require(db,"admin:settings")
            if not actor:return
            if payload.get("revoke") is True:
                db.execute("DELETE FROM integration_credentials WHERE instance_id=? AND provider='serviceops_events'",(actor["instance_id"],))
                append_audit(db,None,"serviceops.events_secret_rotated","Inbound ServiceOps event secret revoked",actor["display_name"],actor["instance_id"]);db.commit()
                return self.send_json({"data":self.serviceops_events_status(db,actor["instance_id"])})
            secret=f"whsec_{secrets.token_urlsafe(32)}"
            try:encrypted=settings_cipher().encrypt(secret.encode()).decode()
            except RuntimeError as exc:return self.send_json({"error":str(exc)},503)
            db.execute("INSERT INTO integration_credentials(instance_id,provider,secret_encrypted,updated_by,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id,provider) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_by=excluded.updated_by,updated_at=excluded.updated_at",(actor["instance_id"],"serviceops_events",encrypted,actor["id"],now()))
            append_audit(db,None,"serviceops.events_secret_rotated","Inbound ServiceOps event secret generated",actor["display_name"],actor["instance_id"]);db.commit()
            # Shown once: paste it as the signing secret of the ServiceOps webhook connection.
            return self.send_json({"data":{**self.serviceops_events_status(db,actor["instance_id"]),"secret":secret}},201)
        if outbox_retry:
            actor=self.require(db,"admin:settings")
            if not actor:return
            item=db.execute("SELECT * FROM serviceops_outbox WHERE id=? AND instance_id=?",(int(outbox_retry.group(1)),actor["instance_id"])).fetchone()
            if not item:return self.send_json({"error":"Not found"},404)
            if item["status"]=="delivered":return self.send_json({"error":"This write was already delivered"},409)
            db.execute("UPDATE serviceops_outbox SET status='pending',attempts=0,next_attempt_at=?,last_error=NULL WHERE id=?",(time.time(),item["id"]))
            append_audit(db,item["runbook_id"],"serviceops.writeback_retried",f"{item['label']} requeued by an administrator",actor["display_name"],actor["instance_id"]);db.commit()
            return self.send_json({"data":{"id":item["id"],"status":"pending"}})
        if path in {"/api/admin/integrations","/api/admin/integrations/test"}:
            actor=self.require(db,"admin:settings")
            if not actor:return
            provider=str(payload.get("provider","")).lower()
            if provider not in {"serviceops","servicenow","oidc","ldap"}:return self.send_json({"error":"Provider must be serviceops, servicenow, oidc, or ldap"},400)
            if path.endswith("/test"):
                if provider=="servicenow": return self.test_servicenow_integration(db,actor,payload)
                if provider=="oidc": return self.test_oidc_integration(db,actor,payload)
                if provider=="ldap": return self.test_ldap_integration(db,actor,payload)
                return self.test_integration(db,provider,actor,payload)
            allowed={"enabled","url","sync_on_live","sync_on_complete"}
            if provider=="serviceops": allowed|={"require_approved","trigger_workflow","record_evidence"}
            if provider=="servicenow": allowed|={"username"}
            if provider=="oidc": allowed={"enabled","url","client_id",*OIDC_POLICY_KEYS}
            if provider=="ldap": allowed=set(ldap_auth.SETTING_KEYS)
            try:
                for key in ("role_mappings","team_mappings"):
                    if key in payload and key in allowed:
                        payload[key]=json.dumps(identity.parse_mapping(payload[key] or "{}",key.split("_")[0]))
            except ValueError as exc:return self.send_json({"error":str(exc)},400)
            for key in ("default_role",):
                if key in payload and key in allowed and str(payload[key]) not in identity.ROLE_RANK:return self.send_json({"error":f"Default role must be one of: {', '.join(identity.ROLE_RANK)}"},400)
            if "secret" in payload or "token" in payload:return self.send_json({"error":"Use the one-way credential field; secrets are never returned to the browser"},400)
            submitted=str(payload.get("credential","")).strip();revoke=payload.get("revoke_credential") is True
            if submitted and revoke:return self.send_json({"error":"Set or revoke a credential, not both"},400)
            if submitted:
                try:encrypted=settings_cipher().encrypt(submitted.encode()).decode()
                except RuntimeError as exc:return self.send_json({"error":str(exc)},503)
                db.execute("INSERT INTO integration_credentials(instance_id,provider,secret_encrypted,updated_by,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(instance_id,provider) DO UPDATE SET secret_encrypted=excluded.secret_encrypted,updated_by=excluded.updated_by,updated_at=excluded.updated_at",(actor["instance_id"],provider,encrypted,actor["id"],now()))
            elif revoke:db.execute("DELETE FROM integration_credentials WHERE instance_id=? AND provider=?",(actor["instance_id"],provider))
            if provider=="ldap":
                url=" ".join(ldap_auth.server_uris(str(payload.get("url",""))))
                if url and not all(uri.lower().startswith(("ldap://","ldaps://")) for uri in url.split()):return self.send_json({"error":"Directory server URLs must start with ldap:// or ldaps://"},400)
                for key in ("user_filter","group_search_filter"):
                    if payload.get(key) and not (str(payload[key]).strip().startswith("(") and str(payload[key]).strip().endswith(")")):return self.send_json({"error":"LDAP filters must be wrapped in parentheses"},400)
            else:
                url=str(payload.get("url","")).strip().rstrip("/")
                if url and not (url.startswith("http://") or url.startswith("https://") or url.startswith("mock://")):return self.send_json({"error":"Connection URL must use http or https"},400)
            for key in allowed:
                if key in payload:
                    value=url if key=="url" else str(payload[key]).lower() if isinstance(payload[key],bool) else str(payload[key])
                    limit=8000 if key.endswith("_mappings") else 500
                    if len(value)>limit:return self.send_json({"error":f"{key.replace('_',' ').capitalize()} is too long"},400)
                    db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(actor["instance_id"],f"{provider}_{key}",value,now()))
            credential_action="; credential rotated" if submitted else "; stored credential revoked" if revoke else ""
            append_audit(db,None,"integration.configured",f"{provider} connection policy updated{credential_action}",actor["display_name"],actor["instance_id"]);db.commit()
            return self.send_json({"data":{"ok":True,"provider":provider}})
        return NOT_HANDLED
