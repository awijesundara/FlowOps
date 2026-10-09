"""Task actions: transitions, checklists, comments, escalation and incidents."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

import flowops.push
import flowops.runbooks
from flowops.audit import append_audit
from flowops.automation import apply_automation_context, automation_context, perform_automation_call, run_automation_task
from flowops.db import connect, now
from flowops.runbooks import COMMUNICATION_TASK_TYPES, apply_custom_field_values, newly_startable_tasks, normalize_checklist, notify_task_ready, owns_runbook, parse_instant, run_communication_task, team_member_user_ids
from flowops.serviceops import queue_serviceops_ctask_writeback
from flowops.web.base import BaseHandler, NOT_HANDLED


class TaskRoutes(BaseHandler):
    def task_extras(self, db: sqlite3.Connection, rid: int, task_type: str, payload: dict[str,Any]) -> dict[str,Any]:
        """Validates the Cutover task-type fields present in a create/edit payload."""
        extras: dict[str,Any]={}
        if "checklist_items" in payload:
            extras["checklist_json"]=json.dumps(normalize_checklist(payload["checklist_items"]))
        if "recipients" in payload: extras["recipients"]=str(payload["recipients"] or "").strip()[:1000]
        if "message" in payload: extras["message"]=str(payload["message"] or "").strip()[:2000]
        if "fixed_start_at" in payload:
            raw=str(payload["fixed_start_at"] or "").strip()
            if raw and not parse_instant(raw): raise ValueError("Fixed start must be an ISO date and time")
            extras["fixed_start_at"]=raw or None
        if "linked_runbook_id" in payload:
            linked=int(payload["linked_runbook_id"]) if payload.get("linked_runbook_id") else None
            if linked is not None:
                instance_id=db.execute("SELECT w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(rid,)).fetchone()[0]
                if linked==rid or not owns_runbook(db,linked,instance_id): raise ValueError("Linked runbook is invalid")
            extras["linked_runbook_id"]=linked
        return extras

    def _post_tasks_db(self, db, path, payload):
        if path.startswith("/api/tasks/") and path.endswith("/test-fire"):
            try: tid=int(path.strip("/").split("/")[2])
            except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
            precheck=self.current_user(db)
            if not precheck: return self.send_json({"error":"Authentication required"},401)
            task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,precheck["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            actor=self.require_scoped_edit(db,runbook_id=task["runbook_id"])
            if not actor:return
            if task["task_type"]!="automation" or not task["automation_url"]:
                return self.send_json({"error":"This task has no automation URL configured"},400)
            context=automation_context(db,task["runbook_id"])
            body=json.dumps({"request_id":f"test-fire-{tid}","task_id":tid,"task_title":task["title"],"test":True}).encode()
            url,body=apply_automation_context(task["automation_url"],body,context)
            headers={"Content-Type":"application/json","X-Request-ID":f"test-fire-{tid}",**context["headers"]}
            status_ok,snippet=perform_automation_call(url,headers,body,timeout=15)
            append_audit(db,task["runbook_id"],"task.automation_test_fired",f"{task['title']}: {'success' if status_ok else 'failed'} ({snippet[:200]})",actor["display_name"]); db.commit()
            return self.send_json({"data":{"ok":status_ok,"result":snippet[:2000]}})
        if path.startswith("/api/tasks/") and path.rsplit("/",1)[-1] in {"checklist","force-start","comments"}:
            try: tid=int(path.strip("/").split("/")[2])
            except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
            action=path.rsplit("/",1)[-1]
            precheck=self.current_user(db)
            if not precheck: return self.send_json({"error":"Authentication required"},401)
            task=db.execute("SELECT t.*,r.status runbook_status FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,precheck["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            if action=="comments":
                actor=self.require(db,"runbooks:view")
                if not actor:return
                body=str(payload.get("body","")).strip()
                if not body: return self.send_json({"error":"Comment is required"},400)
                db.execute("INSERT INTO task_comments(task_id,author,body,created_at) VALUES(?,?,?,?)",(tid,actor["display_name"],body[:2000],now()))
                append_audit(db,task["runbook_id"],"task.commented",f"{task['title']}: {body[:120]}",actor["display_name"])
                doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc},201)
            if action=="force-start":
                # Cutover-style administrator override: start a task its
                # dependencies or fixed start time would otherwise hold back.
                actor=self.require(db,"admin:access")
                if not actor:return
                reason=str(payload.get("reason","")).strip()[:500]
                if not reason: return self.send_json({"error":"A force start requires an audited reason"},400)
                if task["runbook_status"]!="live": return self.send_json({"error":"Tasks can only be executed while the runbook is live"},409)
                if task["status"] not in {"pending","blocked"}: return self.send_json({"error":f"Cannot force start a {task['status']} task"},409)
                if task["task_type"] in {"automation","runbook"}: return self.send_json({"error":"Automation and runbook tasks must be started normally so their side effects run"},400)
                db.execute("UPDATE tasks SET status='running',started_at=COALESCE(started_at,?),force_started=1,force_start_reason=? WHERE id=?",(now(),reason,tid))
                append_audit(db,task["runbook_id"],"task.force_started",f"{task['title']}: {reason}",actor["display_name"])
                doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            if actor["role"]=="Member":
                assigned=task["owner_user_id"]==actor["id"] or (task["owner_team_id"] and actor["id"] in team_member_user_ids(db,task["owner_team_id"]))
                if not assigned:return self.send_json({"error":"Members may only act on tasks assigned to them or their team"},403)
            if task["runbook_status"]!="live": return self.send_json({"error":"Tasks can only be executed while the runbook is live"},409)
            if task["status"] in {"complete","skipped"}: return self.send_json({"error":"This task is already finished"},409)
            items=json.loads(task["checklist_json"]) if task["checklist_json"] else []
            try: index=int(payload.get("index",-1))
            except (TypeError,ValueError): index=-1
            if not 0<=index<len(items): return self.send_json({"error":"Checklist item not found"},404)
            items[index]["done"]=bool(payload.get("done",True))
            db.execute("UPDATE tasks SET checklist_json=? WHERE id=?",(json.dumps(items),tid))
            append_audit(db,task["runbook_id"],"task.checklist_updated",f"{task['title']}: {'✓' if items[index]['done'] else '○'} {items[index]['text']}",actor["display_name"])
            doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
            return self.send_json({"data":doc})
        if path.startswith("/api/tasks/") and path.endswith("/escalate"):
            try: tid=int(path.strip("/").split("/")[2])
            except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
            precheck=self.current_user(db)
            if not precheck: return self.send_json({"error":"Authentication required"},401)
            task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,precheck["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            escalated=1 if payload.get("escalated",True) else 0
            reason=str(payload.get("reason",""))[:500]
            db.execute("UPDATE tasks SET escalated=?,escalation_reason=? WHERE id=?",(escalated,reason if escalated else None,tid))
            detail=f"{task['title']}"+(f": {reason}" if reason else "")
            if escalated: append_audit(db,task["runbook_id"],"task.escalated",detail,actor["display_name"])
            else: append_audit(db,task["runbook_id"],"task.escalation_cleared",detail,actor["display_name"])
            doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
            return self.send_json({"data":doc})
        if path.startswith("/api/tasks/") and path.endswith("/incident"):
            try: tid=int(path.strip("/").split("/")[2])
            except (ValueError,IndexError): return self.send_json({"error":"Not found"},404)
            precheck=self.current_user(db)
            if not precheck: return self.send_json({"error":"Authentication required"},401)
            task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,precheck["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            incident=1 if payload.get("incident",True) else 0
            reason=str(payload.get("reason",""))[:500]
            db.execute("UPDATE tasks SET incident=?,incident_reason=? WHERE id=?",(incident,reason if incident else None,tid))
            detail=f"{task['title']}"+(f": {reason}" if reason else "")
            if incident: append_audit(db,task["runbook_id"],"task.incident_flagged",detail,actor["display_name"])
            else: append_audit(db,task["runbook_id"],"task.incident_cleared",detail,actor["display_name"])
            doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
            return self.send_json({"data":doc})
        return NOT_HANDLED

    def _patch_tasks_tail(self, path, parts, payload):
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
                newly_assigned_user_id=None
                if "owner_user_id" in payload:
                    owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None
                    if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(owner_user_id,actor["instance_id"])).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                    if owner_user_id!=task["owner_user_id"]:
                        changes.append("owner_user_id changed"); sets.append("owner_user_id=?"); values.append(owner_user_id)
                        if owner_user_id: newly_assigned_user_id=owner_user_id
                if "owner_team_id" in payload:
                    owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                    if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,task["runbook_id"])).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                    if owner_team_id!=task["owner_team_id"]: changes.append("owner_team_id changed"); sets.append("owner_team_id=?"); values.append(owner_team_id)
                if "dependency_logic" in payload:
                    dependency_logic=str(payload["dependency_logic"]).strip().lower()
                    if dependency_logic not in ("and","or"): return self.send_json({"error":"Dependency logic must be 'and' or 'or'"},400)
                    if dependency_logic!=task["dependency_logic"]: changes.append(f"dependency_logic: {task['dependency_logic']} → {dependency_logic}"); sets.append("dependency_logic=?"); values.append(dependency_logic)
                try: extras=self.task_extras(db,task["runbook_id"],task["task_type"],payload)
                except ValueError as exc: return self.send_json({"error":str(exc)},400)
                for column,value in extras.items():
                    if value!=task[column]: changes.append(f"{column} changed"); sets.append(f"{column}=?"); values.append(value)
                if "stream" in payload and payload["stream"]:
                    stream_name=str(payload["stream"]).strip()[:80]
                    if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(task["runbook_id"],stream_name)).fetchone():
                        order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(task["runbook_id"],)).fetchone()[0]
                        db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(task["runbook_id"],stream_name,order,now()))
                field_changes=[]
                if isinstance(payload.get("custom_fields"),dict):
                    workspace_id=db.execute("SELECT workspace_id FROM runbooks WHERE id=?",(task["runbook_id"],)).fetchone()[0]
                    field_changes=apply_custom_field_values(db,workspace_id,"task",tid,payload["custom_fields"])
                if not changes and not field_changes: doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); return self.send_json({"data":doc})
                if changes:
                    values.append(tid)
                    db.execute(f"UPDATE tasks SET {','.join(sets)} WHERE id=?",values)
                append_audit(db,task["runbook_id"],"task.edited",f"{task['title']}: "+"; ".join(changes+field_changes),actor["display_name"])
                db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),task["runbook_id"])); doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
                if newly_assigned_user_id: flowops.push.notify_task_assignment(db,actor["instance_id"],newly_assigned_user_id)
                return self.send_json({"data":doc})
        with connect() as db:
            actor=self.require(db,"runbooks:execute")
            if not actor:return
            task=db.execute("SELECT t.* FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE t.id=? AND w.instance_id=?",(tid,actor["instance_id"])).fetchone()
            if not task: return self.send_json({"error":"Not found"},404)
            runbook=db.execute("SELECT status,run_type FROM runbooks WHERE id=?",(task["runbook_id"],)).fetchone()
            if not runbook or runbook["status"]!="live":return self.send_json({"error":"Tasks can only be executed while the runbook is live"},409)
            rehearsal=runbook["run_type"]=="rehearsal"
            if task["task_type"]=="automation" and "runbooks:edit" not in actor["permissions"]:
                return self.send_json({"error":"Automation tasks trigger external systems and require editor-level authorization, not just task assignment."},403)
            if actor["role"]=="Member":
                assigned=task["owner_user_id"]==actor["id"] or (task["owner_team_id"] and actor["id"] in team_member_user_ids(db, task["owner_team_id"]))
                if not assigned:return self.send_json({"error":"Members may only act on tasks assigned to them or their team"},403)
            target=str(payload.get("status","")); valid={"pending":{"running","skipped","blocked"},"running":{"complete","failed","blocked","pending"},"blocked":{"running","pending","skipped"},"failed":{"running","skipped"},"complete":set(),"skipped":set()}
            if task["task_type"] in {"milestone","checklist","sms","email","call"}:valid["pending"].add("complete")
            if target not in valid.get(task["status"],set()): return self.send_json({"error":f"Cannot transition {task['status']} to {target}"},409)
            if target in {"running","complete"} and task["status"]!="running" and not task["force_started"]:
                blockers=db.execute("SELECT COUNT(*) FROM dependencies d JOIN tasks p ON p.id=d.depends_on_id WHERE d.task_id=? AND p.status NOT IN ('complete','skipped')",(tid,)).fetchone()[0]
                # OR-gated joins only need one finished predecessor.
                if blockers and task["dependency_logic"]=="or":
                    total=db.execute("SELECT COUNT(*) FROM dependencies WHERE task_id=?",(tid,)).fetchone()[0]
                    if total>1 and blockers<total: blockers=0
                if blockers: return self.send_json({"error":"Complete predecessor tasks first"},409)
                fixed_start=parse_instant(task["fixed_start_at"])
                if fixed_start and fixed_start>datetime.now(timezone.utc):
                    return self.send_json({"error":f"This task has a fixed start and cannot begin before {task['fixed_start_at']}"},409)
            if target=="complete" and task["checklist_json"]:
                open_items=[item["text"] for item in json.loads(task["checklist_json"]) if not item.get("done")]
                if open_items: return self.send_json({"error":f"Tick every checklist item before completing ({len(open_items)} open)"},409)
            linked_child=None
            if task["task_type"]=="runbook":
                if not task["linked_runbook_id"]: return self.send_json({"error":"This task has no linked runbook to start. Link one first."},400)
                linked_child=db.execute("SELECT id,name,status FROM runbooks WHERE id=?",(task["linked_runbook_id"],)).fetchone()
                if not linked_child: return self.send_json({"error":"The linked runbook no longer exists"},409)
                if target=="running" and linked_child["status"] not in {"ready","live"}:
                    return self.send_json({"error":f"Linked runbook '{linked_child['name']}' must be ready before it can be started (it is {linked_child['status']})"},409)
                if target=="complete" and linked_child["status"]!="complete":
                    return self.send_json({"error":f"Linked runbook '{linked_child['name']}' must complete first"},409)
            validation_result=str(payload.get("validation_result","")).strip()
            if task["task_type"]=="validation" and target=="complete" and validation_result not in {"Pass","Fail","Not Tested"}:return self.send_json({"error":"Validation completion requires Pass, Fail, or Not Tested"},400)
            skip_reason=str(payload.get("skip_reason","")).strip()
            if task["task_type"]=="automation" and target=="skipped" and not skip_reason:
                return self.send_json({"error":"Skipping a failed automation task requires an audited reason."},400)
            if task["task_type"]=="automation" and target=="running" and not str(task["automation_url"] or "").strip():
                return self.send_json({"error":"This automation task has no automation URL configured. Set one before starting it."},400)
            automation_status="queued" if task["task_type"]=="automation" and target=="running" else ("idle" if target=="pending" else task["automation_status"])
            db.execute("UPDATE tasks SET status=?,started_at=CASE WHEN ? IN ('running','complete') THEN COALESCE(started_at,?) ELSE started_at END,completed_at=CASE WHEN ? IN ('complete','skipped') THEN ? ELSE NULL END,validation_result=CASE WHEN ?!='' THEN ? ELSE validation_result END,validation_comment=CASE WHEN ?!='' THEN ? ELSE validation_comment END,blocked_reason=CASE WHEN ?='blocked' THEN ? ELSE blocked_reason END,skip_reason=CASE WHEN ?!='' THEN ? ELSE skip_reason END,automation_status=? WHERE id=?",(target,target,now(),target,now(),validation_result,validation_result,str(payload.get("validation_comment","")).strip(),str(payload.get("validation_comment","")).strip(),target,str(payload.get("blocked_reason","")).strip()[:500],skip_reason,skip_reason,automation_status,tid))
            append_audit(db,task["runbook_id"],"task.transition",f"{task['title']}: {task['status']} → {target}"+(f" ({skip_reason})" if skip_reason else ""),actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),task["runbook_id"]))
            fire_automation=task["task_type"]=="automation" and target=="running"
            if fire_automation and rehearsal:
                # Rehearsals exercise the plan, never the external systems it drives.
                fire_automation=False; stamp=now()
                db.execute("UPDATE tasks SET status='complete',completed_at=?,automation_status='rehearsal_skipped',automation_result=? WHERE id=?",(stamp,"Rehearsal: external automation was not called",tid))
                append_audit(db,task["runbook_id"],"task.automation_result",f"{task['title']}: skipped in rehearsal (no external call)",actor["display_name"])
                target="complete"
            if linked_child and target=="running" and linked_child["status"]=="ready":
                stamp=now()
                db.execute("UPDATE runbooks SET status='live',mode='live',run_type=?,actual_started_at=COALESCE(actual_started_at,?),updated_at=? WHERE id=?",(runbook["run_type"] or "live",stamp,stamp,linked_child["id"]))
                append_audit(db,linked_child["id"],"runbook.transition",f"ready → live (started by task '{task['title']}')"+(" (rehearsal)" if rehearsal else ""),actor["display_name"])
            if task["serviceops_ctask"] and not rehearsal:
                queue_serviceops_ctask_writeback(db,task,target,actor["display_name"],validation_result,skip_reason)
            ready=newly_startable_tasks(db,task["runbook_id"],tid) if target in {"complete","skipped"} else []
            for successor in ready:
                append_audit(db,task["runbook_id"],"task.ready",f"{successor['title']} is ready to start ({successor['owner_display']})","FlowOps")
            doc=flowops.runbooks.runbook_document(db,task["runbook_id"],actor); db.commit()
            for successor in ready: notify_task_ready(db,actor["instance_id"],successor)
            if task["task_type"] in COMMUNICATION_TASK_TYPES and target=="complete":
                threading.Thread(target=run_communication_task,args=(tid,rehearsal),daemon=True).start()
            if fire_automation:
                request_id=uuid.uuid4().hex
                threading.Thread(target=run_automation_task,args=(tid,request_id),daemon=True).start()
            return self.send_json({"data":doc})
