"""Runbooks, streams, my tasks, reports and the dashboard."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import flowops.runbooks
from flowops.audit import append_audit
from flowops.db import connect, now, rows
from flowops.runbooks import TASK_TYPES, ZERO_DURATION_TASK_TYPES, apply_custom_field_values, owns_runbook, parse_tasks_csv, plan_minutes, record_run, tasks_to_csv, tasks_to_xlsx, team_member_user_ids
from flowops.web.base import BaseHandler, NOT_HANDLED


class RunbookRoutes(BaseHandler):
    def _get_runbooks_db(self, db, path):
        if path=="/api/runbooks":
            actor=self.require(db,"runbooks:view")
            if not actor: return
            query=urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            include_archived=query.get("include_archived",["0"])[0]=="1"
            archived_clause="" if include_archived else "AND r.archived=0"
            folder_clause=""; params=[actor["instance_id"]]
            if query.get("folder_id"):
                folder_clause="AND r.folder_id=?"; params.append(int(query["folder_id"][0]))
            member_clause=""
            if actor["role"]=="Member":
                member_clause="AND EXISTS (SELECT 1 FROM tasks mt LEFT JOIN runbook_teams mrt ON mrt.id=mt.owner_team_id LEFT JOIN central_team_members mctm ON mctm.team_id=mrt.central_team_id AND mctm.user_id=? LEFT JOIN team_members mtm ON mtm.team_id=mrt.id AND mtm.user_id=? WHERE mt.runbook_id=r.id AND (mt.owner_user_id=? OR mctm.user_id IS NOT NULL OR mtm.user_id IS NOT NULL))"
                params+=[actor["id"],actor["id"],actor["id"]]
            search_clause=""
            q=(query.get("q",[""])[0]).strip()
            task_owner_join="LEFT JOIN users su ON su.id=st.owner_user_id LEFT JOIN runbook_teams stt ON stt.id=st.owner_team_id"
            if q:
                like=f"%{q}%"
                search_clause=f"AND (r.name LIKE ? OR r.owner LIKE ? OR r.serviceops_ticket LIKE ? OR EXISTS (SELECT 1 FROM tasks st {task_owner_join} WHERE st.runbook_id=r.id AND (st.title LIKE ? OR st.owner LIKE ? OR su.display_name LIKE ? OR stt.name LIKE ?)))"
                params+= [like,like,like,like,like,like,like]
            items=rows(db.execute(f"SELECT r.*,w.name workspace_name,f.name folder_name,rt.name runbook_type_name,rt.icon runbook_type_icon,rt.color runbook_type_color,COUNT(t.id) task_count,SUM(CASE WHEN t.status='complete' THEN 1 ELSE 0 END) done_count FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id LEFT JOIN folders f ON f.id=r.folder_id LEFT JOIN runbook_types rt ON rt.id=r.runbook_type_id LEFT JOIN tasks t ON t.runbook_id=r.id WHERE w.instance_id=? {archived_clause} {folder_clause} {member_clause} {search_clause} GROUP BY r.id ORDER BY r.updated_at DESC",params))
            if items:
                ids=[item["id"] for item in items]; marks=",".join("?"*len(ids))
                plan_tasks: dict[int,list[dict[str,Any]]]={}
                for task in rows(db.execute(f"SELECT id,runbook_id,duration,scheduled_offset,dependency_logic FROM tasks WHERE runbook_id IN ({marks})",ids)):
                    plan_tasks.setdefault(task["runbook_id"],[]).append(task)
                plan_deps: dict[int,list[tuple[int,int]]]={}
                for dep in db.execute(f"SELECT t.runbook_id,d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id IN ({marks})",ids):
                    plan_deps.setdefault(dep[0],[]).append((dep[1],dep[2]))
                for item in items: item["planned_minutes"]=plan_minutes(plan_tasks.get(item["id"],[]),plan_deps.get(item["id"],[]))
            if q:
                like=f"%{q}%"
                for item in items:
                    matched_task=db.execute(f"SELECT st.title FROM tasks st {task_owner_join} WHERE st.runbook_id=? AND (st.title LIKE ? OR st.owner LIKE ? OR su.display_name LIKE ? OR stt.name LIKE ?) LIMIT 1",(item["id"],like,like,like,like)).fetchone()
                    item["matched_task"]=matched_task["title"] if matched_task and q.lower() not in item["name"].lower() else None
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
                doc=flowops.runbooks.runbook_document(db,rid,user)
                csv_body=tasks_to_csv(doc["tasks"] if doc else [])
                self.send_response(200); self.send_header("Content-Type","text/csv; charset=utf-8")
                self.send_header("Content-Disposition",f'attachment; filename="runbook-{rid}-tasks.csv"')
                self.send_header("Content-Length",str(len(csv_body.encode())))
                self.end_headers(); self.wfile.write(csv_body.encode()); return
            if len(parts)==4 and parts[3]=="tasks.xlsx":
                doc=flowops.runbooks.runbook_document(db,rid,user)
                body=tasks_to_xlsx(doc["tasks"] if doc else [])
                self.send_response(200); self.send_header("Content-Type","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                self.send_header("Content-Disposition",f'attachment; filename="runbook-{rid}-tasks.xlsx"')
                self.send_header("Content-Length",str(len(body)))
                self.end_headers(); self.wfile.write(body); return
            if len(parts)!=3:return self.send_json({"error":"Not found"},404)
            doc=flowops.runbooks.runbook_document(db,rid,user)
            return self.send_json({"data":doc} if doc else {"error":"Not found"},200 if doc else 404)
        if path=="/api/my-tasks":
            # Cutover "My tasks": everything assigned to me or my teams
            # across every open runbook, startable work first.
            actor=self.require(db,"runbooks:view")
            if not actor: return
            runbook_ids=[row[0] for row in db.execute("SELECT r.id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND r.archived=0 AND r.status NOT IN ('complete','cancelled')",(actor["instance_id"],))]
            mine=[]
            for rbid in runbook_ids:
                doc=flowops.runbooks.runbook_document(db,rbid,None)
                if not doc: continue
                for task in doc["tasks"]:
                    on_team=bool(task["owner_team_id"]) and actor["id"] in team_member_user_ids(db,task["owner_team_id"])
                    if task["owner_user_id"]!=actor["id"] and not on_team: continue
                    if task["status"] in {"complete","skipped"}: continue
                    mine.append({**{k:task[k] for k in ("id","title","stream","status","task_type","duration","owner_display","blocked","startable","late","fixed_start_at","started_at","planned_start_offset")},
                                 "runbook_id":doc["id"],"runbook_name":doc["name"],"runbook_status":doc["status"],"run_type":doc.get("run_type") or "live","scheduled_at":doc["scheduled_at"]})
            rank={"running":0,"failed":1,"blocked":3}
            mine.sort(key=lambda t:(rank.get(t["status"],2 if t["startable"] and t["runbook_status"]=="live" else 4),t["runbook_name"],t["planned_start_offset"]))
            return self.send_json({"data":mine})
        if path in ("/api/reports/delay","/api/reports/delay.csv"):
            actor=self.require(db,"runbooks:view")
            if not actor: return
            runbook_ids=[row[0] for row in db.execute("SELECT r.id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND r.archived=0",(actor["instance_id"],))]
            report_rows=[]
            for rbid in runbook_ids:
                doc=flowops.runbooks.runbook_document(db,rbid,None)
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
        return NOT_HANDLED

    def _post_runbooks_db(self, db, path, payload):
        parts=path.strip("/").split("/")
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
            doc=flowops.runbooks.runbook_document(db,rid)
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
                task_type=str(payload.get("task_type","normal"))
                if task_type not in TASK_TYPES:return self.send_json({"error":"Invalid task type"},400)
                duration=max(0,min(int(payload.get("duration",15)),10080)); duration=0 if task_type in ZERO_DURATION_TASK_TYPES else max(1,duration)
                try: extras=self.task_extras(db,rid,task_type,payload)
                except ValueError as exc: return self.send_json({"error":str(exc)},400)
                owner_user_id=int(payload["owner_user_id"]) if payload.get("owner_user_id") else None; owner_team_id=int(payload["owner_team_id"]) if payload.get("owner_team_id") else None
                if owner_user_id and not db.execute("SELECT 1 FROM users WHERE id=? AND active=1 AND instance_id=?",(owner_user_id,actor["instance_id"])).fetchone():return self.send_json({"error":"Assigned user is invalid"},400)
                if owner_team_id and not db.execute("SELECT 1 FROM runbook_teams WHERE id=? AND runbook_id=?",(owner_team_id,rid)).fetchone():return self.send_json({"error":"Assigned team is invalid"},400)
                stream=str(payload.get("stream","General")).strip()[:80] or "General"
                if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(rid,stream)).fetchone():
                    stream_order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                    db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,stream,stream_order,now()))
                dependency_logic=str(payload.get("dependency_logic","and")).strip().lower()
                if dependency_logic not in ("and","or"): dependency_logic="and"
                cur=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset,owner_user_id,owner_team_id,dependency_logic) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,title,str(payload.get("description",""))[:2000],stream,"",duration,order,str(payload.get("automation_url",""))[:500] or None,task_type,max(0,int(payload.get("scheduled_offset",0))),owner_user_id,owner_team_id,dependency_logic))
                if extras:
                    db.execute(f"UPDATE tasks SET {','.join(f'{k}=?' for k in extras)} WHERE id=?",(*extras.values(),cur.lastrowid))
                for dep in payload.get("depends_on",[]):
                    if db.execute("SELECT 1 FROM tasks WHERE id=? AND runbook_id=?",(dep,rid)).fetchone(): db.execute("INSERT OR IGNORE INTO dependencies VALUES(?,?)",(cur.lastrowid,dep))
                append_audit(db,rid,"task.created",title,actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
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
                append_audit(db,rid,"task.csv_imported",f"{created} tasks",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
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
                append_audit(db,rid,"task.bulk_edited",f"{len(valid_ids)} tasks: {', '.join(changes)}",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(now(),rid)); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc,"updated":len(valid_ids)})
            if len(parts)==4 and parts[3]=="streams":
                actor=self.require_scoped_edit(db,runbook_id=rid)
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>80:return self.send_json({"error":"Stream name is required (maximum 80 characters)"},400)
                order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                try: cur=db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,name,order,now()))
                except sqlite3.IntegrityError:return self.send_json({"error":"That stream already exists"},409)
                append_audit(db,rid,"stream.created",name,actor["display_name"]); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
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
                db.execute("INSERT INTO comments(runbook_id,author,body,created_at) VALUES(?,?,?,?)",(rid,actor["display_name"],body[:2000],now())); append_audit(db,rid,"comment.added",body[:120],actor["display_name"]); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc},201)
            if len(parts)==4 and parts[3]=="transition":
                actor=self.require(db,"runbooks:execute")
                if not actor:return
                target=str(payload.get("status","")); allowed={"draft","ready","live","paused","complete","cancelled"}
                if target not in allowed: return self.send_json({"error":"Invalid runbook status"},400)
                runbook_row=db.execute("SELECT status,runbook_type_id,approved_at,run_type FROM runbooks WHERE id=?",(rid,)).fetchone()
                current=runbook_row["status"]
                valid={"draft":{"ready","cancelled"},"ready":{"live","draft","cancelled"},"live":{"paused","complete","cancelled"},"paused":{"live","cancelled"},"complete":set(),"cancelled":set()}
                if target not in valid[current]: return self.send_json({"error":f"Cannot transition {current} to {target}"},409)
                # A run is either live or a rehearsal, chosen when it starts
                # and fixed until it ends; resuming a paused run keeps its type.
                if target=="live" and current=="ready":
                    run_type=str(payload.get("run_type","live")).strip().lower()
                    if run_type not in ("live","rehearsal"): return self.send_json({"error":"Run type must be live or rehearsal"},400)
                else:
                    run_type=runbook_row["run_type"] or "live"
                rehearsal=run_type=="rehearsal"
                if target=="live" and not rehearsal and runbook_row["runbook_type_id"]:
                    rtype=db.execute("SELECT requires_approval,name FROM runbook_types WHERE id=?",(runbook_row["runbook_type_id"],)).fetchone()
                    if rtype and rtype["requires_approval"] and not runbook_row["approved_at"]:
                        return self.send_json({"error":f"{rtype['name']} runbooks require approval before going live"},409)
                # Rehearsals never touch the linked change records.
                serviceops_result=servicenow_result=None
                if not rehearsal:
                    try:
                        serviceops_result=self.serviceops_lifecycle(db,rid,target)
                        servicenow_result=self.servicenow_lifecycle(db,rid,target)
                    except PermissionError as exc:
                        return self.send_json({"error":str(exc)},409)
                    except RuntimeError as exc:
                        return self.send_json({"error":str(exc)},502)
                stamp=now()
                if target=="live":
                    db.execute("UPDATE runbooks SET status=?,mode='live',run_type=?,actual_started_at=COALESCE(actual_started_at,?),updated_at=? WHERE id=?",(target,run_type,stamp,stamp,rid))
                elif target=="complete":
                    db.execute("UPDATE runbooks SET status=?,mode='plan',actual_completed_at=?,updated_at=? WHERE id=?",(target,stamp,stamp,rid))
                else:
                    db.execute("UPDATE runbooks SET status=?,mode=?,updated_at=? WHERE id=?",(target,"live" if target=="paused" else "plan",stamp,rid))
                append_audit(db,rid,"runbook.transition",f"{current} → {target}"+(" (rehearsal)" if rehearsal else ""),actor["display_name"])
                if target in ("complete","cancelled"):
                    record_run(db,rid,target,actor["display_name"])
                if target=="complete":
                    # Finishing a child runbook completes the "runbook" tasks that launched it.
                    for parent_task in db.execute("SELECT id,runbook_id,title FROM tasks WHERE linked_runbook_id=? AND task_type='runbook' AND status='running'",(rid,)).fetchall():
                        db.execute("UPDATE tasks SET status='complete',completed_at=? WHERE id=?",(stamp,parent_task["id"]))
                        append_audit(db,parent_task["runbook_id"],"task.transition",f"{parent_task['title']}: running → complete (linked runbook finished)",actor["display_name"])
                doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc,"serviceops":serviceops_result,"servicenow":servicenow_result})
            if len(parts)==4 and parts[3]=="reset":
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                runbook_row=db.execute("SELECT status,run_type FROM runbooks WHERE id=?",(rid,)).fetchone()
                if runbook_row["run_type"]!="rehearsal" or runbook_row["status"] not in {"live","paused","complete","cancelled"}:
                    return self.send_json({"error":"Only a started rehearsal can be reset; live runs are final"},409)
                if runbook_row["status"] in {"live","paused"}: record_run(db,rid,"abandoned",actor["display_name"])
                for task in db.execute("SELECT id,checklist_json FROM tasks WHERE runbook_id=?",(rid,)).fetchall():
                    checklist=[dict(item,done=False) for item in json.loads(task["checklist_json"])] if task["checklist_json"] else None
                    db.execute("UPDATE tasks SET status='pending',started_at=NULL,completed_at=NULL,validation_result=NULL,validation_comment=NULL,blocked_reason=NULL,skip_reason=NULL,automation_status='idle',automation_result=NULL,automation_attempts=0,escalated=0,escalation_reason=NULL,incident=0,incident_reason=NULL,communication_result=NULL,force_started=0,force_start_reason=NULL,checklist_json=? WHERE id=?",(json.dumps(checklist) if checklist is not None else None,task["id"]))
                db.execute("UPDATE runbooks SET status='ready',mode='plan',run_type='live',actual_started_at=NULL,actual_completed_at=NULL,updated_at=? WHERE id=?",(now(),rid))
                append_audit(db,rid,"runbook.rehearsal_reset",f"Rehearsal reset from {runbook_row['status']}; runbook ready for its next run",actor["display_name"])
                doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc})
            if len(parts)==4 and parts[3]=="approve":
                actor=self.require(db,"admin:access")
                if not actor:return
                runbook=db.execute("SELECT status,runbook_type_id,approved_at FROM runbooks WHERE id=?",(rid,)).fetchone()
                if runbook["approved_at"]: return self.send_json({"error":"This runbook is already approved"},409)
                stamp=now()
                db.execute("UPDATE runbooks SET approved_at=?,approved_by=? WHERE id=?",(stamp,actor["display_name"],rid))
                append_audit(db,rid,"runbook.approved",f"Approved by {actor['display_name']}",actor["display_name"]); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc})
            if len(parts)==4 and parts[3]=="serviceops-sync":
                if not self.require(db,"integrations:sync"):return
                return self.sync_serviceops(db,rid,payload)
            if len(parts)==4 and parts[3]=="servicenow-sync":
                if not self.require(db,"integrations:sync"):return
                return self.sync_servicenow(db,rid,payload)
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
                    checklist=json.dumps([dict(item,done=False) for item in json.loads(t["checklist_json"])]) if t["checklist_json"] else None
                    new_tid=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset,owner_user_id,owner_team_id,dependency_logic,checklist_json,recipients,message,fixed_start_at,linked_runbook_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(new_rid,t["title"],t["description"],t["stream"],t["owner"],t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"],t["owner_user_id"],t["owner_team_id"],t["dependency_logic"],checklist,t["recipients"],t["message"],t["fixed_start_at"],t["linked_runbook_id"])).lastrowid
                    id_map[t["id"]]=new_tid
                for dep in db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?",(rid,)):
                    if dep["task_id"] in id_map and dep["depends_on_id"] in id_map:
                        db.execute("INSERT INTO dependencies VALUES(?,?)",(id_map[dep["task_id"]],id_map[dep["depends_on_id"]]))
                append_audit(db,new_rid,"runbook.duplicated",f"Duplicated from {source['name']}",actor["display_name"]); doc=flowops.runbooks.runbook_document(db,new_rid,actor); db.commit()
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
            if len(parts)==4 and parts[3]=="save-as-snippet":
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                name=str(payload.get("name","")).strip()
                if not name or len(name)>160: return self.send_json({"error":"Snippet name is required (maximum 160 characters)"},400)
                task_ids=[int(x) for x in payload.get("task_ids",[]) if str(x).isdigit()]
                if not task_ids: return self.send_json({"error":"Select at least one task to save as a snippet"},400)
                if len(task_ids)>100: return self.send_json({"error":"A snippet may contain at most 100 tasks"},400)
                selected=rows(db.execute(f"SELECT * FROM tasks WHERE runbook_id=? AND id IN ({','.join('?'*len(task_ids))}) ORDER BY sort_order",[rid]+task_ids))
                if len(selected)!=len(set(task_ids)): return self.send_json({"error":"One or more selected tasks were not found in this runbook"},400)
                source=db.execute("SELECT * FROM runbooks WHERE id=?",(rid,)).fetchone()
                stamp=now()
                try: cur=db.execute("INSERT INTO snippets(workspace_id,name,description,created_by,created_at) VALUES(?,?,?,?,?)",(source["workspace_id"],name,str(payload.get("description",""))[:2000],actor["display_name"],stamp))
                except sqlite3.IntegrityError: return self.send_json({"error":"A snippet with that name already exists in this workspace"},409)
                snippet_id=cur.lastrowid
                id_map={}
                for t in selected:
                    new_tid=db.execute("INSERT INTO snippet_tasks(snippet_id,title,description,stream,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?)",(snippet_id,t["title"],t["description"],t["stream"],t["duration"],t["sort_order"],t["automation_url"],t["task_type"],t["scheduled_offset"])).lastrowid
                    id_map[t["id"]]=new_tid
                for dep in db.execute(f"SELECT d.task_id,d.depends_on_id FROM dependencies d WHERE d.task_id IN ({','.join('?'*len(task_ids))})",task_ids):
                    if dep["task_id"] in id_map and dep["depends_on_id"] in id_map:
                        db.execute("INSERT INTO snippet_dependencies VALUES(?,?)",(id_map[dep["task_id"]],id_map[dep["depends_on_id"]]))
                append_audit(db,rid,"snippet.saved",f"{name} ({len(selected)} tasks)",actor["display_name"]); db.commit()
                return self.send_json({"data":{"id":snippet_id,"name":name,"task_count":len(selected)}},201)
            if len(parts)==4 and parts[3]=="insert-snippet":
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                runbook=db.execute("SELECT * FROM runbooks WHERE id=?",(rid,)).fetchone()
                if runbook["status"] in {"complete","cancelled"}: return self.send_json({"error":f"Cannot edit a {runbook['status']} runbook"},409)
                try: snippet_id=int(payload.get("snippet_id") or 0)
                except (TypeError,ValueError): return self.send_json({"error":"Not found"},404)
                snippet=db.execute("SELECT * FROM snippets WHERE id=? AND workspace_id=?",(snippet_id,runbook["workspace_id"])).fetchone()
                if not snippet: return self.send_json({"error":"Not found"},404)
                stamp=now()
                for s in db.execute("SELECT DISTINCT stream FROM snippet_tasks WHERE snippet_id=? ORDER BY sort_order",(snippet_id,)):
                    if not db.execute("SELECT 1 FROM streams WHERE runbook_id=? AND name=?",(rid,s["stream"])).fetchone():
                        order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM streams WHERE runbook_id=?",(rid,)).fetchone()[0]
                        db.execute("INSERT INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",(rid,s["stream"],order,stamp))
                base_order=db.execute("SELECT COALESCE(MAX(sort_order),-1)+1 FROM tasks WHERE runbook_id=?",(rid,)).fetchone()[0]
                id_map={}
                for i,t in enumerate(db.execute("SELECT * FROM snippet_tasks WHERE snippet_id=? ORDER BY sort_order",(snippet_id,))):
                    new_tid=db.execute("INSERT INTO tasks(runbook_id,title,description,stream,owner,duration,sort_order,automation_url,task_type,scheduled_offset) VALUES(?,?,?,?,?,?,?,?,?,?)",(rid,t["title"],t["description"],t["stream"],"",t["duration"],base_order+i,t["automation_url"],t["task_type"],t["scheduled_offset"])).lastrowid
                    id_map[t["id"]]=new_tid
                for dep in db.execute("SELECT snippet_task_id,depends_on_snippet_task_id FROM snippet_dependencies sd JOIN snippet_tasks st ON st.id=sd.snippet_task_id WHERE st.snippet_id=?",(snippet_id,)):
                    if dep["snippet_task_id"] in id_map and dep["depends_on_snippet_task_id"] in id_map:
                        db.execute("INSERT INTO dependencies VALUES(?,?)",(id_map[dep["snippet_task_id"]],id_map[dep["depends_on_snippet_task_id"]]))
                append_audit(db,rid,"snippet.inserted",f"{snippet['name']} ({len(id_map)} tasks)",actor["display_name"]); db.execute("UPDATE runbooks SET updated_at=? WHERE id=?",(stamp,rid)); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc},201)
            if len(parts)==4 and parts[3]=="archive":
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                status=db.execute("SELECT status,archived FROM runbooks WHERE id=?",(rid,)).fetchone()
                if status["status"]!="complete": return self.send_json({"error":"Only a complete runbook can be archived"},409)
                if status["archived"]: return self.send_json({"data":flowops.runbooks.runbook_document(db,rid,actor)})
                db.execute("UPDATE runbooks SET archived=1,updated_at=? WHERE id=?",(now(),rid))
                append_audit(db,rid,"runbook.archived","Archived",actor["display_name"]); doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc})
        return NOT_HANDLED

    def _patch_runbooks(self, path, parts, payload):
        if len(parts)==4 and parts[:2]==["api","runbooks"] and parts[3]=="review":
            try: rid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                runbook=db.execute("SELECT r.* FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=? AND w.instance_id=?",(rid,actor["instance_id"])).fetchone()
                if not runbook: return self.send_json({"error":"Not found"},404)
                if runbook["status"]!="complete": return self.send_json({"error":"A post-implementation review can only be recorded after the runbook is complete"},409)
                review={
                    "what_went_well":str(payload.get("what_went_well",""))[:4000],
                    "what_went_wrong":str(payload.get("what_went_wrong",""))[:4000],
                    "follow_up_actions":str(payload.get("follow_up_actions",""))[:4000],
                    "reviewed_by":actor["display_name"],
                    "reviewed_at":now(),
                }
                db.execute("UPDATE runbooks SET review_json=? WHERE id=?",(json.dumps(review),rid))
                append_audit(db,rid,"runbook.reviewed",f"Post-implementation review recorded by {actor['display_name']}",actor["display_name"])
                doc=flowops.runbooks.runbook_document(db,rid,actor); db.commit()
                return self.send_json({"data":doc})
        if len(parts)==3 and parts[:2]==["api","runbooks"]:
            try: rid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require_workspace_scoped_edit(db,runbook_id=rid)
                if not actor:return
                runbook=db.execute("SELECT r.* FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=? AND w.instance_id=?",(rid,actor["instance_id"])).fetchone()
                if not runbook: return self.send_json({"error":"Not found"},404)
                if runbook["status"] in {"complete","cancelled"}: return self.send_json({"error":f"Cannot edit a {runbook['status']} runbook"},409)
                editable={"name":160,"description":2000,"owner":120,"serviceops_ticket":40,"home_content":8000}
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
                        if parent["parent_runbook_id"]: return self.send_json({"error":"That runbook is already a child of another runbook; linking supports only one level of nesting"},400)
                        if db.execute("SELECT 1 FROM runbooks WHERE parent_runbook_id=?",(rid,)).fetchone(): return self.send_json({"error":"This runbook already has its own linked children; linking supports only one level of nesting"},400)
                    if parent_id!=runbook["parent_runbook_id"]: changes.append("parent_runbook_id changed"); sets.append("parent_runbook_id=?"); values.append(parent_id)
                if isinstance(payload.get("automation_context"),dict):
                    context=payload["automation_context"]
                    headers={str(k)[:100]:str(v)[:500] for k,v in (context.get("headers") or {}).items() if isinstance(k,str)}
                    variables={str(k)[:100]:str(v)[:500] for k,v in (context.get("variables") or {}).items() if isinstance(k,str)}
                    encoded=json.dumps({"headers":headers,"variables":variables})
                    if encoded!=(runbook["automation_context_json"] or ""):
                        changes.append("automation_context changed"); sets.append("automation_context_json=?"); values.append(encoded)
                field_changes=apply_custom_field_values(db,runbook["workspace_id"],"runbook",rid,payload.get("custom_fields",{})) if isinstance(payload.get("custom_fields"),dict) else []
                if not changes and not field_changes: return self.send_json({"data":flowops.runbooks.runbook_document(db,rid,actor)})
                ticket_linked="serviceops_ticket" in payload and str(payload["serviceops_ticket"]).strip()[:40]!=runbook["serviceops_ticket"] and str(payload["serviceops_ticket"]).strip()
                if changes:
                    sets.append("updated_at=?"); values.append(now()); values.append(rid)
                    db.execute(f"UPDATE runbooks SET {','.join(sets)} WHERE id=?",values)
                append_audit(db,rid,"runbook.edited","; ".join(changes+field_changes),actor["display_name"]); db.commit()
                if ticket_linked:
                    try: self.apply_serviceops_sync(db,rid,ticket_linked); db.commit()
                    except RuntimeError as exc: append_audit(db,rid,"serviceops.sync_failed",str(exc)); db.commit()
                doc=flowops.runbooks.runbook_document(db,rid,actor)
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
                append_audit(db,stream["runbook_id"],"stream.renamed",f"{stream['name']} → {name}",actor["display_name"]); doc=flowops.runbooks.runbook_document(db,stream["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
        return NOT_HANDLED

    def _delete_runbooks(self, path, parts, parsed):
        if len(parts)==3 and parts[:2]==["api","runbooks"]:
            try: rid=int(parts[2])
            except ValueError: return self.send_json({"error":"Not found"},404)
            with connect() as db:
                actor=self.require(db,"admin:access")
                if not actor:return
                runbook=db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=? AND w.instance_id=?",(rid,actor["instance_id"])).fetchone()
                if not runbook: return self.send_json({"error":"Not found"},404)
                if runbook["status"]=="live": return self.send_json({"error":"A live runbook cannot be deleted. Pause or complete it first."},409)
                # Task/comment/stream rows cascade-delete via their own FK
                # constraints; audit rows deliberately do NOT (audit.runbook_id
                # has no FK) -- the immutable history of a deleted runbook is
                # preserved, matching this app's compliance-evidence design.
                db.execute("DELETE FROM runbooks WHERE id=?",(rid,))
                append_audit(db,None,"runbook.deleted",f"{runbook['name']} (was {runbook['status']})",actor["display_name"],actor["instance_id"]); db.commit()
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
                db.execute("DELETE FROM streams WHERE id=?",(sid,)); append_audit(db,stream["runbook_id"],"stream.deleted",stream["name"],actor["display_name"]); doc=flowops.runbooks.runbook_document(db,stream["runbook_id"],actor); db.commit()
                return self.send_json({"data":doc})
        return NOT_HANDLED
