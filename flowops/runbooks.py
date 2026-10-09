"""Runbook planning, task rules, import/export and the runbook document."""
from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

import flowops.mail
import flowops.push
from flowops.audit import append_audit
from flowops.db import connect, now, rows


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

TASK_CSV_TYPES={"normal","milestone","checklist","validation","sms","email","call","automation"}

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

TASK_TYPES={"normal","milestone","checklist","validation","sms","email","call","automation","runbook"}

# Task types with no working duration of their own -- they complete in one
# action (a checkpoint, a notification) rather than start-then-finish.
ZERO_DURATION_TASK_TYPES={"milestone","checklist","sms","email","call"}

COMMUNICATION_TASK_TYPES={"sms","email","call"}

CHECKLIST_MAX_ITEMS=50

def parse_instant(value: str | None) -> datetime | None:
    if not value: return None
    try:
        parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

def normalize_checklist(items: Any) -> list[dict[str,Any]]:
    """Accepts a list of strings or {text,done} objects (or one item per line); returns stored shape."""
    if isinstance(items,str): items=items.splitlines()
    if not isinstance(items,list): raise ValueError("Checklist items must be a list")
    result=[]
    for item in items:
        text=str(item.get("text","") if isinstance(item,dict) else item).strip()[:200]
        if not text: continue
        result.append({"text":text,"done":bool(item.get("done")) if isinstance(item,dict) else False})
    if len(result)>CHECKLIST_MAX_ITEMS: raise ValueError(f"A checklist may have at most {CHECKLIST_MAX_ITEMS} items")
    return result

def plan_minutes(tasks: list[dict[str,Any]], deps: list[tuple[int,int]]) -> int:
    """Dependency-aware planned runbook length, the same rule runbook_document() uses."""
    by_id={t["id"]:t for t in tasks}; dep_map: dict[int,list[int]]={}
    for task_id,depends_on in deps: dep_map.setdefault(task_id,[]).append(depends_on)
    memo: dict[int,int]={}
    def start(tid: int, trail: frozenset=frozenset()) -> int:
        if tid in memo: return memo[tid]
        task=by_id[tid]; offset=max(0,int(task.get("scheduled_offset") or 0))
        finishes=[start(d,trail|{tid})+by_id[d]["duration"] for d in dep_map.get(tid,[]) if d in by_id and d not in trail]
        if finishes:
            combine=min if (task.get("dependency_logic")=="or" and len(finishes)>1) else max
            offset=max(offset,combine(finishes))
        memo[tid]=offset; return offset
    return max((start(t["id"])+t["duration"] for t in tasks),default=0)

def record_run(db: sqlite3.Connection, rid: int, outcome: str, actor_name: str) -> None:
    """Snapshot one execution (live or rehearsal) into the run history."""
    rb=db.execute("SELECT run_type,actual_started_at FROM runbooks WHERE id=?",(rid,)).fetchone()
    if not rb or not rb["actual_started_at"]: return
    doc=runbook_document(db,rid,None)
    started=parse_instant(rb["actual_started_at"]); ended=datetime.now(timezone.utc)
    db.execute("INSERT INTO runbook_runs(runbook_id,run_type,outcome,started_at,ended_at,planned_seconds,actual_seconds,task_count,completed_count,late_count,ended_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (rid,rb["run_type"] or "live",outcome,rb["actual_started_at"],ended.isoformat(timespec="seconds"),doc["duration"]*60 if doc else 0,
                max(0,int((ended-started).total_seconds())) if started else 0,len(doc["tasks"]) if doc else 0,
                sum(t["status"] in {"complete","skipped"} for t in doc["tasks"]) if doc else 0,
                sum(bool(t["late"]) or t["delay_minutes"]>0 for t in doc["tasks"]) if doc else 0,actor_name))

def newly_startable_tasks(db: sqlite3.Connection, rid: int, finished_task_id: int) -> list[dict[str,Any]]:
    """Successors of a just-finished task that are now free to start."""
    doc=runbook_document(db,rid,None)
    if not doc: return []
    return [t for t in doc["tasks"] if finished_task_id in t["depends_on"] and t["status"]=="pending" and not t["blocked"]]

def notify_task_ready(db: sqlite3.Connection, instance_id: int, task: dict[str,Any]) -> None:
    recipients={task["owner_user_id"]} if task.get("owner_user_id") else set()
    if task.get("owner_team_id"): recipients|=team_member_user_ids(db,task["owner_team_id"])
    for user_id in recipients: flowops.push.notify_task_assignment(db,instance_id,user_id)

def run_communication_task(task_id: int, rehearsal: bool) -> None:
    """Deliver an email task's message (SMS/call have no provider and are logged)."""
    with connect() as db:
        task=db.execute("SELECT * FROM tasks WHERE id=?",(task_id,)).fetchone()
        if not task: return
        recipients=[r.strip() for r in re.split(r"[,;\s]+",task["recipients"] or "") if r.strip()]
        subject=f"[FlowOps] {task['title']}"; body=task["message"] or task["description"] or task["title"]
    if rehearsal:
        result=f"Rehearsal: not sent to {len(recipients)} recipient(s)"
    elif not recipients:
        result="No recipients configured; nothing sent"
    elif task["task_type"]!="email":
        result=f"Recorded for {len(recipients)} recipient(s); no {task['task_type'].upper()} provider is configured, contact them directly"
    else:
        sent,failed=0,[]
        for recipient in recipients:
            try: flowops.mail.send_mail(recipient,subject,body); sent+=1
            except RuntimeError as exc: failed.append(f"{recipient}: {exc}")
        result=f"Email sent to {sent} of {len(recipients)} recipient(s)"+(f"; failed: {'; '.join(failed)[:400]}" if failed else "")
    with connect() as db:
        db.execute("UPDATE tasks SET communication_result=? WHERE id=?",(result,task_id))
        append_audit(db,task["runbook_id"],"task.communication_sent",f"{task['title']}: {result}","FlowOps")
        db.commit()

def _xlsx_column(index: int) -> str:
    letters=""
    index+=1
    while index: index,rem=divmod(index-1,26); letters=chr(65+rem)+letters
    return letters

def tasks_to_xlsx(tasks: list[dict]) -> bytes:
    """Minimal Office Open XML workbook (stdlib zipfile) with the CSV export's columns."""
    import zipfile
    from xml.sax.saxutils import escape as xml_escape
    fields=["title","stream","owner","duration","task_type","scheduled_offset","status","started_at","completed_at","late","description","automation_url"]
    def cell(ref: str, value: Any) -> str:
        if isinstance(value,bool): value="TRUE" if value else "FALSE"
        if isinstance(value,(int,float)): return f'<c r="{ref}"><v>{value}</v></c>'
        text=xml_escape("" if value is None else str(value))
        return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'
    sheet_rows=[]
    for row_number,values in enumerate([fields]+[[task.get(k) for k in fields] for task in tasks],start=1):
        cells="".join(cell(f"{_xlsx_column(i)}{row_number}",v) for i,v in enumerate(values))
        sheet_rows.append(f'<row r="{row_number}">{cells}</row>')
    sheet=('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           f'<sheetData>{"".join(sheet_rows)}</sheetData></worksheet>')
    files={
        "[Content_Types].xml":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>',
        "_rels/.rels":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
        "xl/workbook.xml":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Tasks" sheetId="1" r:id="rId1"/></sheets></workbook>',
        "xl/_rels/workbook.xml.rels":'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>',
        "xl/worksheets/sheet1.xml":sheet,
    }
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w",zipfile.ZIP_DEFLATED) as archive:
        for name,content in files.items(): archive.writestr(name,content)
    return buf.getvalue()

def runbook_document(db: sqlite3.Connection, rid: int, user: dict[str,Any] | None=None) -> dict[str, Any] | None:
    if user and not owns_runbook(db,rid,user["instance_id"]):
        return None
    rb = db.execute("SELECT * FROM runbooks WHERE id=?", (rid,)).fetchone()
    if not rb:
        return None
    doc = dict(rb)
    raw_review = doc.pop("review_json", None)
    doc["review"] = json.loads(raw_review) if raw_review else None
    raw_automation_context = doc.pop("automation_context_json", None)
    doc["automation_context"] = json.loads(raw_automation_context) if raw_automation_context else {"headers":{},"variables":{}}
    doc["runbook_type_requires_approval"] = bool(db.execute("SELECT requires_approval FROM runbook_types WHERE id=?",(doc["runbook_type_id"],)).fetchone()[0]) if doc.get("runbook_type_id") else False
    all_tasks = rows(db.execute("SELECT t.*,u.display_name owner_user_name,rt.name owner_team_name FROM tasks t LEFT JOIN users u ON u.id=t.owner_user_id LEFT JOIN runbook_teams rt ON rt.id=t.owner_team_id WHERE t.runbook_id=? ORDER BY t.sort_order,t.id", (rid,)))
    deps = rows(db.execute("SELECT d.task_id,d.depends_on_id FROM dependencies d JOIN tasks t ON t.id=d.task_id WHERE t.runbook_id=?", (rid,)))
    dep_map: dict[int,list[int]] = {}
    for dep in deps:
        dep_map.setdefault(dep["task_id"], []).append(dep["depends_on_id"])
    for task in all_tasks:
        task["depends_on"] = dep_map.get(task["id"], [])
        dep_statuses = [next((x["status"] for x in all_tasks if x["id"] == d), "pending") for d in task["depends_on"]]
        # AND (default): every predecessor must finish before this task can
        # start -- a single unfinished dependency blocks it. OR: any one
        # finished predecessor is enough (a Cutover-style "either branch"
        # join) -- only relevant with 2+ dependencies; with 0 or 1 it's moot.
        if task.get("dependency_logic") == "or" and len(dep_statuses) > 1:
            task["blocked"] = task["status"] == "pending" and dep_statuses and not any(s in {"complete","skipped"} for s in dep_statuses)
        else:
            task["blocked"] = task["status"] == "pending" and any(s not in {"complete","skipped"} for s in dep_statuses)
        task["owner_display"] = task["owner_user_name"] or task["owner_team_name"] or task["owner"] or "Unassigned"
        raw_checklist = task.pop("checklist_json", None)
        task["checklist"] = json.loads(raw_checklist) if raw_checklist else []
        fixed_start = parse_instant(task.get("fixed_start_at"))
        task["fixed_start_pending"] = bool(fixed_start and fixed_start > datetime.now(timezone.utc))
        # Cutover-style "startable": free of dependencies and not held back by a fixed start time.
        task["startable"] = task["status"] == "pending" and not task["blocked"] and not task["fixed_start_pending"]
    task_comments: dict[int,list[dict[str,Any]]] = {}
    for comment in rows(db.execute("SELECT tc.* FROM task_comments tc JOIN tasks t ON t.id=tc.task_id WHERE t.runbook_id=? ORDER BY tc.id", (rid,))):
        task_comments.setdefault(comment["task_id"], []).append(comment)
    for task in all_tasks:
        task["comments"] = task_comments.get(task["id"], [])
    linked_ids = {t["linked_runbook_id"] for t in all_tasks if t.get("linked_runbook_id")}
    linked = {row["id"]: dict(row) for row in db.execute(f"SELECT id,name,status FROM runbooks WHERE id IN ({','.join('?'*len(linked_ids))})", tuple(linked_ids))} if linked_ids else {}
    for task in all_tasks:
        task["linked_runbook"] = linked.get(task.get("linked_runbook_id"))
    tasks=all_tasks
    if user and user.get("role")=="Member":
        team_ids={row[0] for row in db.execute("SELECT team_id FROM team_members WHERE user_id=?",(user["id"],))}
        team_ids|={row[0] for row in db.execute("SELECT rt.id FROM runbook_teams rt JOIN central_team_members ctm ON ctm.team_id=rt.central_team_id WHERE rt.runbook_id=? AND ctm.user_id=?",(rid,user["id"]))}
        tasks=[t for t in all_tasks if t["owner_user_id"]==user["id"] or t["owner_team_id"] in team_ids]
    # Earliest-possible-start offset per task is the later of its explicit
    # schedule offset and the finish of its longest predecessor branch.
    # a task blocked behind 90 minutes of prior work cannot be late the
    # instant the runbook's overall start time passes -- it becomes late
    # only once its own dependency chain's planned finish time passes.
    by_id = {t["id"]: t for t in all_tasks}
    earliest_start_memo: dict[int, int] = {}
    def earliest_start(tid: int) -> int:
        if tid in earliest_start_memo: return earliest_start_memo[tid]
        task = by_id.get(tid)
        if not task: return 0
        earliest_start_memo[tid] = max(0, int(task.get("scheduled_offset") or 0))
        finish_times = [earliest_start(dep) + by_id[dep]["duration"] for dep in task["depends_on"] if dep in by_id]
        # OR-gated tasks with 2+ deps can start as soon as the *earliest*
        # branch finishes, not the latest -- the mirror image of the
        # blocked-status check above.
        combine = min if (task.get("dependency_logic") == "or" and len(finish_times) > 1) else max
        offset = max(
            max(0, int(task.get("scheduled_offset") or 0)),
            combine(finish_times) if finish_times else 0,
        )
        earliest_start_memo[tid] = offset
        return offset
    runbook_live = rb["mode"] == "live" or bool(rb["actual_started_at"])
    for task in tasks:
        task["planned_start_offset"] = earliest_start(task["id"])
        task["planned_end_offset"] = task["planned_start_offset"] + task["duration"]
        task["late"] = False
        task["delay_minutes"] = 0
        if rb["scheduled_at"] and not task["blocked"]:
            try:
                scheduled=datetime.fromisoformat(rb["scheduled_at"])
                if scheduled.tzinfo is None: scheduled=scheduled.replace(tzinfo=timezone.utc)
                offset = task["planned_start_offset"]
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
    doc["duration"] = max((earliest_start(t["id"]) + t["duration"] for t in all_tasks), default=0)
    doc["critical_path"] = critical_path(all_tasks)
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
    # Forecast finish: actual timestamps for finished work, "now" as the
    # floor for anything still outstanding, dependency chains projected
    # forward from there -- so an overrunning task pushes the forecast out.
    forecast_end = None
    if started and not completed:
        now_ts = current_time.timestamp(); finish_memo: dict[int,float] = {}
        def projected_finish(tid: int, trail: frozenset = frozenset()) -> float:
            if tid in finish_memo: return finish_memo[tid]
            task = by_id[tid]; seconds = task["duration"] * 60
            done_at = instant(task.get("completed_at"))
            if task["status"] in {"complete","skipped"} and done_at:
                finish_memo[tid] = done_at.timestamp(); return finish_memo[tid]
            began = instant(task.get("started_at"))
            if task["status"] == "running" and began:
                finish_memo[tid] = max(now_ts, began.timestamp() + seconds); return finish_memo[tid]
            finishes = [projected_finish(d, trail | {tid}) for d in task["depends_on"] if d in by_id and d not in trail]
            combine = min if (task.get("dependency_logic") == "or" and len(finishes) > 1) else max
            begin = max([now_ts] + ([combine(finishes)] if finishes else []))
            fixed = instant(task.get("fixed_start_at"))
            if fixed: begin = max(begin, fixed.timestamp())
            finish_memo[tid] = begin + seconds; return finish_memo[tid]
        forecast_ts = max((projected_finish(t["id"]) for t in all_tasks), default=now_ts)
        forecast_end = datetime.fromtimestamp(forecast_ts, timezone.utc)
    doc["runs"] = rows(db.execute("SELECT * FROM runbook_runs WHERE runbook_id=? ORDER BY id DESC LIMIT 20", (rid,)))
    writeback = db.execute("SELECT SUM(status='pending'),SUM(status='failed') FROM serviceops_outbox WHERE runbook_id=?", (rid,)).fetchone()
    doc["serviceops_writeback"] = {"pending": writeback[0] or 0, "failed": writeback[1] or 0}
    doc["timing"] = {
        "forecast_end_at": forecast_end.isoformat(timespec="seconds") if forecast_end else None,
        "forecast_variance_seconds": int(forecast_end.timestamp() - (started.timestamp() + planned_seconds)) if forecast_end and started else None,
        "run_type": doc.get("run_type") or "live",
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
        visiting.add(tid); task=by_id[tid]; best=(max(0,int(task.get("scheduled_offset") or 0)),[])
        for dep in task["depends_on"]:
            if dep in by_id:
                candidate=visit(dep)
                if candidate[0] > best[0]: best=candidate
        visiting.discard(tid); memo[tid]=(best[0]+task["duration"], best[1]+[tid]); return memo[tid]
    return max((visit(t["id"]) for t in tasks), default=(0,[]), key=lambda x:x[0])[1]
