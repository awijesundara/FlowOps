"""Scheduled dashboard summary emails."""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import flowops.mail
import flowops.runbooks
from flowops.db import connect, instance_settings, now, rows


def render_dashboard_email(db: sqlite3.Connection, instance_id: int) -> tuple[str, str]:
    """Renders the scheduled dashboard digest as plain text -- matching
    this app's existing all-plaintext email design (invitations, password
    resets), not an HTML template. Pure function, no SMTP, so it's directly
    unit-testable without a live mail server."""
    stats=dict(db.execute("SELECT COUNT(*) runbooks, SUM(r.status='live') live, SUM(r.status='complete') complete FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?",(instance_id,)).fetchone())
    task_completion=db.execute("SELECT COALESCE(ROUND(100.0*SUM(t.status='complete')/NULLIF(COUNT(*),0)),0) FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=?",(instance_id,)).fetchone()[0] or 0
    runbook_ids=[row[0] for row in db.execute("SELECT r.id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND r.archived=0",(instance_id,))]
    late_lines=[]
    for rbid in runbook_ids:
        doc=flowops.runbooks.runbook_document(db,rbid,None)
        if not doc: continue
        for task in doc["tasks"]:
            if task["late"] or task["delay_minutes"]>0:
                late_lines.append(f"  - {doc['name']} / {task['title']} ({task['status']})")
    lines=[
        "FlowOps workspace digest",
        f"Generated: {now()}",
        "",
        f"Active runbooks: {stats['runbooks'] or 0}",
        f"Live now: {stats['live'] or 0}",
        f"Completed: {stats['complete'] or 0}",
        f"Task completion: {task_completion}%",
        "",
        f"Late or at-risk tasks ({len(late_lines)}):",
    ]
    lines += (late_lines[:25] or ["  (none)"])
    if len(late_lines)>25: lines.append(f"  ... and {len(late_lines)-25} more")
    subject=f"FlowOps digest: {stats['runbooks'] or 0} active runbooks, {task_completion}% task completion"
    return subject, "\n".join(lines)

def maybe_send_dashboard_email(db: sqlite3.Connection, instance_id: int, current_time: datetime | None = None) -> bool:
    """The actual due-check + send logic for one instance, factored out of
    dashboard_email_loop() so tests can exercise the scheduling gate
    directly without waiting on the loop's own 15-minute sleep. Returns
    True if an email was actually sent (and the last-sent checkpoint
    advanced), False if this instance wasn't due."""
    current_time = current_time or datetime.now(timezone.utc)
    settings=instance_settings(db,instance_id)
    frequency=settings.get("dashboard_email_frequency","off")
    if frequency not in ("daily","weekly"): return False
    recipients=[r.strip() for r in settings.get("dashboard_email_recipients","").split(",") if r.strip()]
    if not recipients: return False
    try: hour=int(settings.get("dashboard_email_hour","8") or "8")
    except ValueError: hour=8
    if current_time.hour != hour: return False
    last_sent=settings.get("dashboard_email_last_sent_at","")
    if last_sent:
        try:
            last=datetime.fromisoformat(last_sent)
            if last.tzinfo is None: last=last.replace(tzinfo=timezone.utc)
            min_gap=timedelta(days=1 if frequency=="daily" else 7)
            if current_time-last < min_gap: return False
        except ValueError: pass
    subject,body=render_dashboard_email(db,instance_id)
    sent_any=False
    for recipient in recipients:
        try:
            flowops.mail.send_mail(recipient,subject,body); sent_any=True
        except RuntimeError as exc:
            print(json.dumps({"ts":now(),"level":"error","message":f"dashboard email failed for {recipient}: {exc}"},separators=(",",":")))
    if sent_any:
        db.execute("INSERT INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?) ON CONFLICT(instance_id,key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(instance_id,"dashboard_email_last_sent_at",current_time.isoformat(timespec="seconds"),now()))
        db.commit()
    return sent_any

def dashboard_email_loop() -> None:
    """Checks every 15 minutes (daily/weekly delivery doesn't need finer
    granularity) whether any instance is due its configured dashboard
    digest -- structurally identical to backup_loop()'s daemon-thread
    pattern. Must iterate every instance, not just the default one."""
    while True:
        time.sleep(900)
        try:
            with connect() as db:
                instance_ids=[row["id"] for row in rows(db.execute("SELECT id FROM instances"))]
            # One short connection per instance rather than one held open
            # across every instance's checks and (for whichever instance is
            # actually due) its blocking SMTP sends -- maybe_send_dashboard_
            # email() itself is unaffected/still takes an already-open
            # connection (its tested contract), this only bounds how long
            # any single connection stays open in the common case where
            # most instances aren't due and return immediately.
            for instance_id in instance_ids:
                with connect() as db:
                    maybe_send_dashboard_email(db,instance_id)
        except Exception as exc:
            print(json.dumps({"ts":now(),"level":"error","message":f"dashboard email loop failed: {exc}"},separators=(",",":")))
