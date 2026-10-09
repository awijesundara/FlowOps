"""Automation-task HTTP calls."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

import flowops.net
from flowops.audit import append_audit
from flowops.db import connect, now


def automation_context(db: sqlite3.Connection, runbook_id: int) -> dict[str, Any]:
    """A runbook's admin-configured extra headers/variables for its
    automation task calls (Epic 3.1 'automatic context') -- flat key/value
    only, no conditionals/loops, applied to every automation task fired
    from that runbook. Returns {} if none configured."""
    row = db.execute("SELECT automation_context_json FROM runbooks WHERE id=?", (runbook_id,)).fetchone()
    if not row or not row["automation_context_json"]: return {"headers": {}, "variables": {}}
    try:
        parsed = json.loads(row["automation_context_json"])
    except json.JSONDecodeError:
        return {"headers": {}, "variables": {}}
    return {"headers": parsed.get("headers") or {}, "variables": parsed.get("variables") or {}}

def apply_automation_context(url: str, body: bytes, context: dict[str, Any]) -> tuple[str, bytes]:
    """Flat {{var}} substitution into the automation URL and JSON body
    using the runbook's configured variables -- deliberately simple string
    substitution, not a templating engine, to avoid scope creep."""
    variables = context.get("variables") or {}
    if not variables: return url, body
    def substitute(text: str) -> str:
        for key, value in variables.items():
            text = text.replace("{{" + key + "}}", str(value))
        return text
    return substitute(url), substitute(body.decode()).encode()

def perform_automation_call(url: str, headers: dict[str, str], body: bytes, timeout: float = 30, allow_private_network: bool = False) -> tuple[bool, str]:
    """Fires one automation HTTP call through safe_urlopen (SSRF-resistant).
    Never raises -- callers get a uniform (status_ok, snippet) pass/fail
    result and a truncated response/error snippet for storage."""
    try:
        response = flowops.net.safe_urlopen(url, data=body, headers=headers, method="POST", timeout=timeout, allow_private_network=allow_private_network)
        with response:
            status_ok = 200 <= response.status < 300
            snippet = response.read(2000).decode(errors="replace")
    except Exception as exc:
        status_ok, snippet = False, f"{type(exc).__name__}: {exc}"
    return status_ok, snippet

def run_automation_task(task_id: int, request_id: str) -> None:
    """Executes an 'automation' task's outbound HTTP call in the background so
    the triggering request returns immediately with 'queued'/'running' state;
    the SSE feed (backed by the audit table) carries the eventual success/
    failure to connected clients in real time."""
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task or task["task_type"] != "automation": return
        db.execute("UPDATE tasks SET automation_status='running', automation_attempts=automation_attempts+1 WHERE id=?", (task_id,))
        append_audit(db, task["runbook_id"], "task.automation_running", f"{task['title']}: calling {task['automation_url']}", "FlowOps automation")
        db.commit()
        context = automation_context(db, task["runbook_id"])
    body = json.dumps({"request_id": request_id, "task_id": task_id, "task_title": task["title"]}).encode()
    url = task["automation_url"]
    headers = {"Content-Type": "application/json", "X-Request-ID": request_id, **context["headers"]}
    url, body = apply_automation_context(url, body, context)
    status_ok, snippet = perform_automation_call(url, headers, body)
    with connect() as db:
        task = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not task: return
        final_status = "complete" if status_ok else "failed"
        db.execute(
            "UPDATE tasks SET status=?, automation_status=?, automation_result=?, completed_at=CASE WHEN ?='complete' THEN ? ELSE completed_at END WHERE id=?",
            (final_status, "success" if status_ok else "failed", snippet[:2000], final_status, now(), task_id),
        )
        append_audit(db, task["runbook_id"], "task.automation_result", f"{task['title']}: {final_status}" + ("" if status_ok else f" ({snippet[:200]})"), "FlowOps automation")
        db.execute("UPDATE runbooks SET updated_at=? WHERE id=?", (now(), task["runbook_id"]))
        db.commit()
