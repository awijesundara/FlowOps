"""ServiceOps REST integration: write-back outbox and signed inbound events."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from flowops.audit import append_audit
from flowops.config import DB_PATH
from flowops.db import connect, instance_settings, integration_credential, now, rows
from flowops.runbooks import newly_startable_tasks, parse_instant


# --- ServiceOps collaboration -------------------------------------------
# FlowOps writes CTASK progress and execution evidence back to ServiceOps
# and follows change/CTASK state made directly in ServiceOps. Writes go
# through a transactional outbox: the row is inserted in the same
# transaction as the task transition, and a background worker delivers it
# with no database connection held. Previously the PATCH ran inside the
# request's write transaction, so a slow or unreachable ServiceOps held
# SQLite's write lock for up to the 8-second timeout, and a failed write
# was only audited, never retried -- leaving the change unable to close.
class ServiceOpsError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message); self.status = status

# Seconds to wait before attempt 2, 3, ... A write still failing after the
# last step is parked as failed for an administrator to retry.
SERVICEOPS_RETRY_SCHEDULE = (15, 60, 300, 900, 3600, 3600)

SERVICEOPS_OUTBOX_LEASE_SECONDS = 120

SERVICEOPS_EVENT_TOLERANCE_SECONDS = 300

# Change states that mean the work is no longer authorised.
SERVICEOPS_UNAUTHORISED_CHANGE_STATES = {"Cancelled", "Rejected", "New", "Awaiting Approval"}

SERVICEOPS_AUTHORISED_CHANGE_STATES = {"Approved", "In Progress", "Resolved", "Closed"}

# How a CTASK state set in ServiceOps maps onto a FlowOps task status, and
# which FlowOps statuses each may be applied from.
SERVICEOPS_CTASK_INBOUND = {
    "Work in Progress": ("running", {"pending", "blocked"}),
    "Closed Complete": ("complete", {"pending", "running", "blocked", "failed"}),
    "Cancelled": ("skipped", {"pending", "running", "blocked", "failed"}),
    "Closed Incomplete": ("failed", {"running"}),
}

def serviceops_endpoint(db: sqlite3.Connection, instance_id: int) -> tuple[str, str]:
    row = db.execute("SELECT value FROM instance_settings WHERE instance_id=? AND key='serviceops_url'", (instance_id,)).fetchone()
    base = (row[0] if row else os.getenv("SERVICEOPS_URL", "")).rstrip("/")
    base = base if base.endswith("/api/v1") else f"{base}/api/v1"
    token, _ = integration_credential(db, instance_id, "serviceops")
    if not base or base == "/api/v1" or not token:
        raise ServiceOpsError("Configure the ServiceOps URL and a scoped API token in Administration → Connections")
    return base, token

def serviceops_http(base: str, token: str, method: str, resource: str, body: Any = None, idempotency_key: str | None = None) -> tuple[Any, str, int]:
    encoded = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "X-Request-ID": str(uuid.uuid4())}
    if encoded is not None: headers["Content-Type"] = "application/json"
    if idempotency_key: headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(f"{base}/{resource.lstrip('/')}", data=encoded, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            document = json.load(response); request_id = response.headers.get("X-Request-ID", headers["X-Request-ID"])
            return document.get("data", document), request_id, response.status
    except urllib.error.HTTPError as exc:
        try: problem = json.load(exc); detail = problem.get("detail") or problem.get("error")
        except Exception: detail = None
        raise ServiceOpsError(f"ServiceOps returned HTTP {exc.code}{': '+str(detail) if detail else ''}", exc.code) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ServiceOpsError("ServiceOps is unreachable") from exc

def enqueue_serviceops_write(db: sqlite3.Connection, instance_id: int, runbook_id: int | None, kind: str, label: str, method: str, resource: str, body: Any, idempotency_key: str) -> None:
    """Records a ServiceOps write in the caller's transaction. A repeat of
    the same idempotency key while an earlier copy is still undelivered is
    dropped, since ServiceOps would replay the stored response anyway."""
    if db.execute("SELECT 1 FROM serviceops_outbox WHERE instance_id=? AND idempotency_key=? AND status='pending'", (instance_id, idempotency_key)).fetchone():
        return
    db.execute(
        "INSERT INTO serviceops_outbox(instance_id,runbook_id,kind,label,method,resource,body_json,idempotency_key,status,attempts,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?,?,'pending',0,?,?)",
        (instance_id, runbook_id, kind, label[:200], method, resource, json.dumps(body) if body is not None else None, idempotency_key[:128], time.time(), now()),
    )

def claim_serviceops_writes(limit: int = 20, include_future: bool = False) -> list[dict[str, Any]]:
    """Leases due outbox rows (BEGIN IMMEDIATE, as claim_new_audit_events
    does) so two replicas never deliver the same write at once. A lease
    that expires because a worker died makes the row due again."""
    db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL"); db.execute("BEGIN IMMEDIATE")
        cutoff = float("inf") if include_future else time.time()
        due = rows(db.execute("SELECT * FROM serviceops_outbox WHERE status='pending' AND next_attempt_at<=? ORDER BY id LIMIT ?", (cutoff, limit)))
        lease = time.time() + SERVICEOPS_OUTBOX_LEASE_SECONDS
        for item in due:
            db.execute("UPDATE serviceops_outbox SET next_attempt_at=? WHERE id=?", (lease, item["id"]))
        db.execute("COMMIT")
        return due
    except Exception:
        db.execute("ROLLBACK"); raise
    finally:
        db.close()

def serviceops_failure_is_permanent(status: int | None) -> bool:
    # A 4xx means ServiceOps refused this exact request (bad scope, invalid
    # transition, unknown field); repeating it cannot succeed. Timeouts,
    # throttling, 5xx and network errors are worth retrying.
    return status is not None and 400 <= status < 500 and status not in {408, 425, 429}

def resolve_serviceops_endpoints(db: sqlite3.Connection, items: list[dict[str, Any]]) -> dict[int, tuple[str, str] | ServiceOpsError]:
    endpoints: dict[int, tuple[str, str] | ServiceOpsError] = {}
    for item in items:
        if item["instance_id"] in endpoints: continue
        try: endpoints[item["instance_id"]] = serviceops_endpoint(db, item["instance_id"])
        except ServiceOpsError as exc: endpoints[item["instance_id"]] = exc
        except RuntimeError as exc: endpoints[item["instance_id"]] = ServiceOpsError(str(exc))
    return endpoints

def perform_serviceops_write(item: dict[str, Any], endpoint: tuple[str, str] | ServiceOpsError) -> tuple[str | None, int | None]:
    try:
        if isinstance(endpoint, ServiceOpsError): raise endpoint
        body = json.loads(item["body_json"]) if item["body_json"] else None
        serviceops_http(endpoint[0], endpoint[1], item["method"], item["resource"], body, item["idempotency_key"])
        return None, None
    except ServiceOpsError as exc:
        return str(exc), exc.status

def record_serviceops_results(db: sqlite3.Connection, results: list[tuple[dict[str, Any], str | None, int | None]]) -> None:
    for item, error, status in results:
        attempts = item["attempts"] + 1
        evidence = item["kind"] == "ctask_evidence"
        if error is None:
            db.execute("UPDATE serviceops_outbox SET status='delivered',attempts=?,delivered_at=?,last_error=NULL WHERE id=?", (attempts, now(), item["id"]))
            if evidence: append_audit(db, item["runbook_id"], "serviceops.evidence_recorded", item["label"], "FlowOps", item["instance_id"])
            else: append_audit(db, item["runbook_id"], "serviceops.ctask_synced", item["label"], "FlowOps", item["instance_id"])
        elif serviceops_failure_is_permanent(status) or attempts > len(SERVICEOPS_RETRY_SCHEDULE):
            db.execute("UPDATE serviceops_outbox SET status='failed',attempts=?,last_error=? WHERE id=?", (attempts, error[:500], item["id"]))
            if evidence: append_audit(db, item["runbook_id"], "serviceops.evidence_failed", f"{item['label']}: {error}", "FlowOps", item["instance_id"])
            else: append_audit(db, item["runbook_id"], "serviceops.ctask_sync_failed", f"{item['label']}: {error}", "FlowOps", item["instance_id"])
        else:
            db.execute("UPDATE serviceops_outbox SET attempts=?,last_error=?,next_attempt_at=? WHERE id=?", (attempts, error[:500], time.time() + SERVICEOPS_RETRY_SCHEDULE[attempts - 1], item["id"]))

def dispatch_serviceops_outbox(include_future: bool = False) -> int:
    """One worker pass. Returns the number of writes attempted. Credentials
    are read with a short connection, delivery runs with none open, and
    outcomes are persisted with a second short connection."""
    items = claim_serviceops_writes(include_future=include_future)
    if not items:
        return 0
    with connect() as db:
        endpoints = resolve_serviceops_endpoints(db, items)
    results = [(item, *perform_serviceops_write(item, endpoints[item["instance_id"]])) for item in items]
    with connect() as db:
        record_serviceops_results(db, results); db.commit()
    return len(results)

def flush_serviceops_writes_for_runbook(db: sqlite3.Connection, runbook_id: int) -> int:
    """Delivers a runbook's outstanding CTASK writes inline. Used right
    before the runbook resolves its change, because ServiceOps refuses to
    resolve a change while a required CTASK is still open. Writes that keep
    failing stay queued for the worker; ServiceOps' idempotency keys make a
    concurrent delivery by the worker harmless."""
    items = rows(db.execute("SELECT * FROM serviceops_outbox WHERE runbook_id=? AND status='pending' ORDER BY id", (runbook_id,)))
    if not items:
        return 0
    endpoints = resolve_serviceops_endpoints(db, items)
    record_serviceops_results(db, [(item, *perform_serviceops_write(item, endpoints[item["instance_id"]])) for item in items])
    return len(items)

def serviceops_outbox_loop() -> None:
    while True:
        try:
            dispatch_serviceops_outbox()
        except Exception as exc:
            print(f"serviceops outbox error: {exc}")
        time.sleep(2)

def serviceops_evidence_note(runbook: dict[str, Any], task: dict[str, Any], target: str, actor_name: str, validation_result: str = "", skip_reason: str = "") -> str:
    verb = {"complete": "completed", "skipped": "skipped"}.get(target, target)
    parts = [f'FlowOps runbook "{runbook["name"]}" (#{runbook["id"]}): "{task["title"]}" {verb} by {actor_name}.']
    started = parse_instant(task["started_at"])
    if target == "complete" and started:
        actual = max(0, round((datetime.now(timezone.utc) - started).total_seconds() / 60))
        parts.append(f"Planned {task['duration']} min, actual {actual} min.")
    if validation_result: parts.append(f"Validation: {validation_result}.")
    if skip_reason: parts.append(f"Reason: {skip_reason}.")
    return " ".join(parts)

def queue_serviceops_ctask_writeback(db: sqlite3.Connection, task: dict[str, Any], target: str, actor_name: str, validation_result: str = "", skip_reason: str = "") -> None:
    """Queues the CTASK state (and, on completion or skip, an append-only
    evidence note) for delivery. Never raises and never calls ServiceOps
    from the request thread."""
    state = {"running": "Work in Progress", "complete": "Closed Complete", "skipped": "Cancelled"}.get(target)
    if not state: return
    rb = db.execute("SELECT r.*,w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?", (task["runbook_id"],)).fetchone()
    ticket = str(rb["serviceops_ticket"] or "").strip() if rb else ""
    if not ticket: return
    settings = instance_settings(db, rb["instance_id"])
    if settings.get("serviceops_enabled", "true") != "true": return
    ctask = task["serviceops_ctask"]
    resource = f"tickets/{urllib.parse.quote(ticket)}/ctasks/{urllib.parse.quote(ctask)}"
    enqueue_serviceops_write(db, rb["instance_id"], rb["id"], "ctask_state", f"{ctask} → {state}", "PATCH", resource, {"state": state}, f"flowops-ctask-{ctask}-{target}")
    if target in {"complete", "skipped"} and settings.get("serviceops_record_evidence", "true") == "true":
        note = serviceops_evidence_note(dict(rb), dict(task), target, actor_name, validation_result, skip_reason)
        enqueue_serviceops_write(db, rb["instance_id"], rb["id"], "ctask_evidence", f"{ctask} execution evidence", "PATCH", resource, {"append_work_notes": note}, f"flowops-ctask-{ctask}-{target}-evidence-{task['id']}")

def verify_serviceops_signature(secret: str, timestamp: str, signature: str, raw: bytes, current_time: float | None = None) -> bool:
    """Checks X-ServiceOps-Signature (sha256=HMAC(secret, "<ts>.<body>"))
    and the replay window. ServiceOps releases before the signed-bytes fix
    signed a compact, key-sorted encoding while sending a differently
    formatted body, so that canonical form is accepted as well."""
    if not secret or not signature.startswith("sha256="): return False
    try: stamp = int(timestamp)
    except (TypeError, ValueError): return False
    if abs((current_time if current_time is not None else time.time()) - stamp) > SERVICEOPS_EVENT_TOLERANCE_SECONDS: return False
    provided = signature[len("sha256="):].strip().lower()
    candidates = [raw]
    try: candidates.append(json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")).encode())
    except (ValueError, UnicodeDecodeError): pass
    for body in candidates:
        expected = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, provided): return True
    return False

def apply_serviceops_change_event(db: sqlite3.Connection, instance_id: int, data: dict[str, Any]) -> dict[str, int]:
    number = str(data.get("number") or "").strip(); state = str(data.get("state") or "").strip()[:80]
    previous = str(data.get("previous_state") or "").strip()[:80]
    if not number or not state: raise ValueError("change.state_changed requires number and state")
    affected = rows(db.execute("SELECT r.id,r.name,r.status,r.serviceops_alert FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND UPPER(r.serviceops_ticket)=UPPER(?)", (instance_id, number)))
    alerts = 0
    for rb in affected:
        db.execute("UPDATE runbooks SET serviceops_state=?,serviceops_synced_at=?,updated_at=? WHERE id=?", (state, now(), now(), rb["id"]))
        append_audit(db, rb["id"], "serviceops.event_received", f"{number}: {previous or '?'} → {state}", "ServiceOps", instance_id)
        if state in SERVICEOPS_UNAUTHORISED_CHANGE_STATES and rb["status"] in {"ready", "live", "paused"}:
            alert = f"ServiceOps change {number} is now {state}. The work is no longer authorised; confirm with the change manager before continuing."
            db.execute("UPDATE runbooks SET serviceops_alert=? WHERE id=?", (alert, rb["id"]))
            append_audit(db, rb["id"], "serviceops.change_withdrawn", f"{number} moved to {state} while the runbook is {rb['status']}", "ServiceOps", instance_id)
            alerts += 1
        elif state in SERVICEOPS_AUTHORISED_CHANGE_STATES and rb["serviceops_alert"]:
            db.execute("UPDATE runbooks SET serviceops_alert=NULL WHERE id=?", (rb["id"],))
    return {"runbooks": len(affected), "alerts": alerts}

def apply_serviceops_ctask_event(db: sqlite3.Connection, instance_id: int, data: dict[str, Any]) -> tuple[dict[str, int], list[tuple[int, dict[str, Any]]]]:
    """Mirrors a CTASK state set in ServiceOps. During a live run (never a
    rehearsal) the matching FlowOps task follows it; nothing is written
    back, so the event cannot echo between the two systems. Returns counts
    and the tasks that became startable, for notification after commit."""
    number = str(data.get("number") or "").strip(); ticket = str(data.get("ticket") or "").strip()
    state = str(data.get("state") or "").strip()[:40]
    if not number or not state: raise ValueError("change_task.state_changed requires number and state")
    query = "SELECT t.*,r.status runbook_status,r.run_type FROM tasks t JOIN runbooks r ON r.id=t.runbook_id JOIN workspaces w ON w.id=r.workspace_id WHERE w.instance_id=? AND UPPER(t.serviceops_ctask)=UPPER(?)"
    params: list[Any] = [instance_id, number]
    if ticket: query += " AND UPPER(r.serviceops_ticket)=UPPER(?)"; params.append(ticket)
    tasks = rows(db.execute(query, params))
    applied = 0; ready: list[tuple[int, dict[str, Any]]] = []
    for task in tasks:
        db.execute("UPDATE tasks SET serviceops_ctask_state=? WHERE id=?", (state, task["id"]))
        if state in {"Closed Complete", "Closed Incomplete", "Cancelled"}:
            # ServiceOps has the final word on a closed CTASK: an older queued
            # state write would only be refused and reported as a failure.
            db.execute(
                "UPDATE serviceops_outbox SET status='superseded',last_error=? WHERE runbook_id=? AND kind='ctask_state' AND status='pending' AND resource LIKE ?",
                (f"Superseded: {number} was set to {state} in ServiceOps", task["runbook_id"], f"%/ctasks/{urllib.parse.quote(number)}"),
            )
        mapping = SERVICEOPS_CTASK_INBOUND.get(state)
        live = task["runbook_status"] == "live" and task["run_type"] != "rehearsal"
        if not mapping or not live or task["status"] == mapping[0] or task["status"] not in mapping[1]:
            append_audit(db, task["runbook_id"], "serviceops.ctask_state_received", f"{number}: {state} (task '{task['title']}' stays {task['status']})", "ServiceOps", instance_id)
            continue
        target = mapping[0]; stamp = now()
        db.execute(
            "UPDATE tasks SET status=?,started_at=CASE WHEN ? IN ('running','complete') THEN COALESCE(started_at,?) ELSE started_at END,completed_at=CASE WHEN ? IN ('complete','skipped') THEN ? ELSE NULL END,skip_reason=CASE WHEN ?='skipped' THEN ? ELSE skip_reason END WHERE id=?",
            (target, target, stamp, target, stamp, target, f"{number} cancelled in ServiceOps", task["id"]),
        )
        append_audit(db, task["runbook_id"], "task.transition", f"{task['title']}: {task['status']} → {target} ({number} set to {state} in ServiceOps)", "ServiceOps", instance_id)
        db.execute("UPDATE runbooks SET updated_at=? WHERE id=?", (stamp, task["runbook_id"]))
        applied += 1
        if target in {"complete", "skipped"}:
            for successor in newly_startable_tasks(db, task["runbook_id"], task["id"]):
                append_audit(db, task["runbook_id"], "task.ready", f"{successor['title']} is ready to start ({successor['owner_display']})", "FlowOps", instance_id)
                ready.append((instance_id, successor))
    return {"tasks": len(tasks), "applied": applied}, ready
