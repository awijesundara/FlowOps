"""Outbound webhook matching and delivery."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from typing import Any

import flowops.net
from flowops.config import DB_PATH
from flowops.db import connect, now, rows


def webhook_matches(events_json: str, action: str) -> bool:
    try:
        patterns = json.loads(events_json or '["*"]')
    except (TypeError, ValueError):
        return False
    return any(p == "*" or p == action for p in patterns) if isinstance(patterns, list) else False

def webhook_payload(provider: str, event: dict[str, Any]) -> dict[str, Any]:
    """Slack and Microsoft Teams incoming webhooks each expect their own
    simple message shape and authenticate via the secrecy of the URL
    itself, not a signature header -- unlike FlowOps' own generic webhook,
    which is a portable signed JSON envelope any receiver can verify."""
    summary = f"{event['action']}: {event['detail']}" if event["detail"] else event["action"]
    if provider == "slack":
        return {"text": f"*FlowOps* — {summary}\n_by {event['actor']}_"}
    if provider == "teams":
        return {"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": "FlowOps event",
                "title": "FlowOps", "text": summary, "sections": [{"facts": [{"name": "Actor", "value": event["actor"]}]}]}
    return {
        "event": event["action"], "id": event["id"], "runbook_id": event["runbook_id"],
        "detail": event["detail"], "actor": event["actor"], "created_at": event["created_at"],
    }

def deliver_webhook_once(webhook: dict[str, Any], event: dict[str, Any]) -> tuple[int | None, str | None, int]:
    """POST one audit event to one webhook, retrying up to 3 times with a
    short fixed backoff on network failure or a non-2xx response. Generic
    webhooks are HMAC-signed; Slack/Teams webhooks are not (their own
    incoming-webhook URLs are the secret, per each provider's own model)."""
    provider = webhook.get("provider", "generic")
    payload = webhook_payload(provider, event)
    body = json.dumps(payload, sort_keys=True).encode()
    headers = {"Content-Type": "application/json"}
    if provider == "generic":
        signature = hmac.new(webhook["secret"].encode(), body, hashlib.sha256).hexdigest()
        headers["X-FlowOps-Signature"] = f"sha256={signature}"
        headers["X-FlowOps-Event"] = event["action"]
    last_error = None; status = None
    for attempt in range(1, 4):
        try:
            with flowops.net.safe_urlopen(webhook["url"], data=body, headers=headers, method="POST", timeout=8) as response:
                if 200 <= response.status < 300:
                    return response.status, None, attempt
                status = response.status; last_error = f"HTTP {response.status}"
        except RuntimeError as exc:
            status = None; last_error = str(exc)[:300]
        if attempt < 3: time.sleep(attempt * 2)
    return status, last_error, 3

def claim_new_audit_events() -> list[dict[str, Any]]:
    """Atomically claim the next batch of unprocessed audit rows and
    advance the shared cursor before any (slow, retryable) network I/O
    happens. BEGIN IMMEDIATE takes SQLite's write lock immediately, so
    when multiple FlowOps replicas share one database file (as they do in
    Kubernetes, where this pod's local PV is mounted read/write by every
    replica scheduled to the same node), only one replica's claim can
    succeed per batch -- the other blocks on the write lock (up to the
    connection's busy timeout) and then sees the cursor already advanced
    past this batch, so it correctly claims nothing rather than
    re-delivering the same events to the same webhooks."""
    db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute("SELECT last_audit_id FROM webhook_cursor WHERE id=1").fetchone()
        if not cursor:
            db.execute("INSERT OR IGNORE INTO webhook_cursor(id,last_audit_id) VALUES(1,0)"); last_id = 0
        else:
            last_id = cursor[0]
        events = rows(db.execute("SELECT * FROM audit WHERE id>? ORDER BY id LIMIT 50", (last_id,)))
        if events:
            db.execute("UPDATE webhook_cursor SET last_audit_id=?", (events[-1]["id"],))
        db.execute("COMMIT")
        return events
    except Exception:
        db.execute("ROLLBACK")
        raise
    finally:
        db.close()

def dispatch_pending_webhooks() -> int:
    """Runs one pass: claim newly committed audit rows, deliver them to
    every active, subscribed webhook, and persist the delivery records.
    Returns the number of deliveries attempted (for tests/introspection).

    Deliberately never holds a database connection open across the actual
    delivery (network I/O): a real load test surfaced that an earlier
    version did exactly that -- one open connection wrapped every
    deliver_webhook_once() call for a whole batch, and the first
    successful/failed delivery in that batch already escalates the
    connection to SQLite's write lock. A single slow or unreachable
    webhook (deliver_webhook_once() retries 3x with backoff, up to ~30s
    worst case) then held that write lock for the entire remainder of the
    batch, starving every other writer in the process -- including
    ordinary user logins -- with a real, reproducible 'database is
    locked' error. Fetching the work with one short-lived read connection,
    doing all delivery with no connection open, then persisting results
    with a second short-lived write connection closes that gap."""
    events = claim_new_audit_events()
    if not events:
        return 0
    with connect() as db:
        work = [
            (event, webhook)
            for event in events
            for webhook in rows(db.execute("SELECT * FROM webhooks WHERE instance_id=? AND active=1", (event["instance_id"],)))
            if webhook_matches(webhook["events_json"], event["action"])
        ]
    deliveries = [
        (webhook["id"], event["id"], event["action"], *deliver_webhook_once(webhook, event))
        for event, webhook in work
    ]
    if deliveries:
        with connect() as db:
            for webhook_id, audit_id, action, status, error, attempts in deliveries:
                db.execute(
                    "INSERT INTO webhook_deliveries(webhook_id,audit_id,event_type,success,status_code,error,attempts,attempted_at) VALUES(?,?,?,?,?,?,?,?)",
                    (webhook_id, audit_id, action, 1 if status and 200<=status<300 else 0, status, error, attempts, now()),
                )
            db.commit()
    return len(deliveries)

def webhook_dispatcher_loop() -> None:
    """Background poller (mirrors the SSE feed's own polling design): picks
    up newly committed audit rows and delivers them to every active webhook
    subscribed to that action, so delivery never blocks a request thread."""
    while True:
        try:
            dispatch_pending_webhooks()
        except Exception as exc:
            print(f"webhook dispatcher error: {exc}")
        time.sleep(2)
