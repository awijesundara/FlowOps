"""Hash-chained audit trail."""
from __future__ import annotations

import hashlib
import sqlite3

from flowops.config import DEFAULT_INSTANCE_SLUG
from flowops.db import instance_settings, now, rows


def append_audit(db: sqlite3.Connection, runbook_id: int | None, action: str, detail: str, actor: str = "Preview User", instance_id: int | None = None) -> None:
    if instance_id is None and runbook_id is not None:
        found=db.execute("SELECT w.instance_id FROM runbooks r JOIN workspaces w ON w.id=r.workspace_id WHERE r.id=?",(runbook_id,)).fetchone()
        instance_id=found[0] if found else None
    if instance_id is None:
        found=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone(); instance_id=found[0] if found else None
    previous = db.execute("SELECT event_hash FROM audit WHERE instance_id=? ORDER BY id DESC LIMIT 1",(instance_id,)).fetchone()
    previous_hash = previous[0] if previous else "GENESIS"
    stamp = now()
    digest = hashlib.sha256(f"{previous_hash}|{runbook_id}|{action}|{detail}|{actor}|{stamp}".encode()).hexdigest()
    db.execute("INSERT INTO audit(runbook_id,action,detail,actor,created_at,previous_hash,event_hash,instance_id) VALUES(?,?,?,?,?,?,?,?)",
               (runbook_id, action, detail, actor, stamp, previous_hash, digest, instance_id))

def verify_audit_chain(db: sqlite3.Connection, instance_id: int) -> tuple[bool, int]:
    """Walks the tenant's audit hash chain from its last retention
    checkpoint (or GENESIS) and confirms every row's event_hash matches
    what append_audit() would have computed. Returns (chain_verified,
    events_checked). Shared by the export route and the standalone
    verify endpoint so both report the same result."""
    events = rows(db.execute("SELECT runbook_id,action,detail,actor,created_at,previous_hash,event_hash FROM audit WHERE instance_id=? ORDER BY id ASC", (instance_id,)))
    previous = instance_settings(db, instance_id).get("audit_retention_checkpoint", "GENESIS")
    for event in events:
        if event["previous_hash"] != previous:
            return False, len(events)
        expected = hashlib.sha256(f"{previous}|{event['runbook_id']}|{event['action']}|{event['detail']}|{event['actor']}|{event['created_at']}".encode()).hexdigest()
        if expected != event["event_hash"]:
            return False, len(events)
        previous = event["event_hash"]
    return True, len(events)
