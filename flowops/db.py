"""SQLite connections and small shared query helpers."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from flowops.config import DB_PATH
from flowops.crypto import InvalidToken, settings_cipher


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db

def instance_settings(db: sqlite3.Connection, instance_id: int) -> dict[str,str]:
    return {r["key"]:r["value"] for r in db.execute("SELECT key,value FROM instance_settings WHERE instance_id=?",(instance_id,))}

def integration_credential(db: sqlite3.Connection, instance_id: int, provider: str) -> tuple[str,str]:
    row=db.execute("SELECT secret_encrypted FROM integration_credentials WHERE instance_id=? AND provider=?",(instance_id,provider)).fetchone()
    if row:
        try:return settings_cipher().decrypt(row[0].encode()).decode(),"Encrypted FlowOps setting"
        except (InvalidToken,RuntimeError,UnicodeDecodeError) as exc:raise RuntimeError(f"The stored {provider.title()} credential cannot be decrypted") from exc
    return "","Not configured in FlowOps"

def rows(items) -> list[dict[str, Any]]:
    return [dict(row) for row in items]
