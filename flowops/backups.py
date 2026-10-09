"""Encrypted database backups and the backup schedule."""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

import flowops.config
from flowops.config import BACKUP_INTERVAL_HOURS, DB_PATH
from flowops.crypto import settings_cipher
from flowops.db import now


def list_backups() -> list[dict[str, Any]]:
    if not flowops.config.BACKUP_DIR.exists(): return []
    items=[]
    # .db.enc is the current (encrypted) format; bare .db is only listed for
    # backward compatibility with backups taken before encryption-at-rest
    # shipped -- new backups are never written in that format again.
    for path in sorted(list(flowops.config.BACKUP_DIR.glob("flowops-*.db.enc"))+list(flowops.config.BACKUP_DIR.glob("flowops-*.db")), key=lambda p: p.stat().st_mtime, reverse=True):
        stat=path.stat()
        items.append({"filename":path.name,"size_bytes":stat.st_size,"created_at":datetime.fromtimestamp(stat.st_mtime,tz=timezone.utc).isoformat(timespec="seconds"),"encrypted":path.suffix==".enc"})
    return items

def backup_database() -> dict[str, Any]:
    """Hot, consistent snapshot backup using SQLite's own backup API (safe to
    run against a live database, unlike a plain file copy), then encrypted
    at rest with the same authenticated cipher (SettingsCipher) already
    used for admin-managed credentials -- the on-disk backup is never left
    as a readable SQLite file. This is point-in-time *snapshot* backup, not
    continuous/WAL-shipping PITR -- recovery granularity is the backup
    interval, not per-transaction."""
    flowops.config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + f"{datetime.now(timezone.utc).microsecond:06d}Z"
    plain_path = flowops.config.BACKUP_DIR / f"flowops-{stamp}.db"
    enc_path = flowops.config.BACKUP_DIR / f"flowops-{stamp}.db.enc"
    source = sqlite3.connect(DB_PATH)
    try:
        dest = sqlite3.connect(str(plain_path))
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()
    enc_path.write_bytes(settings_cipher().encrypt(plain_path.read_bytes()))
    plain_path.unlink(missing_ok=True)
    backups = sorted(list(flowops.config.BACKUP_DIR.glob("flowops-*.db.enc"))+list(flowops.config.BACKUP_DIR.glob("flowops-*.db")), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in backups[flowops.config.BACKUP_RETAIN:]:
        stale.unlink(missing_ok=True)
    return {"filename": enc_path.name, "size_bytes": enc_path.stat().st_size}

def backup_loop() -> None:
    while True:
        time.sleep(BACKUP_INTERVAL_HOURS * 3600)
        try:
            backup_database()
        except Exception as exc:
            print(json.dumps({"ts":now(),"level":"error","message":f"scheduled backup failed: {exc}"},separators=(",",":")))
