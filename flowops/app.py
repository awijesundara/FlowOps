"""Process entry point: create the schema, start background workers, serve HTTP."""
from __future__ import annotations

import os
import threading
from http.server import ThreadingHTTPServer

from flowops.backups import backup_loop
from flowops.dashboard_email import dashboard_email_loop
from flowops.schema import init_db
from flowops.serviceops import serviceops_outbox_loop
from flowops.web.handler import Handler
from flowops.webhooks import webhook_dispatcher_loop


def main() -> None:
    init_db()
    threading.Thread(target=webhook_dispatcher_loop, daemon=True).start()
    threading.Thread(target=serviceops_outbox_loop, daemon=True).start()
    threading.Thread(target=backup_loop, daemon=True).start()
    threading.Thread(target=dashboard_email_loop, daemon=True).start()
    host=os.getenv("FLOWOPS_HOST","127.0.0.1"); port=int(os.getenv("FLOWOPS_PORT","8080"))
    print(f"FlowOps listening on http://{host}:{port}")
    ThreadingHTTPServer((host,port),Handler).serve_forever()
