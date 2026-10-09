"""Server-sent live event stream."""
from __future__ import annotations

import json
import time

from flowops.db import connect, rows
from flowops.web.base import BaseHandler, NOT_HANDLED


class EventRoutes(BaseHandler):
    def stream_events(self):
        """Authenticated same-origin SSE feed backed by the durable audit sequence."""
        with connect() as db:
            user=self.current_user(db)
            if not user or "runbooks:view" not in user["permissions"]:
                return self.send_json({"error":"Authentication required"},401)
            instance_id=user["instance_id"]
            version=db.execute("SELECT COALESCE(MAX(id),0) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
        # No socket timeout was ever set on this (or any) connection: a
        # cleanly closed/reset client is already handled below, but a
        # half-open one -- dropped mid-stream with no FIN/RST, e.g. a
        # laptop sleeping or a NAT/firewall silently expiring the session --
        # would leave wfile.write() blocked indefinitely, holding one of
        # ThreadingHTTPServer's one-thread-per-connection threads forever.
        # 30s is comfortably above both the 1s poll tick and the 15s
        # heartbeat, so it never fires during normal operation.
        self.connection.settimeout(30)
        self.send_response(200); self.send_header("Content-Type","text/event-stream; charset=utf-8")
        self.send_header("Cache-Control","no-cache, no-store"); self.send_header("Connection","keep-alive")
        self.send_header("X-Accel-Buffering","no"); self.end_headers()
        try:
            self.wfile.write(f"event: connected\ndata: {{\"version\":{version}}}\n\n".encode()); self.wfile.flush()
            for tick in range(300):
                time.sleep(1)
                with connect() as db:
                    current=db.execute("SELECT COALESCE(MAX(id),0) FROM audit WHERE instance_id=?",(instance_id,)).fetchone()[0]
                    events=rows(db.execute("SELECT id,runbook_id,action,detail,actor,created_at FROM audit WHERE instance_id=? AND id>? ORDER BY id LIMIT 25",(instance_id,version))) if current!=version else []
                if current != version:
                    for event in events:
                        event["version"]=event["id"]
                        self.wfile.write(f"event: workspace\ndata: {json.dumps(event,separators=(',',':'))}\n\n".encode())
                    version=current; self.wfile.flush()
                elif tick % 15 == 0:
                    self.wfile.write(b": heartbeat\n\n"); self.wfile.flush()
        except (BrokenPipeError,ConnectionResetError,TimeoutError):
            return

    def _get_events(self, path):
        if path=="/api/events": return self.stream_events()
        return NOT_HANDLED
