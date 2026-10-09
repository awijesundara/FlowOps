"""The single-page app shell, static assets and health endpoints."""
from __future__ import annotations

import re

from flowops.config import VERSION
from flowops.web.base import BaseHandler, NOT_HANDLED


class AssetRoutes(BaseHandler):
    def _get_assets(self, path):
        if path=="/": return self.static("index.html","text/html; charset=utf-8")
        # The SPA does its own client-side routing (see navigate()/boot() in
        # app.js) and updates the URL via history.pushState so views and
        # individual runbooks are bookmarkable/shareable/refresh-safe --
        # previously there was no server route for any of these, so a
        # refresh or direct link landed on a raw {"error":"Not found"} JSON
        # body instead of the app. These just serve the same shell; app.js
        # reads location.pathname on load to restore the right view.
        if path in ("/runbooks","/my-tasks","/templates","/analytics","/admin") or re.match(r"^/runbooks/\d+$",path) or re.match(r"^/admin/[A-Za-z]+$",path):
            return self.static("index.html","text/html; charset=utf-8")
        if path=="/app.js": return self.static("app.js","application/javascript; charset=utf-8")
        if path=="/strings.js": return self.static("strings.js","application/javascript; charset=utf-8")
        if path=="/sw.js": return self.static("sw.js","application/javascript; charset=utf-8")
        if path=="/monitor.html": return self.static("monitor.html","text/html; charset=utf-8")
        if path=="/monitor.js": return self.static("monitor.js","application/javascript; charset=utf-8")
        if path=="/styles.css": return self.static("styles.css","text/css; charset=utf-8")
        if path=="/api-explorer": return self.static("api-explorer.html","text/html; charset=utf-8")
        if path=="/api-explorer.js": return self.static("api-explorer.js","application/javascript; charset=utf-8")
        if path=="/openapi.json": return self.static("openapi.json","application/json; charset=utf-8")
        if path in ("/health","/ready"): return self.send_json({"status":"ok","service":"flowops","version":VERSION})
        return NOT_HANDLED
