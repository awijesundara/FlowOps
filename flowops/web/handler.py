"""The HTTP handler: dispatches each request to the route groups in order."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from flowops.db import connect
from flowops.web.admin import AdminRoutes
from flowops.web.assets import AssetRoutes
from flowops.web.auth import AuthRoutes
from flowops.web.base import NOT_HANDLED
from flowops.web.catalog import CatalogRoutes
from flowops.web.events import EventRoutes
from flowops.web.integrations import IntegrationRoutes
from flowops.web.profile import ProfileRoutes
from flowops.web.runbooks import RunbookRoutes
from flowops.web.scim import ScimRoutes
from flowops.web.tasks import TaskRoutes
from flowops.web.users import UserAdminRoutes


class Handler(AssetRoutes, AuthRoutes, ProfileRoutes, AdminRoutes, UserAdminRoutes, IntegrationRoutes, ScimRoutes, CatalogRoutes, RunbookRoutes, TaskRoutes, EventRoutes):
    def do_GET(self):
        try: return self._do_GET()
        except Exception as exc: return self._handle_unexpected_error(exc)

    def do_POST(self):
        try: return self._do_POST()
        except Exception as exc: return self._handle_unexpected_error(exc)

    def do_PATCH(self):
        try: return self._do_PATCH()
        except Exception as exc: return self._handle_unexpected_error(exc)

    def do_DELETE(self):
        try: return self._do_DELETE()
        except Exception as exc: return self._handle_unexpected_error(exc)

    def _do_GET(self):
        path=urllib.parse.urlparse(self.path).path
        for route in (self._get_assets, self._get_auth, self._get_scim, self._get_profile, self._get_events,):
            if route(path) is not NOT_HANDLED: return
        with connect() as db:
            for route in (self._get_auth_db, self._get_profile_db, self._get_users_db, self._get_admin_db, self._get_integrations_db, self._get_catalog_db, self._get_runbooks_db,):
                if route(db, path) is not NOT_HANDLED: return
        self.send_json({"error":"Not found"},404)

    def _do_POST(self):
        path=urllib.parse.urlparse(self.path).path
        for route in (self._post_scim, self._post_integrations,):
            if route(path) is not NOT_HANDLED: return
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.send_json({"error":str(exc)},400)
        with connect() as db:
            for route in (self._post_auth_db, self._post_profile_db, self._post_users_db, self._post_admin_db, self._post_tasks_db, self._post_integrations_db, self._post_catalog_db, self._post_runbooks_db,):
                if route(db, path, payload) is not NOT_HANDLED: return
        self.send_json({"error":"Not found"},404)

    def _do_PATCH(self):
        path=urllib.parse.urlparse(self.path).path
        parts=path.strip("/").split("/")
        for route in (self._patch_scim,):
            if route(path, parts) is not NOT_HANDLED: return
        try: payload=self.body()
        except (ValueError,json.JSONDecodeError) as exc: return self.send_json({"error":str(exc)},400)
        for route in (self._patch_profile, self._patch_users, self._patch_runbooks,):
            if route(path, parts, payload) is not NOT_HANDLED: return
        return self._patch_tasks_tail(path, parts, payload)

    def _do_DELETE(self):
        parsed=urllib.parse.urlparse(self.path)
        path=parsed.path
        parts=path.strip("/").split("/")
        for route in (self._delete_scim, self._delete_profile, self._delete_runbooks, self._delete_catalog, self._delete_users, self._delete_admin,):
            if route(path, parts, parsed) is not NOT_HANDLED: return
        return self._delete_users_tail(path, parts, parsed)
