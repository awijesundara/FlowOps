"""Process-wide settings read from the environment, and fixed product constants."""
from __future__ import annotations

import os
from pathlib import Path

# The repository (or image) root that holds VERSION and static/.
ROOT = Path(__file__).resolve().parent.parent

VERSION = ((ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").exists() else "0.0.0")

DB_PATH = os.getenv("FLOWOPS_DB", str(ROOT / "flowops.db"))

BACKUP_DIR = Path(os.getenv("FLOWOPS_BACKUP_DIR", str(Path(DB_PATH).parent / "backups")))

AVATAR_DIR = Path(os.getenv("FLOWOPS_AVATAR_DIR", str(Path(DB_PATH).parent / "avatars")))

BACKUP_RETAIN = int(os.getenv("FLOWOPS_BACKUP_RETAIN", "14"))

BACKUP_INTERVAL_HOURS = float(os.getenv("FLOWOPS_BACKUP_INTERVAL_HOURS", "6"))

CF_ACCESS_TEAM_DOMAIN = os.getenv("FLOWOPS_CF_ACCESS_TEAM_DOMAIN", "")

CF_ACCESS_AUD = os.getenv("FLOWOPS_CF_ACCESS_AUD", "")

STATIC = ROOT / "static"

MAX_BODY = 1_000_000

DEFAULT_INSTANCE_SLUG = "flowops"

ROLE_PERMISSIONS = {
    "Admin": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync","admin:access","admin:users","admin:settings","backups:read"},
    "Editor": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync"},
    "Member": {"runbooks:view","runbooks:execute"},
    "Stakeholder": {"runbooks:view"},
    "Workspace Manager": {"runbooks:view","runbooks:edit","runbooks:execute","integrations:sync"},
    "Folder Creator": {"runbooks:view","runbooks:execute"},
    "Stream Editor": {"runbooks:view","runbooks:execute"},
}

SCOPED_ROLES = {"Workspace Manager","Folder Creator","Stream Editor"}

# i18n scaffolding: English + Japanese (matching this app's existing
# Asia/Tokyo default timezone), wired into a representative slice of the
# UI (login, primary nav, runbook-detail task actions) -- not a full
# translation of the app, a deliberate, stated scope call.
SUPPORTED_LOCALES = {"en","ja"}

TOKEN_SCOPE_PERMISSIONS = {
    "runbooks:read": {"runbooks:view"},
    "runbooks:write": {"runbooks:view","runbooks:edit","runbooks:execute"},
    "scim:provision": {"scim:provision"},
    # Deliberately its own narrow scope rather than admin:access -- a token
    # meant only to pull encrypted backup files off-host (see the
    # off-node backup CronJob) has no business also being able to manage
    # users or settings if it were ever leaked.
    "backups:read": {"backups:read"},
}

# SCIM 2.0 schema URNs (RFC 7643/7644) -- reused verbatim by every SCIM
# response builder below.
SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"

SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"

SCIM_GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group"

# The narrow, documented set of attributes this hand-rolled SCIM filter
# parser understands -- matches what real IdP SCIM connectors (Okta,
# Entra) actually send in practice, not the full SCIM filter grammar.
SCIM_FILTER_ATTRIBUTES = {"username":"username","emails.value":"email","displayname":"display_name","active":"active"}

# The canonical set of every audit action append_audit() can emit, used to
# drive the per-webhook granular event-type subscription checklist (a
# webhook's events_json can already hold any string list -- this is just
# the UI's source of truth for what's selectable, kept in sync with real
# append_audit() call sites by test_webhook_event_actions_list_matches_
# real_append_audit_call_sites, which regex-scans this file itself).
WEBHOOK_EVENT_ACTIONS = (
    "admin.backup_created","admin.folder_creator_granted","admin.folder_creator_revoked",
    "admin.session_revoked","admin.settings_updated","admin.stream_editor_granted",
    "admin.stream_editor_revoked","admin.user_created","admin.user_deleted","admin.user_invited",
    "admin.user_updated","admin.workspace_created","admin.workspace_manager_granted",
    "admin.workspace_manager_revoked","api_token.created","api_token.revoked","audit.exported",
    "audit.retention_purged","auth.invitation_accepted","auth.login","auth.logout",
    "auth.password_reset_completed","auth.password_reset_delivery_failed",
    "auth.password_reset_requested","auth.sso_login","auth.oidc_login","auth.login_failed","auth.login_blocked",
    "auth.account_locked","auth.account_unlocked","auth.default_account_disabled","auth.user_provisioned",
    "auth.mfa_enabled","auth.mfa_disabled","auth.mfa_reset","auth.mfa_failed","auth.mfa_backup_codes_regenerated","central_team.created","central_team.deleted",
    "central_team.member_added","central_team.member_removed","comment.added","custom_field.created",
    "custom_field.deleted","folder.created","folder.deleted","instance.created",
    "integration.configured","integration.tested","profile.avatar_updated","profile.password_changed",
    "profile.updated","runbook.approved","runbook.archived","runbook.created","runbook.deleted","runbook.duplicated",
    "runbook.edited","runbook.rehearsal_reset","runbook.reviewed","runbook.transition","runbook_type.created",
    "runbook_type.deleted","servicenow.lifecycle","servicenow.synced","serviceops.ctask_sync_failed",
    "serviceops.ctask_synced","serviceops.ctasks_imported","serviceops.ctasks_synced",
    "serviceops.change_withdrawn","serviceops.ctask_state_received","serviceops.event_received",
    "serviceops.events_secret_rotated","serviceops.evidence_failed","serviceops.evidence_recorded",
    "serviceops.lifecycle","serviceops.sync_failed","serviceops.synced","serviceops.writeback_retried","snippet.deleted",
    "snippet.inserted","snippet.saved","stream.created","stream.deleted","stream.renamed",
    "task.automation_result","task.automation_running","task.automation_test_fired",
    "task.bulk_edited","task.checklist_updated","task.commented","task.communication_sent","task.created","task.csv_imported","task.edited","task.escalated","task.force_started","task.ready",
    "task.escalation_cleared","task.incident_flagged","task.incident_cleared","task.transition",
    "team.created","template.deleted","template.saved","webhook.created","webhook.deleted",
)
