"""Database creation and in-place schema upgrades (init_db)."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

from flowops.audit import append_audit
from flowops.config import DB_PATH, DEFAULT_INSTANCE_SLUG
from flowops.crypto import password_hash, password_valid
from flowops.db import connect, now


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS runbooks (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'draft', mode TEXT NOT NULL DEFAULT 'plan',
          owner TEXT NOT NULL DEFAULT '', scheduled_at TEXT, serviceops_ticket TEXT,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT 'General',
          owner TEXT NOT NULL DEFAULT '', duration INTEGER NOT NULL DEFAULT 15,
          status TEXT NOT NULL DEFAULT 'pending', sort_order INTEGER NOT NULL DEFAULT 0,
          started_at TEXT, completed_at TEXT, automation_url TEXT
        );
        CREATE TABLE IF NOT EXISTS streams (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(runbook_id, name)
        );
        CREATE TABLE IF NOT EXISTS dependencies (
          task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          depends_on_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          PRIMARY KEY(task_id, depends_on_id), CHECK(task_id != depends_on_id)
        );
        CREATE TABLE IF NOT EXISTS saved_views (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL, filters_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
          UNIQUE(user_id, name)
        );
        CREATE TABLE IF NOT EXISTS comments (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY, runbook_id INTEGER, action TEXT NOT NULL, detail TEXT NOT NULL,
          actor TEXT NOT NULL, created_at TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_purge_lock (
          id INTEGER PRIMARY KEY CHECK(id=1), active INTEGER NOT NULL DEFAULT 0
        );
        INSERT OR IGNORE INTO audit_purge_lock(id,active) VALUES(1,0);
        CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
        BEGIN SELECT RAISE(ABORT, 'audit rows are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
        WHEN (SELECT active FROM audit_purge_lock WHERE id=1)=0
        BEGIN SELECT RAISE(ABORT, 'audit rows are immutable except via retention purge'); END;
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          display_name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT 'Viewer',
          team TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
          last_login_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, csrf_token TEXT NOT NULL,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS workspaces (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
          description TEXT NOT NULL DEFAULT '', color TEXT NOT NULL DEFAULT '#7557e8',
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS folders (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(workspace_id, name)
        );
        CREATE TABLE IF NOT EXISTS runbook_types (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, icon TEXT NOT NULL DEFAULT '◇', color TEXT NOT NULL DEFAULT '#7557e8',
          default_description TEXT NOT NULL DEFAULT '', requires_approval INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          UNIQUE(workspace_id, name)
        );
        CREATE TABLE IF NOT EXISTS invitations (
          id INTEGER PRIMARY KEY, email TEXT NOT NULL, role TEXT NOT NULL,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
          accepted_at TEXT, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS password_resets (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, used_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS runbook_teams (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          name TEXT NOT NULL, created_at TEXT NOT NULL, central_team_id INTEGER, UNIQUE(runbook_id,name)
        );
        CREATE TABLE IF NOT EXISTS team_members (
          team_id INTEGER NOT NULL REFERENCES runbook_teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(team_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS central_teams (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(workspace_id,name)
        );
        CREATE TABLE IF NOT EXISTS central_team_members (
          team_id INTEGER NOT NULL REFERENCES central_teams(id) ON DELETE CASCADE,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          PRIMARY KEY(team_id,user_id)
        );
        CREATE TABLE IF NOT EXISTS custom_field_definitions (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          entity_type TEXT NOT NULL CHECK(entity_type IN ('runbook','task')), name TEXT NOT NULL,
          field_type TEXT NOT NULL DEFAULT 'text' CHECK(field_type IN ('text','number','date','boolean','select')),
          options_json TEXT NOT NULL DEFAULT '[]', required INTEGER NOT NULL DEFAULT 0,
          sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          UNIQUE(workspace_id, entity_type, name)
        );
        CREATE TABLE IF NOT EXISTS custom_field_values (
          definition_id INTEGER NOT NULL REFERENCES custom_field_definitions(id) ON DELETE CASCADE,
          entity_id INTEGER NOT NULL, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
          PRIMARY KEY(definition_id, entity_id)
        );
        CREATE TABLE IF NOT EXISTS webhooks (
          id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          name TEXT NOT NULL, url TEXT NOT NULL, secret TEXT NOT NULL,
          provider TEXT NOT NULL DEFAULT 'generic' CHECK(provider IN ('generic','slack','teams')),
          events_json TEXT NOT NULL DEFAULT '["*"]', active INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_deliveries (
          id INTEGER PRIMARY KEY, webhook_id INTEGER NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
          audit_id INTEGER, event_type TEXT NOT NULL, success INTEGER NOT NULL DEFAULT 0,
          status_code INTEGER, error TEXT, attempts INTEGER NOT NULL DEFAULT 0, attempted_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_cursor (
          id INTEGER PRIMARY KEY CHECK (id=1), last_audit_id INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
          id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, scopes_json TEXT NOT NULL DEFAULT '[]',
          created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL,
          last_used_at TEXT, revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS instances (
          id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
          name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS templates (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT 'General',
          created_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS template_tasks (
          id INTEGER PRIMARY KEY, template_id INTEGER NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
          title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT 'General',
          duration INTEGER NOT NULL DEFAULT 15, sort_order INTEGER NOT NULL DEFAULT 0,
          automation_url TEXT, task_type TEXT NOT NULL DEFAULT 'normal', scheduled_offset INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS template_dependencies (
          template_task_id INTEGER NOT NULL REFERENCES template_tasks(id) ON DELETE CASCADE,
          depends_on_template_task_id INTEGER NOT NULL REFERENCES template_tasks(id) ON DELETE CASCADE,
          PRIMARY KEY(template_task_id, depends_on_template_task_id)
        );
        CREATE TABLE IF NOT EXISTS snippets (
          id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL, created_at TEXT NOT NULL,
          UNIQUE(workspace_id, name)
        );
        CREATE TABLE IF NOT EXISTS snippet_tasks (
          id INTEGER PRIMARY KEY, snippet_id INTEGER NOT NULL REFERENCES snippets(id) ON DELETE CASCADE,
          title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', stream TEXT NOT NULL DEFAULT 'General',
          duration INTEGER NOT NULL DEFAULT 15, sort_order INTEGER NOT NULL DEFAULT 0,
          automation_url TEXT, task_type TEXT NOT NULL DEFAULT 'normal', scheduled_offset INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS snippet_dependencies (
          snippet_task_id INTEGER NOT NULL REFERENCES snippet_tasks(id) ON DELETE CASCADE,
          depends_on_snippet_task_id INTEGER NOT NULL REFERENCES snippet_tasks(id) ON DELETE CASCADE,
          PRIMARY KEY(snippet_task_id, depends_on_snippet_task_id)
        );
        CREATE TABLE IF NOT EXISTS instance_settings (
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          key TEXT NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL,
          PRIMARY KEY(instance_id,key)
        );
        CREATE TABLE IF NOT EXISTS serviceops_outbox (
          id INTEGER PRIMARY KEY, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          runbook_id INTEGER REFERENCES runbooks(id) ON DELETE SET NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
          method TEXT NOT NULL, resource TEXT NOT NULL, body_json TEXT, idempotency_key TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL,
          last_error TEXT, created_at TEXT NOT NULL, delivered_at TEXT
        );
        CREATE INDEX IF NOT EXISTS serviceops_outbox_due ON serviceops_outbox(status,next_attempt_at);
        CREATE TABLE IF NOT EXISTS serviceops_inbound_events (
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          event_id TEXT NOT NULL, event_type TEXT NOT NULL, outcome TEXT NOT NULL, received_at TEXT NOT NULL,
          PRIMARY KEY(instance_id,event_id)
        );
        CREATE TABLE IF NOT EXISTS integration_credentials (
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          provider TEXT NOT NULL, secret_encrypted TEXT NOT NULL,
          updated_by INTEGER REFERENCES users(id), updated_at TEXT NOT NULL,
          PRIMARY KEY(instance_id,provider)
        );
        CREATE TABLE IF NOT EXISTS workspace_managers (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,workspace_id)
        );
        CREATE TABLE IF NOT EXISTS oidc_states (
          state TEXT PRIMARY KEY, code_verifier TEXT NOT NULL,
          redirect_to TEXT NOT NULL, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vapid_keys (
          instance_id INTEGER PRIMARY KEY REFERENCES instances(id) ON DELETE CASCADE,
          private_key_pem_encrypted TEXT NOT NULL, public_key_b64url TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS push_subscriptions (
          id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
          endpoint TEXT NOT NULL UNIQUE, p256dh TEXT NOT NULL, auth TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS folder_creator_grants (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          folder_id INTEGER NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,folder_id)
        );
        CREATE TABLE IF NOT EXISTS stream_editor_grants (
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          PRIMARY KEY(user_id,runbook_id)
        );
        CREATE TABLE IF NOT EXISTS runbook_runs (
          id INTEGER PRIMARY KEY, runbook_id INTEGER NOT NULL REFERENCES runbooks(id) ON DELETE CASCADE,
          run_type TEXT NOT NULL CHECK(run_type IN ('live','rehearsal')), outcome TEXT NOT NULL,
          started_at TEXT, ended_at TEXT NOT NULL, planned_seconds INTEGER NOT NULL DEFAULT 0,
          actual_seconds INTEGER NOT NULL DEFAULT 0, task_count INTEGER NOT NULL DEFAULT 0,
          completed_count INTEGER NOT NULL DEFAULT 0, late_count INTEGER NOT NULL DEFAULT 0,
          ended_by TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS task_comments (
          id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
          author TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)
        db.execute("INSERT OR IGNORE INTO instances(slug,name,created_at) VALUES(?,?,?)",(DEFAULT_INSTANCE_SLUG,"FlowOps",now()))
        default_instance=db.execute("SELECT id FROM instances WHERE slug=?",(DEFAULT_INSTANCE_SLUG,)).fetchone()[0]
        for table in ("users","workspaces","invitations","audit"):
            existing={row[1] for row in db.execute(f"PRAGMA table_info({table})")}
            if "instance_id" not in existing: db.execute(f"ALTER TABLE {table} ADD COLUMN instance_id INTEGER REFERENCES instances(id)")
            db.execute(f"UPDATE {table} SET instance_id=? WHERE instance_id IS NULL",(default_instance,))
        columns={row[1] for row in db.execute("PRAGMA table_info(runbooks)")}
        if "workspace_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id)")
        if "actual_started_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_started_at TEXT")
        if "actual_completed_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN actual_completed_at TEXT")
        if "archived" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
        if "folder_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN folder_id INTEGER REFERENCES folders(id)")
        folder_columns={row[1] for row in db.execute("PRAGMA table_info(folders)")}
        if "parent_folder_id" not in folder_columns: db.execute("ALTER TABLE folders ADD COLUMN parent_folder_id INTEGER REFERENCES folders(id)")
        if "runbook_type_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN runbook_type_id INTEGER REFERENCES runbook_types(id)")
        if "parent_runbook_id" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN parent_runbook_id INTEGER REFERENCES runbooks(id)")
        if "home_content" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN home_content TEXT NOT NULL DEFAULT ''")
        if "review_json" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN review_json TEXT")
        if "approved_at" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN approved_at TEXT")
        if "approved_by" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN approved_by TEXT")
        if "run_type" not in columns: db.execute("ALTER TABLE runbooks ADD COLUMN run_type TEXT NOT NULL DEFAULT 'live'")
        type_columns={row[1] for row in db.execute("PRAGMA table_info(runbook_types)")}
        if "requires_approval" not in type_columns: db.execute("ALTER TABLE runbook_types ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0")
        rbteam_columns={row[1] for row in db.execute("PRAGMA table_info(runbook_teams)")}
        if "central_team_id" not in rbteam_columns: db.execute("ALTER TABLE runbook_teams ADD COLUMN central_team_id INTEGER REFERENCES central_teams(id)")
        webhook_columns={row[1] for row in db.execute("PRAGMA table_info(webhooks)")}
        if "provider" not in webhook_columns: db.execute("ALTER TABLE webhooks ADD COLUMN provider TEXT NOT NULL DEFAULT 'generic'")
        for column,definition in {
          "serviceops_type":"TEXT","serviceops_title":"TEXT","serviceops_state":"TEXT",
          "serviceops_priority":"TEXT","serviceops_synced_at":"TEXT","serviceops_request_id":"TEXT",
          "automation_context_json":"TEXT",
          "servicenow_change_number":"TEXT","servicenow_sys_id":"TEXT","servicenow_state":"TEXT","servicenow_synced_at":"TEXT",
          "serviceops_alert":"TEXT"
        }.items():
            if column not in columns: db.execute(f"ALTER TABLE runbooks ADD COLUMN {column} {definition}")
        task_columns={row[1] for row in db.execute("PRAGMA table_info(tasks)")}
        task_migrations={
          "task_type":"TEXT NOT NULL DEFAULT 'normal'", "scheduled_offset":"INTEGER NOT NULL DEFAULT 0",
          "owner_user_id":"INTEGER REFERENCES users(id)", "owner_team_id":"INTEGER REFERENCES runbook_teams(id)",
          "validation_result":"TEXT", "validation_comment":"TEXT", "blocked_reason":"TEXT",
          "serviceops_ctask":"TEXT", "serviceops_ctask_team":"TEXT", "serviceops_ctask_state":"TEXT",
          "automation_status":"TEXT NOT NULL DEFAULT 'idle'", "automation_result":"TEXT",
          "automation_attempts":"INTEGER NOT NULL DEFAULT 0", "skip_reason":"TEXT",
          "escalated":"INTEGER NOT NULL DEFAULT 0", "escalation_reason":"TEXT",
          "incident":"INTEGER NOT NULL DEFAULT 0", "incident_reason":"TEXT",
          "dependency_logic":"TEXT NOT NULL DEFAULT 'and'",
          "checklist_json":"TEXT", "recipients":"TEXT NOT NULL DEFAULT ''", "message":"TEXT NOT NULL DEFAULT ''",
          "communication_result":"TEXT", "fixed_start_at":"TEXT",
          "linked_runbook_id":"INTEGER REFERENCES runbooks(id) ON DELETE SET NULL",
          "force_started":"INTEGER NOT NULL DEFAULT 0", "force_start_reason":"TEXT",
        }
        for column,definition in task_migrations.items():
            if column not in task_columns: db.execute(f"ALTER TABLE tasks ADD COLUMN {column} {definition}")
        user_columns={row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "dashboard_widgets" not in user_columns: db.execute("ALTER TABLE users ADD COLUMN dashboard_widgets TEXT")
        for column,definition in {
          "avatar_path":"TEXT", "title":"TEXT NOT NULL DEFAULT ''",
          "timezone":"TEXT NOT NULL DEFAULT 'Asia/Tokyo'", "date_format":"TEXT NOT NULL DEFAULT 'system'",
          "locale":"TEXT NOT NULL DEFAULT 'en'",
          # Sign-in hardening (ServiceOps parity): which provider owns the
          # account, persistent lockout, TOTP multi-factor, and a version
          # bumped by password/MFA changes to void half-finished sign-ins.
          "auth_provider":"TEXT NOT NULL DEFAULT 'local'", "external_id":"TEXT NOT NULL DEFAULT ''",
          "failed_login_count":"INTEGER NOT NULL DEFAULT 0", "locked_until":"INTEGER",
          "mfa_enabled":"INTEGER NOT NULL DEFAULT 0", "mfa_secret_encrypted":"TEXT",
          "mfa_pending_secret_encrypted":"TEXT", "mfa_backup_codes":"TEXT", "mfa_last_step":"INTEGER",
          "auth_version":"INTEGER NOT NULL DEFAULT 1",
        }.items():
            if column not in user_columns: db.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        if "nonce" not in {row[1] for row in db.execute("PRAGMA table_info(oidc_states)")}:
            db.execute("ALTER TABLE oidc_states ADD COLUMN nonce TEXT")
        db.execute("""CREATE TABLE IF NOT EXISTS mfa_challenges (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          auth_version INTEGER NOT NULL, source TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
          expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
        )""")
        session_columns={row[1] for row in db.execute("PRAGMA table_info(sessions)")}
        for column,definition in {"ip_address":"TEXT NOT NULL DEFAULT ''","user_agent":"TEXT NOT NULL DEFAULT ''"}.items():
            if column not in session_columns:db.execute(f"ALTER TABLE sessions ADD COLUMN {column} {definition}")
        db.execute("UPDATE workspaces SET color='#7557e8' WHERE color='#3158c7'")
        db.execute("UPDATE users SET role='Admin' WHERE role='Administrator'")
        db.execute("UPDATE users SET role='Editor' WHERE role='Runbook Manager'")
        db.execute("UPDATE users SET role='Member' WHERE role IN ('Operator','Viewer')")
        db.execute("INSERT OR IGNORE INTO workspaces(name,description,color,created_at,instance_id) VALUES(?,?,?,?,?)",("Resilience Operations","Production change, recovery, and release orchestration.","#7557e8",now(),default_instance))
        default_workspace=db.execute("SELECT id FROM workspaces WHERE instance_id=? ORDER BY id LIMIT 1",(default_instance,)).fetchone()[0]
        db.execute("UPDATE runbooks SET workspace_id=? WHERE workspace_id IS NULL",(default_workspace,))
        if db.execute("SELECT COUNT(*) FROM runbooks").fetchone()[0] == 0:
            stamp = now()
            cur = db.execute("INSERT INTO runbooks(name,description,status,mode,owner,scheduled_at,serviceops_ticket,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("Payments platform release", "Coordinated production release with validation and rollback gates.", "ready", "plan", "Release Management", "2026-09-08T21:00", "CHG0001042", stamp, stamp))
            rid = cur.lastrowid
            seed = [
                ("Confirm change approval", "Governance", "Maya Chen", 10),
                ("Notify stakeholders", "Communications", "Liam Park", 5),
                ("Enable maintenance mode", "Platform", "SRE Team", 10),
                ("Deploy application release", "Deployment", "Release Team", 25),
                ("Run production smoke tests", "Validation", "QA Team", 20),
                ("Restore traffic", "Platform", "SRE Team", 10),
                ("Close change and publish summary", "Governance", "Maya Chen", 10),
            ]
            ids=[]
            for pos, (title, stream, owner, duration) in enumerate(seed):
                ids.append(db.execute("INSERT INTO tasks(runbook_id,title,stream,owner,duration,sort_order) VALUES(?,?,?,?,?,?)", (rid,title,stream,owner,duration,pos)).lastrowid)
            for task_id, predecessor in zip(ids[1:], ids[:-1]):
                db.execute("INSERT INTO dependencies VALUES(?,?)", (task_id, predecessor))
            append_audit(db, rid, "runbook.created", "Sample release runbook created", "FlowOps")
        db.execute("UPDATE runbooks SET workspace_id=? WHERE workspace_id IS NULL",(default_workspace,))
        for stream_rid, stream, pos in db.execute(
            "SELECT runbook_id, stream, MIN(sort_order) FROM tasks GROUP BY runbook_id, stream ORDER BY runbook_id, MIN(sort_order)"
        ).fetchall():
            db.execute(
                "INSERT OR IGNORE INTO streams(runbook_id,name,sort_order,created_at) VALUES(?,?,?,?)",
                (stream_rid, stream, pos, now()),
            )
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            # The bootstrap administrator never gets a known password: use
            # FLOWOPS_BOOTSTRAP_PASSWORD, or generate one and print it once,
            # at the only moment it is created.
            password=os.getenv("FLOWOPS_BOOTSTRAP_PASSWORD","")
            if len(password)<12:
                password=secrets.token_urlsafe(18)
                print(json.dumps({"ts":now(),"level":"warning","message":"FLOWOPS_BOOTSTRAP_PASSWORD was not set (or is under 12 characters). Generated a one-time administrator password; sign in as admin and change it now.","bootstrap_password":password},separators=(",",":")),flush=True)
            db.execute("INSERT INTO users(username,display_name,email,role,team,password_hash,created_at,instance_id) VALUES(?,?,?,?,?,?,?,?)",
                       ("admin","Administrator",os.getenv("FLOWOPS_BOOTSTRAP_EMAIL","").strip().lower(),"Admin","",password_hash(password),now(),default_instance))
        # Earlier releases seeded these accounts with passwords published in
        # the README. Disable a seeded operator that still has its published
        # password (kept, not deleted, so audit history stays intact) and
        # warn while the administrator still uses its published default.
        for username,published in (("operator","Operator!Preview2026"),("admin","FlowOps!Preview2026")):
            row=db.execute("SELECT * FROM users WHERE username=? AND active=1 AND auth_provider='local'",(username,)).fetchone()
            if not row or not password_valid(published,row["password_hash"]): continue
            if username=="operator":
                db.execute("UPDATE users SET active=0 WHERE id=?",(row["id"],))
                db.execute("DELETE FROM sessions WHERE user_id=?",(row["id"],))
                append_audit(db,None,"auth.default_account_disabled","operator: still had its published preview password","FlowOps",row["instance_id"])
            elif os.getenv("FLOWOPS_PREVIEW_TOKENS","false").lower()!="true":
                print(json.dumps({"ts":now(),"level":"warning","message":"The admin account still uses the published preview password. Change it now."},separators=(",",":")),flush=True)
        defaults={"workspace_name":"Resilience Operations","timezone":"Asia/Tokyo","require_approval":"true","session_hours":"8","serviceops_enabled":"true","directory_enabled":"false","directory_domain":"",
          "serviceops_url":os.getenv("SERVICEOPS_URL","http://host.docker.internal:8080"),"serviceops_sync_on_live":"true","serviceops_sync_on_complete":"true","serviceops_require_approved":"true","serviceops_trigger_workflow":"false","serviceops_record_evidence":"true",
          "local_auth_enabled":"true","login_max_attempts":"5","login_lockout_minutes":"15",
          "ldap_enabled":"false","ldap_url":"","ldap_bind_dn":"","ldap_base_dn":"","ldap_user_filter":"(&(objectClass=user)(sAMAccountName={username}))",
          "ldap_group_base_dn":"","ldap_group_search_filter":"","ldap_nested_groups":"false","ldap_start_tls":"true","ldap_validate_cert":"true",
          "ldap_require_access_group":"false","ldap_role_mappings":"{}","ldap_team_mappings":"{}","ldap_default_role":"Member","ldap_domain":"",
          "oidc_auto_provision":"false","oidc_role_claim":"realm_access.roles","oidc_role_mappings":"{}","oidc_team_mappings":"{}","oidc_default_role":"Member","oidc_required_acr":"",
        }
        for key,value in defaults.items(): db.execute("INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)",(key,value,now()))
        for key,value in defaults.items():
            legacy=db.execute("SELECT value FROM settings WHERE key=?",(key,)).fetchone()
            db.execute("INSERT OR IGNORE INTO instance_settings(instance_id,key,value,updated_at) VALUES(?,?,?,?)",(default_instance,key,legacy[0] if legacy else value,now()))
