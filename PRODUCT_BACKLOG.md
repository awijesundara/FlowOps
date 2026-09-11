# FlowOps Product Backlog

This is the authoritative development contract for FlowOps. Every implementation
change must map to a story here, preserve phase order, include acceptance tests,
and update the delivery status. New work must not bypass unfinished P0 stories
in the active phase unless the backlog is explicitly amended by the product owner.

Priority: **P0** blocks phase shipment; **P1** is expected; **P2** may move.
Size: **S** under three days; **M** three days to two weeks; **L** must be split.

Status: `DONE`, `PARTIAL`, `NEXT`, or `BACKLOG`.

## Phase 1 — MVP: Single Team, Manual Runbook Execution

Goal: one isolated customer team can build, assign, and execute a runbook live.

### Epic 1.1 — Identity and Access Foundation

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Customer creates an account and isolated instance | P0 | M | DONE |
| Admin invites users by email | P0 | S | DONE |
| User logs in with email and password | P0 | S | DONE |
| Admin assigns fixed Admin, Editor, or Member role | P0 | M | DONE |
| Session expiry and password reset | P0 | S | DONE |

Role acceptance: Admin may create, edit, and delete instance content; Editor may
create and edit runbooks; Member may act only on assigned tasks. Role changes
take effect without re-login.

Identity delivery note (2026-09-07): invitation acceptance and password reset
use hashed, expiring, single-use tokens, duplicate-account protection,
non-enumerating reset requests, session invalidation, audit events, and the
responsive login UI. Production mode delivers purpose-built SMTP messages and
does not return tokens; local preview token display is explicitly gated by
`FLOWOPS_PREVIEW_TOKENS`. Regression coverage proves invitation delivery,
password-reset delivery, single use, and session invalidation.

Instance-isolation evidence (2026-09-06): self-registration creates a dedicated
organization, initial Admin, default workspace, tenant settings, and tenant audit
chain. Server-side authorization scopes users, workspaces, runbooks, tasks,
assignment options, dashboards, live events, and integration configuration to
the authenticated instance. Existing databases migrate into the default FlowOps
instance without discarding records. Cross-tenant read, execution, and admin
mutation attempts return not found; regression coverage is in
`test_customer_instance_registration_and_cross_tenant_isolation`.

### Epic 1.2 — Workspace and Runbook Structure

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Admin creates a workspace | P0 | S | DONE |
| Editor creates a runbook inside a workspace | P0 | M | DONE |
| Editor sets runbook name and scheduled start | P0 | S | DONE |
| Editor duplicates a runbook | P1 | S | DONE |
| Editor archives a completed runbook | P1 | S | DONE |

### Epic 1.3 — Streams and Tasks

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Editor creates streams within a runbook | P0 | S | DONE |
| Editor creates a task with description, owner, start, and duration | P0 | M | DONE |
| Editor sets task dependencies | P0 | L | DONE |
| Dependencies block task start until predecessors finish | P0 | M | DONE |
| Member sees only tasks assigned to them or their team | P0 | M | DONE |
| Member marks assigned task started, complete, or blocked | P0 | S | DONE |
| Incomplete task becomes late after scheduled end | P0 | M | DONE |

Dependency logic is the highest-risk Phase 1 item and requires model, UI,
real-time, and scheduling tests before shipment.

### Epic 1.4 — Teams

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Editor creates a runbook team and adds users | P0 | M | DONE |
| Editor assigns a task to a team | P0 | S | DONE |
| Member sees their runbook team | P1 | S | DONE |

### Epic 1.5 — Live Execution View

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Task status reaches other viewers within two seconds without refresh | P0 | L | DONE |
| Users see a live list or timeline of all tasks | P0 | M | DONE |
| Users filter tasks by stream, owner, or status | P1 | M | DONE |

Real-time acceptance: changes appear for all viewers within two seconds without
manual refresh; concurrency must be load-tested before building later phases.

Load-test evidence (2026-09-10, `tools/load_test_realtime.py` against a
disposable local instance, not production): the SSE feed (`/api/events`) is a
1-second server-side poll per connection, not push-based, so worst-case
propagation is bounded by design. Measured with real concurrent HTTP clients
(not simulated): 25 viewers → p50 0.708s / max 0.710s; 60 viewers → p50 0.520s
/ max 0.723s; 150 viewers → p50 0.524s / max 0.917s. All three runs delivered
to 100% of connected clients with zero errors and stayed under the 2-second
target with wide margin; server logs were clean (no errors/tracebacks) at all
three concurrency levels. 150 concurrent viewers already exceeds Phase 1's
single-team MVP scope; validating the "hundreds of users" target from Epic 4.6
is out of scope for this pass and remains separately tracked there.

### Epic 1.6 — Basic Audit Trail

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Every task status/edit is logged with timestamp and actor | P0 | M | DONE |
| Admin views the audit log for one runbook | P1 | S | DONE |

Exit: a real team plans dependencies, executes live, receives real-time state,
and retrieves an audit trail with no automation dependency.

## Phase 2 — Collaboration and Governance

### Epic 2.1 — Expanded Roles

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Workspace Manager, Stakeholder, and Member scoped roles | P0 | L | DONE |
| Folder-scoped Runbook Creator | P0 | M | DONE |
| Stream Editor rights | P1 | M | DONE |
| Global Stakeholder read-only visibility | P1 | M | DONE |

Four new roles exist alongside Admin/Editor/Member: `Stakeholder` (global,
instance-wide read-only — `{"runbooks:view"}`, no edit or execute, closing
"Global Stakeholder read-only visibility" fully), `Workspace Manager`
(Editor-equivalent rights, but narrowed at authorization time to only the
workspaces they're explicitly granted via `workspace_managers`), `Folder
Creator` (view/execute only, plus the specific right to create a runbook
inside a folder they're granted via `folder_creator_grants` — denied
without a grant even with a valid folder_id), and `Stream Editor`
(view/execute only, plus the right to create/edit/delete streams and edit
tasks — not runbook fields — within a runbook they're granted via
`stream_editor_grants`). `POST/GET/DELETE /api/admin/{workspace-managers,
folder-creators,stream-editors}` manage grants; `Administration → Scoped
roles` is the admin UI for granting and revoking them. Scoping is enforced
via two new authorization helpers (`require_scoped_edit` narrows to
Folder Creator/Stream Editor grants or full `runbooks:edit`;
`require_workspace_scoped_edit` narrows a `Workspace Manager` to their
granted workspace) applied at task/stream create-edit-delete and at
runbook create/duplicate/save-as-template/archive/teams/field-edit.
Regression tests create a real user of each new role, log in as them, and
assert both the pre-grant 403 and the post-grant 200/201 — not just that
the role string exists.

Member runbook visibility: `DONE`. `GET /api/runbooks` now excludes any
runbook where the requesting Member has no assigned task — personally
(`owner_user_id`) or via a team they belong to, directly (`team_members`)
or through a central team (`central_team_members`) — instead of listing
every runbook in the instance. This is deliberately scoped to the list
endpoint only, reusing the same assignment relationship
`runbook_document()` already uses to filter a Member's *task* list within
a runbook they can open; it does not touch `owns_runbook()` (the
lower-level check used by comments, teams, and direct-link access across
many endpoints), so a Member who already has a runbook open via a shared
link is unaffected — only what appears in their own runbook list/command
center changed. Aggregate dashboard counts (`/api/dashboard`) remain
instance-wide, unscoped, since they were never per-user to begin with.
Covered by `test_member_runbook_list_only_shows_runbooks_with_an_assigned_task`.

Workspace structural setup — creating folders, runbook types, and
templates themselves (as opposed to runbooks within them) — remains
Admin/Editor only; `Workspace Manager` does not extend to that layer yet.

### Epic 2.2 — Folders and Runbook Types

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Workspace folders | P0 | S | DONE |
| Custom runbook types with name, icon, and color | P1 | M | DONE |
| Approval flow attached to runbook type | P1 | L | DONE |
| Creator selects a runbook type and inherits defaults | P0 | S | DONE |
| Nested folders | P2 | M | DONE |
| Saved, reusable runbook-list filter views | P2 | M | DONE |
| Runbook home page for instructions and links | P2 | M | DONE |

Nested folders (2026-09-11): `folders.parent_folder_id` (nullable,
self-referencing) is set at creation time (`POST /api/folders` accepts
`parent_folder_id`, rejecting an invalid one) -- arbitrary depth, not
capped at one level like linked runbooks. The runbook-creation folder
picker renders the tree depth-first with indentation so nesting is
visible, not just a flat alphabetical list. Covered by
`test_nested_folders_track_parent_and_reject_invalid_parent`.

Runbook home page (2026-09-11): `runbooks.home_content` is a free-text
field (up to 8000 chars, newlines and URLs preserved/auto-linked in the
rendered view) editable through the existing generic runbook field-edit
endpoint (`PATCH /api/runbooks/{id}`) -- gated the same way every other
runbook field already is (`runbooks:edit`/workspace-scoped, blocked once
`complete`/`cancelled`). Rendered as a "Runbook home" sidebar card at the
top of the detail view with an Edit action for Editors/Admins. Covered
by `test_runbook_home_content_is_editable_and_returned_in_document`.

Saved runbook-list filter views (2026-09-11): `saved_views` are per-user
(`POST/GET/DELETE /api/saved-views`), storing an arbitrary `filters`
JSON object (today: search text + status) under a name unique per user.
The Runbooks page toolbar has a "Saved views" picker (applies the
stored filters immediately) and a "☆ Save view" button (captures the
current search box + status filter). Covered by
`test_saved_views_are_per_user_created_listed_and_deleted` (including
cross-user isolation -- one user's saved views are invisible to
another).

Approval flow evidence (2026-09-10): `runbook_types.requires_approval`
(set at type-creation time, "New runbook type" admin action) gates the
`ready → live` transition specifically -- `POST /api/runbooks/{id}/transition`
checking `target=='live'` returns 409 ("... runbooks require approval
before going live") if the runbook's type requires approval and
`runbooks.approved_at` is still null, checked against the *type at
transition time* (not cached at creation), so changing a type's
requirement takes effect immediately for every runbook of that type.
`POST /api/runbooks/{id}/approve` (`admin:access` only) stamps
`approved_at`/`approved_by` once and 409s on a second approval attempt.
Runbook types without `requires_approval` are completely unaffected --
covered by a dedicated regression test alongside the gate itself. The
runbook detail view shows a status chip ("Approval required" / "✓
Approved by ...") and an Approve button for admins on gated types.

### Epic 2.3 — Templates

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Save runbook as reusable template | P0 | M | DONE |
| Create runbook from saved template | P0 | S | DONE |
| Scope template visibility by workspace | P2 | M | DONE |
| Reusable task snippets (subset of tasks, not a whole runbook), capped at 100 tasks | P2 | M | BACKLOG |

Scoping evidence (2026-09-10): previously any active workspace could be
passed to `POST /api/templates/{id}/use`, letting a template created in one
workspace get used to create a runbook in a completely different one --
templates were only nominally workspace-owned. Fixed: "use" always creates
in the template's *own* workspace now, silently ignoring any
`workspace_id` override in the request rather than trusting it. `GET
/api/templates` also accepts `?workspace_id=` to filter the list. The
picker UI itself doesn't yet filter by the currently-selected workspace
client-side (it lists everything the tenant can see, grouped by category),
but the actual cross-workspace reuse the story is about is closed.
Regression test proves a template created in one workspace is excluded
from a `?workspace_id=` filter for a different workspace and that "use"
lands the new runbook in the template's own workspace even when a
different one is requested.

### Epic 2.4 — Central and Linked Teams

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Workspace central teams | P0 | M | DONE |
| Link central team into runbook | P0 | M | DONE |
| Central membership changes propagate | P1 | M | DONE |

UI evidence (2026-09-10): `Administration → Central teams` creates/deletes
central teams and adds/removes members; the runbook detail view has a
"Link central team" action under a new "Linked runbooks" concept card.

Propagation evidence (2026-09-10): a runbook team linked to a central team
resolves membership live via `team_member_user_ids()` (direct
`team_members` UNION the linked central team's current
`central_team_members`) on every read, rather than copying members at link
time. Regression test adds a member to a central team *after* linking it
into a live runbook and asserts the runbook team's member list and count
update immediately with no re-link step, that a user whose only membership
is via the central team can act on tasks assigned to that team, and that
removing them from the central team removes that permission immediately.
Central-team CRUD and membership management currently exist only as API
endpoints (`/api/central-teams`, `.../members`); there is no admin UI for
managing central teams or linking one into a runbook yet.

### Epic 2.5 — CSV and Bulk Management

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Import tasks from CSV | P1 | M | DONE |
| Bulk-edit owner or timing | P2 | M | DONE |

Import tasks from CSV: `DONE`. `POST /api/runbooks/{id}/tasks-import` accepts
a raw CSV body (`title` column required; `stream`, `duration`, `task_type`,
`scheduled_offset`, `description`, `automation_url` optional), auto-creates
any streams referenced that don't already exist, and falls back an unknown
`task_type` to `normal` rather than rejecting the row. Covered by
`test_task_csv_import_creates_tasks_and_backfills_unknown_type_to_normal`
and `test_task_csv_import_rejects_csv_missing_title_column`. Runbook detail
view has an "Import CSV" button (Editor/Admin only, gated on
`runbooks:edit`) that reads a local file and posts it.

Bulk-edit owner or timing: `DONE`. `POST /api/runbooks/{id}/tasks-bulk-edit`
takes a `task_ids` list plus any of `owner_user_id`/`owner_team_id`/
`duration`/`scheduled_offset`, applies them to exactly the selected tasks
in one UPDATE, and rejects an empty or entirely-invalid selection. A "Bulk
edit" button in the runbook detail view lets you pick tasks by number and
set a new duration. Covered by
`test_bulk_edit_tasks_updates_owner_and_duration_across_selected_tasks_only`
and `test_bulk_edit_tasks_rejects_empty_or_invalid_task_id_selection`.

### Epic 2.6 — Node Map

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Dependency graph identifies sequence and bottlenecks | P1 | L | DONE |
| Nodes color-code task status | P2 | S | DONE |

Dependency graph identifies sequence and bottlenecks: `DONE`. The node-map
view now lays tasks out in columns by dependency depth (each task's column
is `1 + max(column of its dependencies)`, `0` for entry points), so
parallel branches render side by side instead of one flat left-to-right
row — the layout itself shows real fan-out/fan-in structure, not just
task-creation order. Nodes on the runbook's already-computed
`critical_path` (the same list the timeline view uses) get a visually
distinct border and a "Critical path" badge, identifying the
zero-slack bottleneck sequence directly on the graph.

Exit: multiple teams self-serve within governed boundaries and reuse structures
and central team rosters.

## Phase 3 — Automation and Integration

### Epic 3.1 — Integration Framework

Named connections (P0/M), API key/basic/bearer/OAuth authentication (P0/L),
automatic context (P1/M), and sandbox action tests (P0/M) remain `BACKLOG`
-- there is still no reusable, named "connection" abstraction with its own
stored credentials; an automation task's URL is per-task, not backed by a
shared, admin-managed connection profile.

Triggered actions with URL and payload template (P0/L) and auto-complete
on success (P1/M): `DONE` (2026-09-11) via a new `automation` task type.
`PATCH /api/tasks/{id}` starting an automation task (`pending`/`failed` ->
`running`) validates an `automation_url` is set, then returns immediately
with `automation_status: "queued"` while a background thread POSTs
`{request_id, task_id, task_title}` to that URL and reports the eventual
outcome asynchronously -- the triggering HTTP request is never blocked on
slow/unreliable external I/O. Success (2xx) auto-completes the task and
sets `automation_status: "success"`; failure (non-2xx, timeout, connection
error) sets `automation_status: "failed"` and the task status to
`failed`, storing the error detail in `automation_result` for the
operator. `failed -> running` (already a valid transition in the existing
task state machine) doubles as "Retry" and increments
`automation_attempts`; `failed -> skipped` doubles as an *audited* skip --
FlowOps-specifically requires a non-empty `skip_reason` for automation
tasks (stored and shown in the audit trail), where a normal task's skip
needs no reason. Every state change is written through `append_audit`, so
the existing SSE feed (already polling the audit table) carries queued →
running → success/failed to every connected client in real time with no
new transport. Authorization is intentionally stricter than a normal
task: triggering, retrying, or skipping an automation task requires
`runbooks:edit` (Editor/Admin), not just being the task's assigned
owner -- a Member who owns an automation task cannot fire it themselves,
since it calls an external system on the runbook's behalf. There is no
distinct "rehearsal" execution mode in FlowOps today (tasks of every type
can only execute while the runbook is `live`, per the pre-existing status
check), so "rehearsal safely skips integration tasks" doesn't have a
literal analog to close here — it isn't a gap specific to automation
tasks. Covered by `test_automation_task_executes_and_reports_success`
(real local HTTP receiver, not mocked), `test_automation_task_failure_allows_retry_and_audited_skip`,
`test_automation_task_requires_editor_permission_not_just_assignment`,
and `test_automation_task_requires_url_before_starting`.

Product-owner sequencing note (2026-09-06): the supplied automation demonstration
and explicit ServiceOps administration request authorize a bounded Phase 3
foundation slice while Phase 1 remains active. Connection policy, encrypted
credential lifecycle, and safe connection tests are `DONE`; a reusable
named-connection abstraction (as opposed to a per-task URL) remains
`BACKLOG`.

The first-party ServiceOps REST v1 connector is now `PARTIAL`: ticket retrieval,
server-side bearer authentication, request correlation, change approval checks,
idempotent Live/complete state write-back, optional workflow triggering, local
audit evidence, and ticket projection are implemented. ServiceOps API client
creation/revocation remains owned by ServiceOps; inbound signed events and
asynchronous delivery retry remain under Epic 3.5.

### Epic 3.2 — Custom Fields

Typed, scoped custom-field definitions (P0/M) and values on tasks/runbooks
(P1/S): `DONE`. `custom_field_definitions`
are workspace- and entity-type-scoped (`runbook` or `task`), typed
(text/number/date/boolean/select with a bounded option list), and unique
per workspace+entity_type+name. `PATCH /api/runbooks/{id}` and
`PATCH /api/tasks/{id}` both accept an optional `custom_fields` object
(`{definition_id: value}`) alongside their existing field edits, validated
against the field's own type/options and silently ignoring any
definition_id that doesn't belong to that workspace/entity_type (fails
closed rather than trusting client-supplied IDs). Every runbook and task in
`runbook_document()` now carries a resolved `custom_fields` map keyed by
field name. Regression test covers definition creation/duplicate
rejection/invalid type, setting a value from each side (runbook and task),
an invalid select option being silently rejected rather than stored, and
deleting a definition cascading its values away.
`Administration → Custom fields` defines fields (entity type, name, type,
options); the runbook detail view shows a "Custom fields" card with an
"Edit" action to set values, resolved by name for readability.

### Epic 3.3 — Predefined Integrations

Slack (P1/M) and Microsoft Teams (P1/M): `DONE`, built on Epic 3.5's
webhook infrastructure rather than as separate connectors. A webhook now
carries a `provider` (`generic`/`slack`/`teams`); `webhook_payload()`
formats the same underlying audit event into Slack's plain `{"text":...}`
message shape or a Teams `MessageCard`, and delivery correctly skips
FlowOps' own HMAC signature header for both -- Slack/Teams incoming
webhooks authenticate via the secrecy of the destination URL itself, not a
verifiable signature, so signing them would be meaningless overhead, not
extra security. Regression test posts to a real local receiver for each
provider and asserts the provider-specific shape and the absence of a
signature header. ServiceNow change tracking (P2/L) remains `BACKLOG`.
ServiceOps remains the first-party complementary connector for the deeper,
scoped REST integration Epic 3.1 already covers.

### Epic 3.4 — Public REST API

Scoped revocable tokens (P0/M): `DONE`. Administrators create named
`api_tokens` (`fo_…`, shown once, `runbooks:read`/`runbooks:write` scopes,
revocable any time) under Administration → API tokens. `current_user()`
resolves `Authorization: Bearer fo_…` the same way it resolves a session
cookie, so every existing runbook/task endpoint -- not a hand-picked subset
-- already satisfies external runbook creation (P0/L), status queries
(P0/M), and task updates (P1/M) once authenticated this way; token requests
are correctly exempt from the CSRF header (CSRF is a cookie/browser-session
concern only). Documented sandbox API (P0/M): `DONE` as a README section
with curl examples; a dedicated interactive API explorer remains open.
Regression test creates a read-scoped and a write-scoped token, proves the
read token gets 403 on a write call, proves a write token can create a
runbook and transition it without any CSRF header, proves an invalid token
gets 401, and proves revocation takes effect on the next request.

### Epic 3.5 — Outbound Webhooks

State-change webhooks (P1/M) and retry with backoff (P1/M): `DONE`.
Administrators create named, HMAC-SHA256-signed webhooks under
Administration → Webhooks; a background poller (same polling design as the
SSE feed, not request-path delivery) picks up every new audit event --
which already covers every runbook and task state change, since those are
audited today -- and POSTs a signed payload (`X-FlowOps-Signature: sha256=…`,
`X-FlowOps-Event: <action>`) to every active, subscribed webhook, retrying
up to 3 attempts with a fixed backoff on network failure or non-2xx.
Verified with a real regression test that spins up an actual local HTTP
receiver (not a mock) and confirms the delivered signature matches an
independently computed HMAC. Not done: outbound URL SSRF hardening (the
existing MicroK8s NetworkPolicy already restricts this app's egress to DNS
and the ServiceOps pod only, meaningfully limiting blast radius, but there
is no app-level DNS-rebinding-resistant destination validation the way
ServiceOps has for its own webhooks) and per-webhook granular event-type
subscriptions (a webhook can filter by action name via its `events` list
today, but there's no UI for choosing anything other than the "*" default).

Exit: runbooks trigger external work and external systems safely drive runbooks.

## Phase 4 — Enterprise Scale and Compliance

### Epic 4.1 — Linked Runbooks

Primary/secondary runbook linking (P0/L) and aggregate parent status (P0/L):
`DONE`. `PATCH /api/runbooks/{id}` accepts
`parent_runbook_id`, rejects self-parenting and a two-hop cycle (linking a
runbook's own parent back to itself as a child), and is workspace-scoped.
`runbook_document()` resolves `parent_runbook` (id/name/status) on a child
and `child_runbooks` (each with its own task_count/done_count/progress) on
a parent, plus `aggregate_progress` (completed tasks across every child,
not per-child averaged) and `aggregate_status` (complete only if every
child is complete; live if any child is live; cancelled if any child is
cancelled; otherwise in_progress). Regression test links two children with
real tasks under one parent, executes a task in one child, and confirms
the parent's aggregate progress/status reflect it. The runbook detail view
has a "Linked runbooks" card ("Set parent" action) that shows the parent
when this runbook is a child, or the linked children with live aggregate
progress/status when it's a parent.

One level of nesting only (P1/S): `DONE` (2026-09-11). `PATCH
/api/runbooks/{id}` now also rejects linking when the prospective parent
already has its own parent, or when the runbook being linked already has
children of its own -- both would create a grandparent/grandchild chain,
which "one level of linking" explicitly rules out. Covered by
`test_linked_runbooks_reject_more_than_one_level_of_nesting`.

### Epic 4.2 — Dashboards and Reporting

Configurable multi-runbook dashboard (P0/L): `PARTIAL`. CSV export (P1/S):
`DONE` at the per-runbook task level — `GET /api/runbooks/{id}/tasks.csv`
returns every task's title, stream, owner, duration, type, schedule
offset, live status/timestamps, and lateness as a downloadable CSV
(reusing the same lateness calculation as the live view, not a
separate/divergent one), wired to an "Export CSV" button in the runbook
detail view. Covered by
`test_task_csv_export_returns_downloadable_csv_with_current_task_state`.

Post-event timing and delay report (P1/M): `DONE`. `GET /api/reports/delay`
walks every non-archived runbook in the tenant and returns every task that
is either currently past its scheduled deadline (a live, incomplete task)
or finished late (a completed task whose `completed_at` is after its
computed deadline) -- the deadline itself reuses `runbook_document()`'s
existing dependency-chain-aware `earliest_start()` calculation, not a
separate approximation. `GET /api/reports/delay.csv` is the same data as a
downloadable CSV. PDF export (P1/S): `DONE` via a dedicated print
stylesheet (`Delay report` under Analytics, "Print / Save as PDF" button
triggering `window.print()`) that hides the sidebar/header and prints only
the active view -- every browser's native print dialog offers "Save as
PDF," so this needed no PDF-generation library (this app is intentionally
stdlib-only). Covered by
`test_delay_report_includes_completed_late_tasks_and_currently_late_tasks`,
verified end-to-end against a real container (both a still-late and a
finished-late task correctly appear in both the JSON and CSV forms).
Configurable multi-runbook dashboard (P0/L): `DONE`. Each user can now
show/hide the three command-center widgets (Runbook activity, Today
readiness, Delay summary) via a "Customize" button on the home view,
persisted server-side per-user (`users.dashboard_widgets`, `PATCH
/api/me/dashboard`) and applied on every login. The new Delay summary
widget surfaces the same `/api/reports/delay` data used by the full
report, directly on the dashboard. Scheduled-email delivery of the
dashboard is not implemented -- FlowOps has no outbound email scheduler
today and adding one is out of proportion to this story; the CSV/PDF
export routes already give a manual path to the same data.

Post-implementation review (2026-09-11): `PATCH /api/runbooks/{id}/review`
records `what_went_well`/`what_went_wrong`/`follow_up_actions` plus
`reviewed_by`/`reviewed_at`, stored as `runbooks.review_json` and
surfaced as `review` in the runbook document. Deliberately the inverse
gate of every other runbook field edit: it 409s until the runbook
reaches `complete` (a normal field edit 409s *after* completion), since
a review only makes sense once execution is over. A completed runbook
without a review yet shows an "Add review" action for Editors/Admins;
once recorded, the sidebar card becomes a read-only summary. The write
goes through `append_audit` (`runbook.reviewed`), so it's part of the
same immutable history as everything else on the runbook. Covered by
`test_post_implementation_review_only_allowed_after_completion`.

### Epic 4.3 — Compliance Audit

Immutable-by-policy audit (P0/L): `PARTIAL`. Checksummed export (P1/M):
`DONE`. `GET /api/admin/audit/export` returns every audit event for the
tenant, walks the existing hash chain server-side before returning
(`previous_hash`/`event_hash`, already used for tamper-evidence) and
reports `chain_verified: true/false`, plus a `sha256:` checksum computed
over the canonical serialization of the exported events array -- a
recipient can re-serialize `data.events` the same way
(`json.dumps(events, sort_keys=True, separators=(',',':'))`) and confirm
the export matches `data.checksum`. The export action is itself audited.
Regression test recomputes the checksum independently and confirms it
matches.

Configurable retention (P1/M): `DONE`. `audit_retention_days` (Platform
settings, 0 = keep forever) gates `POST /api/admin/audit/purge`
(`admin:access` only), which deletes events older than the retention
window and records a checkpoint (`audit_retention_checkpoint` instance
setting) so the checksummed export's hash-chain walk starts from that
checkpoint instead of assuming the very first surviving row is the
original genesis -- a purge is an intentional, audited break in the
chain's history, not tamper, and the export correctly keeps verifying as
`chain_verified: true` for everything since the last purge. The purge
itself is audited (`audit.retention_purged`) and requires a retention
period to be configured first (400 on an unset/zero retention). "Purge by
retention" is an action under Administration → Audit. Regression test
backdates the oldest audit row past the retention window, purges, and
confirms both that the row is gone and that the export's chain
verification still passes afterward -- proving the checkpoint mechanism
works, not just that deletion happened.

### Epic 4.4 — Security Hardening

SAML/OIDC SSO (P0/L), SCIM (P1/L), managed encryption at rest/in transit
(P0/L), and independent penetration test (P0/L): `BACKLOG`.

### Epic 4.5 — Mobile and Field Access

Responsive assigned-task execution (P1/L): `PARTIAL`. Push notifications for
assignment/overdue work (P2/M): `BACKLOG`.

### Epic 4.6 — Multi-Region and Scale

Regional residency (P1/L) and validated hundreds-of-users/thousands-of-tasks
real-time performance (P0/L): `BACKLOG`.

Exit: regulated enterprises can run large multi-region operations with
compliance-grade evidence.

## Cross-Cutting Non-Functional Backlog

| Item | Priority | Status |
|---|---:|---:|
| Dependency and scheduling engine automated coverage | P0 | PARTIAL |
| Real-time load test before each phase | P0 | DONE for Phase 1 |
| Structured API/background-job logging and error tracking | P0 | DONE |
| Database backup and point-in-time recovery | P0 | DONE (snapshot backup, not continuous PITR) |
| Public API rate limiting | P1 | DONE |
| Core execution UI accessibility review | P1 | PARTIAL |
| Internationalization scaffolding | P2 | BACKLOG |
| FlowOps platform disaster-recovery plan | P1 | BACKLOG |

Foundational hygiene (2026-09-11): every `do_GET`/`do_POST`/`do_PATCH`/
`do_DELETE` dispatcher is now wrapped so an unhandled exception can no
longer crash the connection silently — it's logged as a structured JSON
line (`error_id`, exception type, full traceback) and the client gets a
500 with that same `error_id` for correlation, instead of a bare
connection reset. Database backups run automatically every
`FLOWOPS_BACKUP_INTERVAL_HOURS` (default 6h) via SQLite's own hot-backup
API (safe against a live database), retaining the last
`FLOWOPS_BACKUP_RETAIN` (default 14) snapshots under `<data dir>/backups`
— inside the same persistent volume as the live database, so it survives
pod restarts. This is honestly a snapshot backup, not continuous
WAL-shipping PITR: recovery granularity is the backup interval, not
per-transaction. `Administration → Platform & security → Database
backups` lists existing backups and can trigger one on demand;
`GET`/`POST /api/admin/backups` back it. Public API tokens (`Bearer
fo_...`) are now rate-limited to `FLOWOPS_API_RATE_LIMIT` (default 120)
requests per rolling minute per token, returning `429` with a
`Retry-After` header when exceeded — session-cookie browser traffic
(the SPA's own polling) is unaffected. Covered by
`test_unhandled_exception_returns_structured_500_instead_of_crashing`,
`test_admin_can_trigger_and_list_database_backups`,
`test_backup_retention_deletes_oldest_beyond_retain_limit`, and
`test_api_token_requests_are_rate_limited`.

Accessibility review evidence (2026-09-10): this pass was a manual code review
of `static/index.html`/`app.js` (no headless-browser/axe-core tooling was
available in this environment, so this is not a full automated WCAG 2.2 AA
scan). Confirmed already-compliant: form labels are real `<label>` elements
(not placeholder-only), status is always conveyed as text via `chip()` (not
color alone), and modal dialogs use native `<dialog>`/`.showModal()`, which
gives built-in focus trapping and Escape-to-close. Found and fixed two real
gaps: the three modal close buttons (×) and the sign-out button were
icon-only with no accessible name (`aria-label` added to all four); the new
stream rename/delete control was mouse-only (dblclick, no keyboard path) --
replaced with a separate, independently focusable "✎" button per stream.
Not done: color-contrast measurement, screen-reader walkthrough, keyboard-only
full-app traversal, and zoom/reflow testing all require actual browser
rendering and remain open.

## Suggested Team Shape

- Phase 1: two or three full-stack engineers, a real-time owner, and one designer.
- Phase 2: add a permissions/data-model specialist.
- Phase 3: add an API and integrations specialist.
- Phase 4: add security engineering and regulated-industry compliance expertise.

## Current Delivery Focus

1. ~~Finish Phase 1 Epic 1.3 P0: first-class stream creation and stream edits.~~ Done 2026-09-10: dedicated `streams` table, create/rename/delete API and UI, existing task streams backfilled.
2. ~~Finish Phase 1 Epic 1.6 P0: audit every task and runbook edit, not only transitions.~~ Done 2026-09-10: added field-edit endpoints (`PATCH /api/tasks/{id}` without `status`, `PATCH /api/runbooks/{id}`) audited as `task.edited`/`runbook.edited`, usable independent of live/status gating; dedicated edit UI (vs. API-only) remains a follow-up.
3. ~~Validate Phase 1 with dependency/scheduling breadth and real-time load evidence.~~ Load evidence done 2026-09-10 (see Epic 1.5 real-time acceptance note); dependency/scheduling breadth beyond the existing fan-in/chain regression tests remains open.
4. Complete the core execution UI accessibility review before Phase 1 exit.

## Guide Requirements Traceability

These notes were reconciled from `Cutover Task Executor Guide.pdf` (TE) and
`Cutover Quick Start Guide.pdf` (QS). They are implementation requirements for
FlowOps, but remain subordinate to the phase and P0 ordering above.

### Phase 1 guide requirements

| Requirement | Source | Backlog mapping | Status |
|---|---|---|---|
| Registration invitation, email/password login, optional SSO handoff | TE p1; QS p4 | 1.1 | PARTIAL |
| Home shows accessible workspaces, live/planning runbooks, assigned tasks | TE p2; QS p5 | 1.2, 1.5 | PARTIAL |
| Global navigation, search, profile, help, role-aware admin/settings | QS p6 | 1.1, 1.5 | PARTIAL |
| Individual and CSV user onboarding with roles/workspace permissions | QS p7 | 1.1; 2.1; 2.5 | PARTIAL |
| Task detail shows timings, description, owners, teams, dependencies | TE p2; QS p15, p21 | 1.3, 1.4 | PARTIAL |
| My Tasks focuses on tasks assigned to the user or their team | TE p2; QS p18 | 1.3, 1.5 | PARTIAL |
| Only assigned user/team can start or complete a startable task | TE p3; QS p27 | 1.3, 1.4 | DONE |
| Dependency-blocked tasks are visible but disabled | TE p3; QS p27 | 1.3 | DONE |
| Start and completion capture actual timestamps and unlock successors | TE p3; QS p27 | 1.3 | DONE |
| Normal, Milestone, Checklist, Validation, SMS, Email, Call behaviors | TE p4 | 1.3 | PARTIAL |
| Validation completion captures Pass, Fail, Not Tested and commentary | TE p4 | 1.3, 1.6 | DONE |
| Live/rehearsal start, pause, resume, cancel and admin override | QS p26-p27 | 1.5 | PARTIAL |
| Planning countdown, overdue-start warning, live elapsed clock, and final planned-versus-actual duration | QS p14, p26-p27 | 1.2, 1.5 | DONE |
| Automatic ready-to-start and run-start notifications | TE p3; QS p28 | 1.5 | PARTIAL |
| Live single-runbook dashboard updates without refresh | QS p16, p30 | 1.5 | DONE |
| Runbook audit includes detail, stream, team, task, and timing changes | QS p16, p29 | 1.6 | PARTIAL |

### Phase 2 guide requirements

| Requirement | Source | Backlog mapping | Status |
|---|---|---|---|
| Workspace list/table/timeline views, sorting, filters, saved views | QS p8-p13 | 2.2 | PARTIAL (list view with saved filters DONE; table/timeline view alternatives remain BACKLOG) |
| Folders, nested folders, sticky/applied filters | QS p13 | 2.2 | DONE |
| Runbook type selection and blank/template creation | QS p19-p20 | 2.2, 2.3 | PARTIAL |
| Central teams propagate membership into linked runbook teams | QS p10-p11, p22 | 2.4 | DONE |
| Interactive dependency node map with critical path | QS p17 | 2.6 | PARTIAL |
| Runbook home/pages for operational instructions and links | QS p16 | 2.2 | BACKLOG |
| CSV task import, filtered export, Excel/timezone options | QS p23 | 2.5 | BACKLOG |
| Approved reusable snippets, maximum 100 tasks | QS p10, p24 | 2.3 | BACKLOG |

### Phase 3 and 4 guide requirements

| Requirement | Source | Backlog mapping | Status |
|---|---|---|---|
| Data-source view maps CMDB applications/services to templates | QS p10 | 3.1, 3.2 | BACKLOG |
| Parent runbook controls one level of linked child runbooks | QS p25 | 4.1 | BACKLOG |
| Linked-runbook dashboard aggregates child progress live | QS p25 | 4.1, 4.2 | BACKLOG |
| Multi-runbook dashboard with filters and scheduled email sharing | QS p31 | 4.2 | BACKLOG |
| Post-implementation review after completion | QS p32 | 4.2 | DONE |
| Downloadable, filterable audit evidence | QS p29 | 4.3 | BACKLOG |

### Video-derived integration requirements

Source: supplied integration demonstration,
reviewed from the full 5:22 transcript on 2026-09-06.

| Requirement | Video evidence | Backlog mapping | Status |
|---|---|---|---|
| Admin configures the ServiceOps endpoint, safety policy, and encrypted API-key lifecycle entirely in the web UI | ServiceOps API client and least-privilege requirements | 3.1 | DONE |
| Admin tests a connection without exposing its credential to the browser | 4:38-5:15 | 3.1 | DONE |
| ServiceOps API compatibility test validates JSON, authentication, and `tickets:read`, and explains additional lifecycle scopes | ServiceOps REST API v1 contract | 3.1 | DONE |
| Test Connection validates the URL and API key currently entered in the browser before saving, rather than silently testing a stale deployment fallback | ServiceOps administrator workflow regression 2026-09-10 | 3.1 | DONE |
| Browser-triggered ServiceOps synchronization uses the authenticated CSRF-aware API client and refreshes the runbook projection without a page reload | ServiceOps runbook synchronization regression 2026-09-10 | 3.1 | DONE |
| Integration tasks execute only in Live; rehearsal safely skips them | 1:28-1:39 | 3.1 | DONE (no distinct rehearsal mode exists; all task types already gate on live-only execution) |
| Directory sign-in delegates AD/LDAP verification to ServiceOps and displays the configured AD domain | ServiceOps login behavior | 4.4 | DONE |
| Queued/running progress and percentage update the task in real time | 1:42-2:25 | 1.5, 3.1 | DONE |
| Removed unsupported automation-provider configuration from the product surface and API | Product-owner decision 2026-09-07 | 3.1 | DONE |
| Missing-job errors return actionable detail; operator can retry or audited-skip | 2:55-3:50 | 1.6, 3.1 | DONE |
| Only authorized executors can trigger potentially destructive external jobs | 4:38-5:03 | 1.1, 3.1 | DONE |
| ServiceOps owns approval/risk/record lifecycle; FlowOps returns execution state and evidence | Product integration decision | 3.1, 3.5 | PARTIAL |
| Use ServiceOps REST v1 ticket, update, and workflow APIs with scoped bearer identity, request IDs, and idempotency keys | ServiceOps `docs/API_REFERENCE.md` §§1-3, 5, 7-8 | 3.1 | DONE |
| Block a linked change from Live when ServiceOps reports it is not approved | ServiceOps lifecycle guard and FlowOps integration policy | 3.1 | DONE |
| Persist a minimal ServiceOps ticket projection and show its state in the runbook | ServiceOps ticket document contract | 3.1, 3.2 | DONE |

### Guide-derived delivery rule

For each story above, completion requires: persistent data behavior, server-side
authorization, real-time propagation where applicable, accessible desktop and
mobile UI, actor-attributed audit evidence, automated regression coverage, and
a healthy Docker preview. A visual placeholder does not qualify as complete.
