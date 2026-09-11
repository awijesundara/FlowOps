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
| Reusable task snippets (subset of tasks, not a whole runbook), capped at 100 tasks | P2 | M | DONE |

Reusable task snippets (2026-09-11): distinct from a template (which
captures an entire runbook), a snippet captures an explicit, arbitrary
subset of a runbook's tasks -- `POST /api/runbooks/{id}/save-as-snippet`
takes `task_ids`, rejects a selection over 100 tasks or containing a task
that doesn't belong to that runbook, and copies only the internal
dependencies where *both* endpoints are in the selection (a dependency on
a task left out of the snippet is silently dropped, not left dangling).
`POST /api/runbooks/{id}/insert-snippet` appends a snippet's tasks
(preserving their internal dependency chain) onto the end of a
*different* runbook's task list, auto-creating any missing streams --
mirroring how "use template" works, but appending into an existing
runbook instead of creating a new one. `GET/DELETE /api/snippets`
round it out. Runbook detail view: "✂ Save snippet" (prompts for task
numbers, reusing the same numbered-list picker as the existing "Bulk
edit" action) and "＋ Insert snippet". Covered by
`test_snippet_captures_selected_tasks_and_internal_dependencies_only`
and `test_snippet_rejects_more_than_one_hundred_tasks`.

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

Named connections (P0/M) and API key/basic/bearer/OAuth authentication
(P0/L) remain `BACKLOG` -- explicitly deferred (2026-09-11, product-owner
direction): there is still no reusable, named "connection" abstraction
with its own stored credentials; an automation task's URL is per-task,
not backed by a shared, admin-managed connection profile.

Automatic context (P1/M): `DONE` (2026-09-11), scoped to the existing
per-task `automation_url` mechanism rather than a connection record (since
connections themselves are deferred, above). `runbooks.automation_context_json`
stores admin/Editor-configured extra headers and `{{var}}` substitution
values (`PATCH /api/runbooks/{id}` accepts an `automation_context` object);
`run_automation_task()` merges the configured headers and does flat
string substitution into the automation URL and request body -- no
templating engine, just literal `{{name}}` replacement, to avoid scope
creep. Surfaced as an "Automation context" sidebar card on the runbook
detail view (Editor/Admin only). Covered by
`test_automation_task_carries_runbooks_configured_context_header_and_variable`
(a real receiver confirms both the injected header and the substituted
URL query parameter).

Sandbox action tests (P0/M): `DONE` (2026-09-11), likewise scoped to
`automation_url` rather than a connection. `POST /api/tasks/{id}/test-fire`
fires the task's existing automation URL (through the same
SSRF-hardened `perform_automation_call()` every other automation call
uses) without touching the task's own `status`/`automation_status`/
`automation_attempts` -- audited as `task.automation_test_fired`, a
distinctly-named event from a real production run. Gated by the same
`runbooks:edit`/workspace-scoped permission as every other task mutation
(not a separate admin capability, since there's no connection-level owner
to scope it to). A "🧪 Test" button appears next to every automation
task with a configured URL. Covered by
`test_task_test_fire_reaches_receiver_without_touching_task_state` (a
real receiver, exactly one `task.automation_test_fired` audit row, task
status/automation fields provably unchanged before/after) and
`test_task_test_fire_requires_automation_url`.

SSRF hardening (Epic 3.5, P0 -- security): `DONE` (2026-09-11). Every
outbound call this app makes to an admin/user-supplied destination --
webhook delivery, automation task URLs -- now goes through a new
`safe_urlopen()` instead of `urllib.request.urlopen()` directly.
Behavior (not code) modeled on ServiceOps's own webhook SSRF hardening
(`serviceops_core/dns_pin.py`, `app.py`'s `_integration_address_allowed()`)
-- ServiceOps uses the third-party `requests` library; this reimplements
the same protections with stdlib `urllib`/`socket`/`ipaddress` only, to
stay within this app's zero-dependency architecture.
`_integration_address_allowed()` rejects loopback/link-local/multicast/
reserved/unspecified addresses unconditionally and ordinary private
ranges unless an explicit `allow_private_network` flag is set (opt-in,
for trusted admin-configured integrations expected to reach in-cluster
hosts -- not used by webhooks/automation URLs today, but available for
the ServiceNow connector below). `resolve_endpoint_addresses_safely()`
re-resolves at delivery time and validates every A/AAAA record, closing
the gap a literal-string hostname check alone can't catch (a
public-looking hostname resolving to a private address). A
`pin_resolved_addresses` context manager (a `threading.local`-scoped
monkeypatch of `socket.getaddrinfo`) forces the connection that follows
to use exactly the addresses just validated, closing the classic
DNS-rebinding TOCTOU gap between validation and connection. Redirects are
followed manually (a minimal custom `urllib` opener with no automatic
redirect-following or HTTPError-raising), re-validating and re-pinning on
every hop, capped at 3. The existing MicroK8s NetworkPolicy egress
restriction remains defense-in-depth, not a substitute. Covered by
`test_webhook_test_fire_against_loopback_is_rejected_before_any_connection`
(end-to-end: a real API call, real 502, real error message),
`test_ssrf_address_validation_rejects_private_ranges_and_allows_public`
(unit-level, no DNS dependency -- proves both under- and over-blocking are
real bugs), and `test_pin_resolved_addresses_forces_the_pinned_answer_for_the_same_host`
(proves the pinning mechanism itself, since simulating true DNS rebinding
isn't practical without controlling DNS). Existing webhook/automation
tests that legitimately need a real receiver on `127.0.0.1` now bypass
only the SSRF *destination check* for that one call (never the validation
logic itself, which has its own dedicated tests above) -- the identical
technique ServiceOps's own test suite uses for the same unconditional-
loopback-rejection tension.

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

CTASK sub-task visibility (2026-09-11): `DONE`. A linked change ticket's
CTASKs now surface their owning team and assigned person as distinct
fields — previously `sync_serviceops_ctasks()` collapsed ServiceOps's
`assignmentGroup` (team) and `assignee` (person) into one generic `owner`
string, and re-syncing an already-imported CTASK was silently skipped
(`if number in existing: continue`), so team/assignee changes made later
in ServiceOps never reached FlowOps. Fixed: `tasks.serviceops_ctask_team`
stores the team separately from `owner` (the assignee), and re-sync now
**updates** the existing task's title/description/owner/team instead of
skipping it. The task list shows each CTASK's own ticket number as a chip
on the title and "Team · Assignee" in place of the old single owner field;
the runbook detail view's "ServiceOps record" sidebar card gained a
"Sub-tasks" list (number, title, team, assignee) for every linked CTASK.
Covered by
`test_serviceops_ctask_sync_stores_team_and_assignee_separately_and_updates_on_resync`,
which also proves the stale-re-sync bug is fixed (a second sync with a
newly-assigned person updates the existing task, not just the first
import). Existing no-duplicate-on-resync coverage
(`test_serviceops_v1_ticket_sync_uses_scoped_bearer_and_stores_projection`)
still passes unchanged.

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
signature header. ServiceOps remains the first-party complementary
connector for the deeper, scoped REST integration Epic 3.1 already covers.

ServiceNow change tracking (P2/L): `DONE` (2026-09-11). Modeled directly
on the ServiceOps connector's shape (`serviceops_request`/
`apply_serviceops_sync`/`sync_serviceops`), not copied -- real
adaptations for ServiceNow's actual Table API: Basic Auth (username +
password) rather than a bearer token, since credential storage reuses
the existing `integration_credentials` table (`provider='servicenow'`)
with the username as a plain `servicenow_username` setting and the
password as the stored secret -- a bespoke credential store, not a named
connection (deferred, see Epic 3.1); response envelope is
`{"result":...}`, not `{"data":...}`; state is ServiceNow's numeric
`change_request` state code (`-1` Implement, `3` Closed by default OOB
configuration), not a string match like ServiceOps's `"Approved"`.
`GET /api/now/table/change_request?sysparm_query=number=...` links a
change by number; `PATCH .../change_request/{sys_id}` pushes state on the
same `live`/`complete` transition hooks ServiceOps already uses,
independently and in addition to it (`runbooks.servicenow_change_number`/
`_sys_id`/`_state`/`_synced_at`, parallel to the existing `serviceops_*`
columns). All ServiceNow HTTP calls go through the new SSRF-hardened
`safe_urlopen()` (`allow_private_network=True`, since a ServiceNow
instance is expected to be a trusted, admin-configured destination like
ServiceOps, not an arbitrary user-supplied URL). Administration →
Connections gained a ServiceNow policy form (URL, username, password,
enabled, sync-on-live/complete) alongside the existing ServiceOps one; the
runbook detail view has a "ServiceNow change" sidebar card (Link/Sync
action) mirroring the ServiceOps record card. Covered by
`test_servicenow_connector_syncs_change_and_pushes_lifecycle_state`
(a real local `http.server`-based double returning ServiceNow-shaped
JSON -- not `unittest.mock` -- proving GET sync, the `live` transition's
PATCH with the correct state code, and that the credential is never
echoed back) and `test_servicenow_integration_requires_username_and_url`.

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
with curl examples. Interactive API explorer: `DONE` (2026-09-11).
`/api-explorer` is a small, hand-rolled explorer (`static/api-explorer.html`/
`.js`, ~90 lines) -- deliberately not a vendored Swagger UI bundle, to stay
consistent with this app's zero-third-party-dependency architecture. It
reads a hand-maintained `static/openapi.json` (a real, partial OpenAPI 3.0
document covering exactly the 7 endpoints in this section's own README
table), renders a clickable endpoint list, builds a parameter/body form
from each operation's schema, and fires a real authenticated `fetch()`
with a pasted bearer token, showing the raw response. This is good
interactive coverage of the documented sandbox API, not a full
schema-driven client -- a proportionate, stated scope call given the
no-third-party-JS constraint. Covered by
`test_api_explorer_openapi_doc_paths_resolve_to_real_routes` (drives every
documented path with a real bearer token and fails if any of them 404s,
catching doc drift automatically), `test_api_explorer_page_serves_and_can_call_a_real_endpoint`,
and a Playwright test
(`test_api_explorer_can_call_a_real_endpoint_with_a_pasted_token`) that
pastes a freshly-created token into the real page and confirms a live
`GET /api/runbooks` call renders a 200 response in the browser.
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
independently computed HMAC.

Outbound URL SSRF hardening: `DONE` (2026-09-11) -- see Epic 3.1 above for
the full `safe_urlopen()`/DNS-pinning writeup; webhook delivery is one of
its call sites, alongside automation task URLs and the ServiceNow
connector.

Per-webhook granular event-type subscriptions: `DONE` (2026-09-11). A new
`WEBHOOK_EVENT_ACTIONS` constant enumerates every real `append_audit()`
action (77 distinct events as of this writing), served as
`available_events` on `GET /api/admin/webhooks`. The webhook creation flow
now offers a comma-separated event picker against that live list instead
of always defaulting to `["*"]` -- a text-based picker rather than a
checkbox grid, a proportionate scope call given this admin panel's
existing prompt()-based micro-form convention (streams, runbook home,
automation context all follow the same pattern) rather than introducing a
new dialog just for this. Each webhook's admin-list row now shows "all
events" or the subscribed count. Covered by
`test_webhook_event_actions_list_matches_real_append_audit_call_sites`
(regex-scans `server.py`'s own real call sites and fails on drift),
`test_webhook_available_events_lists_canonical_actions`, and
`test_webhook_only_delivers_to_subscribed_event_types` (a real receiver
confirms a `folder.created`-only subscriber never receives a
`runbook.created` event fired in the same batch).

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
report, directly on the dashboard.

Scheduled-email delivery of the dashboard: `DONE` (2026-09-11). A new
`dashboard_email_loop()` background thread (structurally identical to the
existing `backup_loop()`/`webhook_dispatcher_loop()` daemon-thread
pattern) checks every 15 minutes whether any instance is due its
configured digest, across every instance, not just the default one.
Platform settings gained `dashboard_email_frequency` (`off`/`daily`/
`weekly`), `dashboard_email_hour` (0-23 UTC), and a comma-separated
`dashboard_email_recipients` list -- no cron-expression parser, since
daily/weekly-at-a-configured-hour doesn't need one. `render_dashboard_email()`
produces a plain-text digest (active runbooks, live count, completions,
task-completion percentage, up to 25 late/at-risk tasks) reusing the same
data the dashboard widgets and `/api/reports/delay` already compute, sent
via the existing `send_mail()` -- matching this app's all-plaintext email
design (invitations, password resets), no HTML template engine. A
`dashboard_email_last_sent_at` checkpoint per instance ensures at most one
send per configured period. The due-check/send logic is factored into
`maybe_send_dashboard_email(db, instance_id, current_time)`, callable
directly with an injected reference time, so the scheduling gate itself is
deterministically testable without waiting on the loop's real 15-minute
sleep or standing up a live SMTP server. Covered by
`test_dashboard_email_render_includes_runbook_and_completion_data`
(isolated from SMTP -- asserts the render function's content directly) and
`test_dashboard_email_scheduling_gate_sends_only_once_per_configured_interval`
(wrong hour → no send; first due run → sends to every recipient; same day
again → correctly suppressed; 24h later at the same hour → due again).
Real SMTP delivery against a real mail relay is a manual Docker-preview
verification step (set real `FLOWOPS_SMTP_*` env vars, confirm an email
arrives) -- stated here explicitly rather than silently assumed, since it
depends on infrastructure this automated suite can't stand up.

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

Immutable-by-policy audit (P0/L): `DONE` (2026-09-11). The hash chain and
export-time verification already existed; this closes the remaining gap
with real, database-level enforcement rather than convention alone.
`audit_no_update`/`audit_no_delete` triggers (`init_db()`) reject *any*
`UPDATE` on the `audit` table unconditionally, and reject `DELETE` unless
the sanctioned retention-purge path has set `audit_purge_lock.active=1`
around its own `DELETE` (cleared again immediately after) — so nothing
else in the codebase, now or added later, can silently rewrite or erase
audit history, while the existing configurable-retention purge keeps
working exactly as before. The chain-walk previously inlined in
`GET /api/admin/audit/export` is now `verify_audit_chain()`, shared with a
new standalone `GET /api/admin/audit/verify` (chain integrity check
without paying the cost of a full export — suitable for a periodic
monitoring probe). Covered by
`test_audit_rows_are_immutable_by_policy_at_the_database_level` (a raw
`UPDATE`/`DELETE` against the `audit` table, bypassing the app entirely,
must raise `sqlite3.IntegrityError`) and
`test_audit_verify_endpoint_confirms_chain_without_requiring_export`; the
existing retention-purge test
(`test_configurable_audit_retention_purges_old_events_and_keeps_chain_verifiable`)
still passes, confirming the sanctioned purge path is unaffected. Checksummed export (P1/M):
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

SAML/OIDC SSO (P0/L): `DONE` (2026-09-11) for OIDC; SAML itself remains
out of scope this pass (no real customer IdP is available in this
environment — validated instead against a throwaway local Keycloak
container, scripted end to end via its own admin REST API, no manual
clicking). A full authorization-code + PKCE relying party, independently
implemented against the existing dependency-free architecture (`urllib`
only, no `authlib`/`requests-oauthlib`): `GET /auth/oidc/login` builds a
PKCE `code_verifier`/`code_challenge` (S256) and `state`, persists them in
a new `oidc_states` DB table (replica-safe — the MicroK8s deployment runs
2 pod replicas with no session affinity between the login and callback
requests, so an in-memory dict would break under load balancing) with a
10-minute expiry, and redirects to the provider's `authorization_endpoint`
resolved via OIDC discovery (`GET {issuer}/.well-known/openid-configuration`,
cached 1h). `GET /auth/oidc/callback` validates and single-use-consumes the
`state` row, exchanges the code for an `id_token` at the `token_endpoint`
(via the existing SSRF-hardened `safe_urlopen`, `allow_private_network=True`
— matches the ServiceOps/ServiceNow connectors' trust model), and verifies
the `id_token`'s RS256 signature via a generalized `verify_oidc_id_token()`/
`_fetch_jwks()` pair (parameterized versions of the existing Cloudflare
Access JWT verifier — same `pow(base,exp,mod)` modular-exponentiation
technique, no crypto library added), checking signature, issuer, audience,
and expiry. On success, maps the verified email to an existing active
FlowOps user (same trust model as the already-shipped Cloudflare Access
SSO — deliberately no auto-provisioning here; that's SCIM's job) and issues
a session through the exact same code path `/api/auth/login` already uses.
Settings/credential storage extends `/api/admin/integrations` to a third
`oidc` provider (issuer URL, client ID, client secret via the existing
one-way-encrypted `integration_credentials` table); a `GET
/api/admin/integrations/test` variant fetches the live discovery document
and JWKS and reports the RSA key count, without needing a full login round
trip to sanity-check a new configuration. Fast-suite coverage (no
Docker/Keycloak needed):
`test_verify_oidc_id_token_checks_signature_issuer_audience_and_expiry`
(real RSA keypair generated in-test, same technique as the Cloudflare
Access test — signature tampering, wrong issuer, wrong audience, expiry,
unknown `kid`, and list-shaped `aud` all independently verified),
`test_oidc_connection_test_verifies_a_real_discovery_document_and_jwks`
(real local HTTP double serving a discovery document + JWKS; credential
never echoed back), `test_oidc_login_is_disabled_by_default_and_redirects_when_enabled`.
Heavy, opt-in, real end-to-end coverage against an actual Keycloak
container lives in `test_oidc.py`
(`FLOWOPS_OIDC_TEST_KEYCLOAK=1 python3 -m pytest test_oidc.py -v`, kept out
of the default fast run since it boots a real Docker container): a realm,
confidential client, and two test users are provisioned via Keycloak's own
admin REST API (no manual clicking); a real Playwright browser drives
`/auth/oidc/login` through Keycloak's actual login form and back through
`/auth/oidc/callback`, asserting a real FlowOps session cookie is set, `GET
/api/auth/me` returns the correct verified identity, and a real
`auth.oidc_login` audit row is written
(`test_full_authorization_code_pkce_flow_establishes_a_real_flowops_session`);
a second test confirms an OIDC identity with no matching active FlowOps
account is correctly rejected, not silently logged in
(`test_login_is_rejected_when_no_active_flowops_account_matches_the_oidc_email`).
Verified live in the Docker preview: `/api/admin/integrations` correctly
reports the new `oidc` block, and `/auth/oidc/login` 404s while disabled
rather than redirecting anywhere.

SCIM (P1/L): `DONE` (2026-09-11) — `/scim/v2/Users` and `/scim/v2/Groups`,
authenticated with the exact existing `api_tokens`/`Bearer fo_...`
mechanism (`current_user()`), gated by a new `scim:provision` scope added
to `TOKEN_SCOPE_PERMISSIONS` — no new auth mechanism, no session cookies
involved (SCIM clients aren't browsers). SCIM `User` maps to the `users`
table (`userName`→`username`, `displayName`/`name.formatted`→
`display_name`, `emails[0].value`→`email`, `active`→`users.active`);
SCIM `Group` maps to `central_teams`/`central_team_members` (the
cross-runbook membership model, not per-runbook `runbook_teams` — groups
provision into the instance's first workspace). SSO-first provisioned
users get an unusable random `password_hash` via the existing PBKDF2
helper (cosmetic only, satisfies the `NOT NULL` constraint; they
authenticate via OIDC, never a local password). `DELETE` is implemented as
deprovisioning (`active=0`), matching FlowOps's existing soft-delete
convention everywhere else (audit rows and task ownership reference user
ids) rather than a literal row delete. `PATCH` implements SCIM's
`Operations` shape (distinct from FlowOps's own plain-field `PATCH` style
elsewhere) for `active`/`displayName` on Users and `members` add/replace/
remove on Groups. A minimal hand-rolled filter parser supports `eq`/`co`/
`sw` against a documented, narrow attribute set (`userName`,
`emails.value`, `displayName`, `active`) joined with `and` — not the full
SCIM filter grammar, matching what real IdP SCIM connectors (Okta, Entra)
actually send in practice; an unsupported attribute or operator returns a
`400` with a SCIM-shaped error body, not a silent no-op. Pagination via
`startIndex`/`count` (1-based, per spec). Covered by
`test_scim_requires_a_bearer_token_with_the_scim_scope` (missing bearer →
401, wrong scope → 403), `test_scim_user_lifecycle_create_get_patch_deactivate`
(create → SCIM-shaped JSON with `schemas`/`id`/`userName`/`meta`, GET,
PATCH rename + deactivate confirmed against the real `users` row, DELETE
confirmed as a soft-delete not a hard delete),
`test_scim_filter_supports_eq_co_sw_on_the_documented_attribute_set`,
`test_scim_group_lifecycle_create_membership_and_deletion_reflects_central_team_members`
(create with initial members, PATCH add/remove reflected in
`central_team_members`, delete). Verified live in the Docker preview: a
real SCIM token provisions a user end to end (`POST /scim/v2/Users` →
`GET /scim/v2/Users` lists it), and an unauthenticated request correctly
401s.

Managed encryption at rest/in transit (P0/L): `DONE` (2026-09-11),
interpreted for this self-hosted deployment as self-managed rather than a
cloud KMS. At rest: `backup_database()` now encrypts every snapshot with
the existing `SettingsCipher` (authenticated AES-256-CTR via `openssl`,
already protecting admin-managed credentials) immediately after SQLite's
hot-backup API writes it, before the plaintext intermediate file is
deleted — confirmed genuinely plaintext-before/opaque-after by a test that
opens the resulting file directly as SQLite (must fail) and round-trips it
back through `settings_cipher().decrypt()` to a valid database (must
succeed). In transit: confirmed, not assumed, by reading the actual tunnel
manifest (`k8s/terraform/cloudflared.yaml`) — `cloudflared` runs as a
genuine Cloudflare Tunnel (`tunnel run --token`), which by architecture
terminates public TLS at Cloudflare's edge before proxying over its own
encrypted tunnel connection into the cluster; this is a structural
property of Cloudflare Tunnels, not inferred from the separately-configured
Access identity layer. Covered by
`test_database_backups_are_encrypted_at_rest_and_round_trip_decrypt`. A
cloud-KMS
integration is out of scope unless the deployment target changes.

Independent penetration test (P0/L): `BACKLOG` — **excluded from the
current implementation pass**; requires an external, third-party
penetration-testing engagement not available in this environment.

### Epic 4.5 — Mobile and Field Access

Responsive assigned-task execution (P1/L): `DONE` (2026-09-11) — CSS-only
pass targeting the 375-414px viewport range (320px reflow already proven,
see Cross-Cutting table). Two real, concrete issues found and fixed, not
assumed: (1) task action buttons (`.task-actions button`) were 6px/9px
padding at 11px font — well under a real touch-target minimum. Fixed with
a `max-width:480px` rule that stacks the actions row onto its own full-width
grid row (`.task{grid-template-columns:32px 1fr 30px}`, actions at
`grid-column:1/-1`) and bumps buttons to `min-height/min-width:44px`.
(2) A genuine CSS grid blowout: `.detail-grid{grid-template-columns:1fr}`
(the existing `max-width:900px` rule) still let the single track grow to
its widest descendant's min-content size — confirmed via live layout
inspection that the resolved track was rendering at 1058px inside a 335px
container, overflowing the page by 700+px the moment a runbook was
actually opened at a narrow width (the pre-existing 320px test only ever
checked the *runbooks list*, never opened a runbook, so this was
invisible until this pass). Fixed with `minmax(0,1fr)`, the standard fix
for this exact class of bug, mirroring the `main{min-width:0}` guard
already in place one level up in the same file. Covered by
`test_task_execution_view_reflows_and_meets_touch_targets_at_375` and
`_at_414` in `test_browser.py`: opens a real runbook at each viewport
(through the real off-canvas mobile nav, `#menu` → sidebar), asserts zero
horizontal page overflow, and asserts every visible task action button's
real bounding box is at least 44×44px.

Push notifications for assignment/overdue work (P2/M): `DONE` (2026-09-11)
for task assignment; overdue-work push is not wired in this pass (see
scope note below) — interpreted as standards-based Web Push (VAPID),
since native APNs/FCM push requires a paid mobile developer account not
available in this environment. RFC 8291 payload encryption needs ECDH
over P-256 + AES-GCM + HKDF, none of which exist in the Python stdlib
(unlike the RSA modexp trick that makes the hand-rolled JWT verifier
possible) — resolved with the RFC-8030-compliant no-payload wake-up-ping
pattern instead: `static/sw.js`'s `push` handler shows a generic "you have
new activity" notification with no content, and clicking it opens the
app, where the existing real-time SSE activity feed (`/api/events`,
already shipped) takes over. VAPID JWT signing (ES256 / ECDSA P-256, also
absent from the stdlib) shells out to `openssl`, the same external-process
pattern `SettingsCipher` already establishes and this codebase already
trusts — `generate_vapid_keypair()`, `vapid_jwt()`, and a hand-rolled
`_der_ecdsa_signature_to_raw()` (openssl's signature output is DER, JOSE's
ES256 needs fixed-width raw r‖s). One VAPID keypair is generated lazily
per instance and its private key encrypted at rest with the existing
`SettingsCipher` (`vapid_keys` table). `GET /api/push/vapid-public-key`,
`POST`/`DELETE /api/push/subscribe` (`push_subscriptions` table, one row
per browser/device); a 404/410 from the push service during delivery
prunes the stale subscription automatically instead of retrying forever.
Wired into task assignment (`PATCH /api/tasks/{id}` with a changed
`owner_user_id` triggers `notify_task_assignment()`) — **narrower than the
epic's full name**: overdue-work detection is not wired in this pass (no
new background loop consuming it); assignment via the bulk-edit endpoint
and task-creation-with-owner are also not wired, only the single-task edit
path is, since that's the primary real assignment flow exercised by the
UI. Stated here explicitly as a scope decision, not an oversight. Frontend:
a "🔔 Enable push notifications" button in the profile Privacy tab
registers `/sw.js` and calls `PushManager.subscribe()`. Tests:
`test_vapid_jwt_is_a_real_ec_signature_verifiable_by_openssl_itself`
(generates a real keypair, signs a real JWT, and asks `openssl` itself —
independently of this app's own signer — to verify the signature),
`test_push_subscribe_stores_and_unsubscribe_removes_a_real_subscription`,
`test_task_assignment_sends_a_real_web_push_and_expired_subscription_is_pruned`
(a real local HTTP double receives the push, asserting the real `vapid
t=…, k=…` Authorization header shape, empty body, and TTL header; a
second double returning 410 confirms the stale subscription is deleted).
`test_browser.py`'s
`test_enabling_push_notifications_registers_a_real_service_worker_and_subscribes`
verifies real service-worker registration and a real 65-byte P-256 VAPID
key shape in an actual browser, then attempts a real
`pushManager.subscribe()` call — this step needs the browser to reach a
real push service (Google's, in Chrome), which this sandboxed headless
test environment cannot do (`AbortError: Registration failed`), so it
skips with an explicit, honest reason rather than reporting false success;
full subscribe-through-delivery remains a manual verification step in a
real browser, exactly as anticipated. Verified live in the Docker preview:
`/api/push/vapid-public-key` returns a real, correctly-shaped key.

### Epic 4.6 — Multi-Region and Scale

Regional residency (P1/L): `BACKLOG` — **excluded from the current
implementation pass**; requires real infrastructure in a second geographic
region, not available on this single-LAN, 2-node MicroK8s deployment.

Validated hundreds-of-users/thousands-of-tasks real-time performance
(P0/L): `BACKLOG`, in progress — extending the existing
`tools/load_test_realtime.py` (already proven at 150 concurrent viewers,
see Epic 1.5) to 300 and 500 concurrent viewers against the Docker
preview.

Exit: regulated enterprises can run large multi-region operations with
compliance-grade evidence.

## Cross-Cutting Non-Functional Backlog

| Item | Priority | Status |
|---|---:|---:|
| Dependency and scheduling engine automated coverage | P0 | DONE |
| Real-time load test before each phase | P0 | DONE for Phase 1 |
| Structured API/background-job logging and error tracking | P0 | DONE |
| Database backup and point-in-time recovery | P0 | DONE (snapshot backup, not continuous PITR) |
| Public API rate limiting | P1 | DONE |
| Core execution UI accessibility review | P1 | DONE for Phase 1 |
| Internationalization scaffolding | P2 | DONE |
| FlowOps platform disaster-recovery plan | P1 | BACKLOG |

Internationalization scaffolding (2026-09-11): `DONE`. A `static/strings.js`
keyed dictionary (`en`/`ja` — Japanese chosen to match this codebase's
existing `Asia/Tokyo` default timezone) with a `t(key)` helper and an
`applyLocale()` DOM-update function, served via a new `GET /strings.js`
static route. Wired into a representative slice of the UI, not the whole
app — a deliberate, stated scope call matching the plan's own framing:
the login screen's sign-in button, the five primary sidebar nav labels,
and the assigned-task execution view's action buttons (Start/Complete/
skipped). A new `users.locale` column (`ALTER TABLE`, default `'en'`)
persists the choice server-side, switchable from the existing profile
page (`PATCH /api/profile`, a `SUPPORTED_LOCALES` server-side allowlist —
an unsupported value silently falls back to `en` rather than erroring,
matching the frontend `t()` helper's own fallback so client and server
never disagree). The login screen itself reads the locale from
`localStorage` (set after every successful login/profile update) since
there's no authenticated user yet to look a stored preference up for.
Covered by `test_self_service_profile_update_edits_own_fields_and_is_audited`
(locale persists through `PATCH /api/profile` and `GET /api/auth/me`;
an unsupported locale falls back to `en`) and two real-browser tests:
`test_switching_locale_to_japanese_translates_nav_and_falls_back_for_unknown_locale`
(live nav-label translation via `setLocale('ja')`, then confirms an
unknown locale renders English, not raw keys or a crash) and
`test_login_screen_renders_in_the_locale_persisted_from_a_previous_session`
(logs out, sets `localStorage`, reloads, confirms the real login button
renders in Japanese).

Dependency and scheduling engine coverage (2026-09-11): `DONE`. The
existing `earliest_start()`/`critical_path()` logic (`runbook_document()`)
already implements dependency-aware scheduling correctly; this closes the
gap by adding regression coverage for the scenarios that weren't
previously exercised: a diamond dependency (confirming the join task waits
for the *later* of two branches, and that the critical path follows the
longer branch, not creation order), combined fan-out/fan-in across three
branches, a 12-task deep sequential chain (no recursion-depth issue), and
a cross-stream dependency (confirming stream boundaries don't implicitly
gate task start). Also confirmed, by reading every `INSERT INTO
dependencies` call site, that dependency cycles are structurally
impossible through the current API: a task's dependencies are fixed at
creation time and may only reference already-existing tasks, and no
endpoint ever edits an existing task's dependency list afterward — so no
cycle-rejection guard was needed. Covered by
`test_diamond_dependency_waits_for_the_later_of_two_branches`,
`test_combined_fan_out_fan_in_computes_correct_join_offset`,
`test_deep_sequential_chain_accumulates_offsets_without_error`, and
`test_cross_stream_dependency_still_gates_task_start`.

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

Accessibility review evidence (2026-09-10 through 2026-09-11): the initial
manual semantic review fixed unnamed icon controls and a mouse-only stream
action. A subsequent real-Chrome Playwright/axe-core pass now covers the
command center, runbook inventory, and runbook execution detail against WCAG
2 A/AA and WCAG 2.1 AA rules, with no serious or critical violations. It also
proved keyboard activation of runbook rows and 320 CSS-pixel reflow without
horizontal page scrolling. The fixes add native button semantics to runbook
cards/rows, accessible filter names, a skip link, a polite toast live region,
proper tab and notification-drawer state, visible keyboard focus paths,
measured contrast corrections, and reduced-motion handling. Regression:
`test_axe_has_no_serious_or_critical_execution_ui_violations`,
`test_runbook_rows_are_keyboard_operable`, and
`test_execution_ui_reflows_without_horizontal_page_scroll` in
`test_browser.py`. This closes the Phase 1 core execution UI review; future
screens still require the same gate as they are introduced.

## Suggested Team Shape

- Phase 1: two or three full-stack engineers, a real-time owner, and one designer.
- Phase 2: add a permissions/data-model specialist.
- Phase 3: add an API and integrations specialist.
- Phase 4: add security engineering and regulated-industry compliance expertise.

## Current Delivery Focus

1. ~~Finish Phase 1 Epic 1.3 P0: first-class stream creation and stream edits.~~ Done 2026-09-10: dedicated `streams` table, create/rename/delete API and UI, existing task streams backfilled.
2. ~~Finish Phase 1 Epic 1.6 P0: audit every task and runbook edit, not only transitions.~~ Done 2026-09-10: added field-edit endpoints (`PATCH /api/tasks/{id}` without `status`, `PATCH /api/runbooks/{id}`) audited as `task.edited`/`runbook.edited`, usable independent of live/status gating; dedicated edit UI (vs. API-only) remains a follow-up.
3. ~~Validate Phase 1 with dependency/scheduling breadth and real-time load evidence.~~ Load evidence done 2026-09-10 (see Epic 1.5 real-time acceptance note); dependency/scheduling breadth beyond the existing fan-in/chain regression tests remains open.
4. ~~Complete the core execution UI accessibility review before Phase 1 exit.~~ Done 2026-09-11: Chrome/axe-core command-center, inventory, and execution-detail scan; keyboard row activation; and 320px reflow regressions pass.
5. ~~Add a self-service profile page matching ServiceOps's feature depth.~~ Done 2026-09-11: `PATCH /api/profile` (display name, email, title, timezone, date format), `POST /api/profile/avatar` (base64 PNG/JPEG upload, magic-byte validated, served from `/avatar/{id}`), `POST /api/profile/change-password` (current-password re-auth, revokes every other session for the account), `GET /api/profile/export` (downloadable JSON: profile, audit history, assigned tasks) — full frontend in `static/index.html`/`static/app.js` (sidebar avatar click opens a tabbed Details/Password/Privacy modal). Tests: `test_self_service_profile_update_edits_allowed_fields_only`, `test_self_service_avatar_upload_validates_and_serves_image`, `test_self_service_change_password_requires_current_password_and_revokes_other_sessions`, `test_profile_export_downloads_own_audit_and_task_history`, plus a negative auth test. All 80 tests pass; manually verified end-to-end against a running instance (login, patch, avatar upload/fetch, export, password change all returned expected responses).

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
| Interactive dependency node map with critical path | QS p17 | 2.6 | DONE (reconciled 2026-09-11 — see Epic 2.6: depth-based column layout, critical-path badge) |
| Runbook home/pages for operational instructions and links | QS p16 | 2.2 | DONE (reconciled 2026-09-11 — see Epic 2.2: `runbooks.home_content`, `test_runbook_home_content_is_editable_and_returned_in_document`) |
| CSV task import, filtered export, Excel/timezone options | QS p23 | 2.5 | PARTIAL (reconciled 2026-09-11 — CSV import/export DONE, see Epic 2.5; Excel-format export and per-column timezone options are the genuine remaining gap) |
| Approved reusable snippets, maximum 100 tasks | QS p10, p24 | 2.3 | DONE (reconciled 2026-09-11 — see Epic 2.3: `POST /api/runbooks/{id}/save-as-snippet`/`insert-snippet`, 100-task cap enforced) |

### Phase 3 and 4 guide requirements

| Requirement | Source | Backlog mapping | Status |
|---|---|---|---|
| Data-source view maps CMDB applications/services to templates | QS p10 | 3.1, 3.2 | BACKLOG |
| Parent runbook controls one level of linked child runbooks | QS p25 | 4.1 | DONE (reconciled 2026-09-11 — see Epic 4.1: parent/child linking, one-level-only enforced, `test_linked_runbooks_reject_more_than_one_level_of_nesting`) |
| Linked-runbook dashboard aggregates child progress live | QS p25 | 4.1, 4.2 | DONE (reconciled 2026-09-11 — see Epic 4.1: `aggregate_progress`/`aggregate_status` on the parent, live via `runbook_document()`) |
| Multi-runbook dashboard with filters and scheduled email sharing | QS p31 | 4.2 | DONE (reconciled 2026-09-11 — per-user configurable dashboard and scheduled-email sharing both DONE, see Epic 4.2) |
| Post-implementation review after completion | QS p32 | 4.2 | DONE |
| Downloadable, filterable audit evidence | QS p29 | 4.3 | PARTIAL (reconciled 2026-09-11 — checksummed, hash-chain-verified download DONE via `GET /api/admin/audit/export`, see Epic 4.3; server-side filtering by date/actor/action is the genuine remaining gap — the endpoint always returns the full tenant history) |

### Video-derived integration requirements

Source: supplied integration demonstration,
reviewed from the full 5:22 transcript on 2026-09-06.

| Requirement | Video evidence | Backlog mapping | Status |
|---|---|---|---|
| Admin configures the ServiceOps endpoint, safety policy, and encrypted API-key lifecycle entirely in the web UI | ServiceOps API client and least-privilege requirements | 3.1 | DONE |
| Admin tests a connection without exposing its credential to the browser | 4:38-5:15 | 3.1 | DONE |
| ServiceOps API compatibility test validates JSON, authentication, and `tickets:read`, and explains additional lifecycle scopes | ServiceOps REST API v1 contract | 3.1 | DONE |
| Test Connection validates the URL and API key currently entered in the browser before saving, rather than silently testing a stale deployment fallback | ServiceOps administrator workflow regression 2026-09-10 | 3.1 | DONE |
| Browser-triggered ServiceOps synchronization uses the authenticated CSRF-aware API client, recovers a stale in-memory CSRF token from the authenticated session with one safe retry, and refreshes the runbook projection without a page reload | ServiceOps runbook synchronization regressions 2026-09-10 and 2026-09-11 | 3.1 | DONE |
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
