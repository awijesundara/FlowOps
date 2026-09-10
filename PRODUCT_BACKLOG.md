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
| Workspace Manager, Stakeholder, and Member scoped roles | P0 | L | BACKLOG |
| Folder-scoped Runbook Creator | P0 | M | BACKLOG |
| Stream Editor rights | P1 | M | BACKLOG |
| Global Stakeholder read-only visibility | P1 | M | BACKLOG |

### Epic 2.2 — Folders and Runbook Types

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Workspace folders | P0 | S | BACKLOG |
| Custom runbook types with name, icon, and color | P1 | M | BACKLOG |
| Approval flow attached to runbook type | P1 | L | BACKLOG |
| Creator selects a runbook type and inherits defaults | P0 | S | BACKLOG |

### Epic 2.3 — Templates

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Save runbook as reusable template | P0 | M | BACKLOG |
| Create runbook from saved template | P0 | S | PARTIAL |
| Scope template visibility by workspace | P2 | M | BACKLOG |

### Epic 2.4 — Central and Linked Teams

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Workspace central teams | P0 | M | BACKLOG |
| Link central team into runbook | P0 | M | BACKLOG |
| Central membership changes propagate | P1 | M | BACKLOG |

### Epic 2.5 — CSV and Bulk Management

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Import tasks from CSV | P1 | M | BACKLOG |
| Bulk-edit owner or timing | P2 | M | BACKLOG |

### Epic 2.6 — Node Map

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Dependency graph identifies sequence and bottlenecks | P1 | L | PARTIAL |
| Nodes color-code task status | P2 | S | DONE |

Exit: multiple teams self-serve within governed boundaries and reuse structures
and central team rosters.

## Phase 3 — Automation and Integration

### Epic 3.1 — Integration Framework

Named connections (P0/M), API key/basic/bearer/OAuth authentication (P0/L),
triggered actions with URL and payload template (P0/L), automatic context
(P1/M), auto-complete on success (P1/M), and sandbox action tests (P0/M) are
all `BACKLOG` except the fixed ServiceOps read connector, which is `PARTIAL`.

Product-owner sequencing note (2026-09-06): the supplied automation demonstration
and explicit ServiceOps administration request authorize a bounded Phase 3
foundation slice while Phase 1 remains active. Connection policy, encrypted
credential lifecycle, and safe connection tests are `DONE`; job actions, asynchronous polling,
and task outcome automation remain `BACKLOG` and may not be represented as done.

The first-party ServiceOps REST v1 connector is now `PARTIAL`: ticket retrieval,
server-side bearer authentication, request correlation, change approval checks,
idempotent Live/complete state write-back, optional workflow triggering, local
audit evidence, and ticket projection are implemented. ServiceOps API client
creation/revocation remains owned by ServiceOps; inbound signed events and
asynchronous delivery retry remain under Epic 3.5.

### Epic 3.2 — Custom Fields

Typed, scoped custom-field definitions (P0/M) and values on tasks/runbooks
(P1/S) are `BACKLOG`.

### Epic 3.3 — Predefined Integrations

Slack (P1/M), Microsoft Teams (P1/M), and ServiceNow change tracking (P2/L)
are `BACKLOG`. ServiceOps remains the first-party complementary connector.

### Epic 3.4 — Public REST API

External runbook creation (P0/L), status queries (P0/M), task updates (P1/M),
documented sandbox API (P0/M), and scoped revocable tokens (P0/M) are `BACKLOG`.
Current browser endpoints are internal and do not satisfy this epic.

### Epic 3.5 — Outbound Webhooks

State-change webhooks (P1/M) and retry with backoff (P1/M) are `BACKLOG`.

Exit: runbooks trigger external work and external systems safely drive runbooks.

## Phase 4 — Enterprise Scale and Compliance

### Epic 4.1 — Linked Runbooks

Primary/secondary runbook linking (P0/L) and aggregate parent status (P0/L):
`BACKLOG`.

### Epic 4.2 — Dashboards and Reporting

Configurable multi-runbook dashboard (P0/L): `PARTIAL`. Post-event timing and
delay report (P1/M), CSV/PDF export (P1/S): `BACKLOG`.

### Epic 4.3 — Compliance Audit

Immutable-by-policy audit (P0/L): `PARTIAL`. Checksummed export (P1/M) and
configurable retention (P1/M): `BACKLOG`.

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
| Structured API/background-job logging and error tracking | P0 | BACKLOG |
| Database backup and point-in-time recovery | P0 | BACKLOG |
| Public API rate limiting | P1 | BACKLOG |
| Core execution UI accessibility review | P1 | NEXT |
| Internationalization scaffolding | P2 | BACKLOG |
| FlowOps platform disaster-recovery plan | P1 | BACKLOG |

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
| Workspace list/table/timeline views, sorting, filters, saved views | QS p8-p13 | 2.2 | BACKLOG |
| Folders, nested folders, sticky/applied filters | QS p13 | 2.2 | BACKLOG |
| Runbook type selection and blank/template creation | QS p19-p20 | 2.2, 2.3 | PARTIAL |
| Central teams propagate membership into linked runbook teams | QS p10-p11, p22 | 2.4 | BACKLOG |
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
| Post-implementation review after completion | QS p32 | 4.2 | BACKLOG |
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
| Integration tasks execute only in Live; rehearsal safely skips them | 1:28-1:39 | 3.1 | BACKLOG |
| Directory sign-in delegates AD/LDAP verification to ServiceOps and displays the configured AD domain | ServiceOps login behavior | 4.4 | DONE |
| Queued/running progress and percentage update the task in real time | 1:42-2:25 | 1.5, 3.1 | BACKLOG |
| Removed unsupported automation-provider configuration from the product surface and API | Product-owner decision 2026-09-07 | 3.1 | DONE |
| Missing-job errors return actionable detail; operator can retry or audited-skip | 2:55-3:50 | 1.6, 3.1 | BACKLOG |
| Only authorized executors can trigger potentially destructive external jobs | 4:38-5:03 | 1.1, 3.1 | BACKLOG |
| ServiceOps owns approval/risk/record lifecycle; FlowOps returns execution state and evidence | Product integration decision | 3.1, 3.5 | PARTIAL |
| Use ServiceOps REST v1 ticket, update, and workflow APIs with scoped bearer identity, request IDs, and idempotency keys | ServiceOps `docs/API_REFERENCE.md` §§1-3, 5, 7-8 | 3.1 | DONE |
| Block a linked change from Live when ServiceOps reports it is not approved | ServiceOps lifecycle guard and FlowOps integration policy | 3.1 | DONE |
| Persist a minimal ServiceOps ticket projection and show its state in the runbook | ServiceOps ticket document contract | 3.1, 3.2 | DONE |

### Guide-derived delivery rule

For each story above, completion requires: persistent data behavior, server-side
authorization, real-time propagation where applicable, accessible desktop and
mobile UI, actor-attributed audit evidence, automated regression coverage, and
a healthy Docker preview. A visual placeholder does not qualify as complete.
