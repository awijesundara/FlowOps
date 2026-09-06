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
| Customer creates an account and isolated instance | P0 | M | PARTIAL |
| Admin invites users by email | P0 | S | PARTIAL |
| User logs in with email and password | P0 | S | DONE |
| Admin assigns fixed Admin, Editor, or Member role | P0 | M | DONE |
| Session expiry and password reset | P0 | S | PARTIAL |

Role acceptance: Admin may create, edit, and delete instance content; Editor may
create and edit runbooks; Member may act only on assigned tasks. Role changes
take effect without re-login.

### Epic 1.2 — Workspace and Runbook Structure

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Admin creates a workspace | P0 | S | DONE |
| Editor creates a runbook inside a workspace | P0 | M | DONE |
| Editor sets runbook name and scheduled start | P0 | S | DONE |
| Editor duplicates a runbook | P1 | S | BACKLOG |
| Editor archives a completed runbook | P1 | S | BACKLOG |

### Epic 1.3 — Streams and Tasks

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Editor creates streams within a runbook | P0 | S | PARTIAL |
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
| Users filter tasks by stream, owner, or status | P1 | M | PARTIAL |

Real-time acceptance: changes appear for all viewers within two seconds without
manual refresh; concurrency must be load-tested before building later phases.

### Epic 1.6 — Basic Audit Trail

| Story | Priority | Size | Status |
|---|---:|---:|---:|
| Every task status/edit is logged with timestamp and actor | P0 | M | PARTIAL |
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

Product-owner sequencing note (2026-09-06): the supplied Jenkins demonstration
and explicit ServiceOps administration request authorize a bounded Phase 3
foundation slice while Phase 1 remains active. Connection policy, server-secret
status, and safe connection tests are `DONE`; job actions, asynchronous polling,
and task outcome automation remain `BACKLOG` and may not be represented as done.

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
| Real-time load test before each phase | P0 | NEXT |
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

1. Finish Phase 1 Epic 1.1 P0: instance/account isolation, email login/invite,
   fixed role model, immediate role propagation, password reset.
2. Finish Phase 1 Epic 1.2 P0: real workspace creation and runbook ownership.
3. Finish Phase 1 Epic 1.3 and 1.4 P0 assignment/team visibility gaps.
4. Validate Phase 1 with accessibility and real-time load evidence.

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

Source: [Cutover integrates with Jenkins](https://www.youtube.com/watch?v=sPqkWgEgBto),
reviewed from the full 5:22 transcript on 2026-09-06.

| Requirement | Video evidence | Backlog mapping | Status |
|---|---|---|---|
| Admin configures ServiceOps/Jenkins endpoint, enablement, safety policy, and server-secret status | 4:38-5:15 stresses discovery, authentication, and least privilege | 3.1 | DONE |
| Admin tests a connection without exposing its credential to the browser | 4:38-5:15 | 3.1 | DONE |
| Jenkins action selects an existing job and supports sets of jobs | 0:13-0:44 | 3.1 | BACKLOG |
| Integration tasks execute only in Live; rehearsal safely skips them | 1:28-1:39 | 3.1 | BACKLOG |
| Job parameters map FlowOps/runbook values into the Jenkins payload | 1:11-1:24; 3:57-4:30 | 3.1, 3.2 | BACKLOG |
| Queued/running progress and percentage update the task in real time | 1:42-2:25 | 1.5, 3.1 | BACKLOG |
| Jenkins success auto-completes and failure marks the task failed | 2:18-2:55 | 3.1 | BACKLOG |
| Missing-job errors return actionable detail; operator can retry or audited-skip | 2:55-3:50 | 1.6, 3.1 | BACKLOG |
| Only authorized executors can trigger potentially destructive external jobs | 4:38-5:03 | 1.1, 3.1 | BACKLOG |
| ServiceOps owns approval/risk/record lifecycle; FlowOps returns execution state and evidence | Product integration decision | 3.1, 3.5 | PARTIAL |

### Guide-derived delivery rule

For each story above, completion requires: persistent data behavior, server-side
authorization, real-time propagation where applicable, accessible desktop and
mobile UI, actor-attributed audit evidence, automated regression coverage, and
a healthy Docker preview. A visual placeholder does not qualify as complete.
