# FlowOps

Development is governed by the authoritative [Product Backlog](PRODUCT_BACKLOG.md).

FlowOps is an original operational-orchestration application for planning,
rehearsing, and executing dependency-aware runbooks. It complements ServiceOps:
ServiceOps owns ITSM governance and records; FlowOps owns coordinated execution.

## Local preview

```bash
docker compose up --build -d
```

Open <http://localhost:8088>. Persistent SQLite data lives in the named
`flowops-data` Docker volume. Health endpoints are `/health` and `/ready`.

For this local preview, sign in as `admin` with `FlowOps!Preview2026`. Set
`FLOWOPS_BOOTSTRAP_PASSWORD` before the first start of any shared environment.

To run without Docker:

```bash
FLOWOPS_PORT=8088 python3 server.py
```

## Current capabilities

- Workspace dashboard and searchable runbook inventory
- Runbook creation, scheduling, ownership, streams, and comments
- Dependency-gated task execution and calculated critical path
- Draft, ready, live, paused, complete, and cancelled lifecycle
- Templates, progress reporting, and hash-chained audit events
- Persistent SQLite storage and responsive desktop/mobile interface
- Server-side ServiceOps ticket lookup using a least-privilege bearer token
- Authenticated workspaces with expiring HttpOnly sessions and CSRF protection
- Administrator, Runbook Manager, Operator, and Viewer privilege tiers
- User administration, role matrix, workspace policy, and security dashboard
- Authenticated server-sent events with automatic reconnect and sub-second UI refresh
- Live execution timeline, stream filters, status telemetry, and dependency node-map view
- Runbook teams with user membership and team-assigned task execution
- Member-scoped task visibility and server-enforced executor ownership
- Normal, milestone, checklist, validation, SMS, email, and call task types
- Automatic late-task flags plus validation results and evidence commentary
- Durable runbook timing with countdowns, overdue warnings, live elapsed clocks, planned-window progress, and completion variance
- Administrator-managed ServiceOps and Jenkins connection policies, server-only credential status, and safe connection testing

This is a production-shaped MVP, not a copy of Cutover's proprietary software.
It implements common operational-orchestration concepts with original FlowOps
branding, code, information architecture, and visual design.

## ServiceOps connection

1. In ServiceOps, create an API client whose acting user can see the relevant
   tickets. Grant only `tickets:read` for the included lookup integration.
2. Copy `.env.example` to `.env` and set `SERVICEOPS_URL` and
   `SERVICEOPS_TOKEN`. Do not commit `.env`.
3. Recreate the FlowOps container and link a ServiceOps ticket number when
   creating a runbook.
4. Use **Sync ServiceOps** in the runbook view.

The bearer token stays server-side. ServiceOps' tenant, user, team, role, and
lifecycle controls still apply. Future bidirectional updates should use the
existing ServiceOps `tickets:update` and `workflows:execute` scopes with
idempotency keys, and FlowOps should accept signed ServiceOps webhooks.

Admins can configure and test ServiceOps and Jenkins endpoints under
**Administration → Integrations**. Credentials are intentionally absent from
the browser/API configuration model: supply `SERVICEOPS_TOKEN`, or
`JENKINS_USER` and `JENKINS_TOKEN`, to the FlowOps container environment.

## API highlights

| Endpoint | Purpose |
|---|---|
| `GET /api/runbooks` | List runbooks |
| `POST /api/runbooks` | Create a runbook |
| `GET /api/runbooks/{id}` | Retrieve execution plan and history |
| `POST /api/runbooks/{id}/tasks` | Add a dependency-aware task |
| `PATCH /api/tasks/{id}` | Apply a controlled task transition |
| `POST /api/runbooks/{id}/transition` | Apply a runbook transition |
| `POST /api/runbooks/{id}/serviceops-sync` | Retrieve linked ticket |
| `GET /api/events` | Authenticated real-time workspace event stream |

## Product roadmap

The next production phases are authentication/RBAC and tenant isolation,
editable dependency maps, CSV import/export, approved templates, automation
workers and signed webhooks, notifications, scheduled starts, rehearsal
snapshots, parent/child runbooks, richer analytics, PostgreSQL, backup/restore,
and security/observability deployment gates.
# FlowOps
