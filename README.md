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
- Semantic-versioned releases (`VERSION` file, same convention as ServiceOps), shown in the sidebar and login screen
- Server-side ServiceOps ticket lookup using a least-privilege bearer token
- Authenticated workspaces with expiring HttpOnly sessions and CSRF protection
- Expiring single-use invitations and password recovery with session invalidation and non-enumerating requests
- Administrator, Runbook Manager, Operator, and Viewer privilege tiers
- User administration, role matrix, workspace policy, and security dashboard
- Authenticated server-sent events with automatic reconnect and sub-second UI refresh
- Live execution timeline, stream filters, status telemetry, and dependency node-map view
- Runbook teams with user membership and team-assigned task execution
- Member-scoped task visibility and server-enforced executor ownership
- Normal, milestone, checklist, validation, SMS, email, and call task types
- Automatic late-task flags plus validation results and evidence commentary
- Durable runbook timing with countdowns, overdue warnings, live elapsed clocks, planned-window progress, and completion variance
- Administration home for users, roles, workspaces, sessions, audit evidence, system health, email readiness, and connected systems
- Administrator-managed ServiceOps connection policy with encrypted API-key set/rotate/revoke and compatibility testing
- SMTP-delivered invitations and password resets with preview-only token display

This is a production-shaped MVP, not a copy of Cutover's proprietary software.
It implements common operational-orchestration concepts with original FlowOps
branding, code, information architecture, and visual design.

## ServiceOps connection

1. In ServiceOps, create an API client whose acting user can see the relevant
   tickets. Grant only `tickets:read` for the included lookup integration.
2. Copy `.env.example` to `.env`, generate a durable
   `FLOWOPS_SETTINGS_ENCRYPTION_KEY`, and set `SERVICEOPS_URL`. Do not commit
   `.env` or rotate the encryption key without migrating stored credentials.
3. Recreate the FlowOps container and link a ServiceOps ticket number when
   creating a runbook.
4. Use **Sync ServiceOps** in the runbook view.

The bearer token stays server-side. ServiceOps' tenant, user, team, role, and
lifecycle controls still apply. Bidirectional updates use the existing
ServiceOps `tickets:update` and `workflows:execute` scopes with idempotency
keys. Signed inbound ServiceOps webhooks remain backlog work.

The connector uses ServiceOps REST v1 directly: `GET /api/v1/tickets/{number}`
for governed context, `PATCH /api/v1/tickets/{number}` for idempotent Live and
completion write-back, and optionally `POST
/api/v1/tickets/{number}/workflow-events`. FlowOps sends an `X-Request-ID` on
every request and an `Idempotency-Key` for state changes. Create the acting API
client in ServiceOps with `tickets:read`, adding `tickets:update` and
`workflows:execute` only for enabled policies.

Admins configure ServiceOps under **Administration → Connections**. Create a
named client in ServiceOps under **Administration → API access**, grant
`tickets:read`, `tickets:update`, and optionally `workflows:execute`, then paste
the one-time `sop_…` key into FlowOps. In MicroK8s use
`http://serviceops.operations.svc.cluster.local`; the public Cloudflare Access
URL is intended for browsers and returns an HTML login challenge to API calls.

FlowOps can also delegate AD/LDAP password verification to ServiceOps. Enable
it under **Administration → Platform settings → Sign-in and directory** and
enter the AD domain shown by ServiceOps. The login page then labels the source
with that domain and provisions successful directory users as FlowOps Members.
They can paste, rotate, test, or revoke a scoped token there. FlowOps encrypts
the token at rest and never returns it through the browser API. There is no
deployment-token fallback: the web-managed credential is the sole ServiceOps
API identity, so a revoked environment secret cannot appear healthy. The
encryption key itself remains a deployment secret.

For real invitation and password-reset delivery, configure
`FLOWOPS_PUBLIC_URL`, `FLOWOPS_SMTP_HOST`, `FLOWOPS_MAIL_FROM`, and the relevant
SMTP port/security/credential variables. Set `FLOWOPS_PREVIEW_TOKENS=false` in
shared environments; only local preview mode returns one-time tokens to the UI.

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

### Public API access

Every endpoint above also accepts a scoped bearer token instead of a browser
session, for external automation (CI pipelines, scripts, other services).

1. Sign in as an Administrator, go to **Administration → API tokens → New
   token**, and choose one or more scopes: `runbooks:read` (list/view only)
   or `runbooks:write` (create, edit, and transition runbooks and tasks).
2. Copy the returned `fo_…` token immediately -- it is shown exactly once and
   cannot be retrieved again. Revoke it from the same screen at any time;
   revocation takes effect on the next request.
3. Call the API with `Authorization: Bearer fo_…` instead of a session
   cookie. Bearer-token requests are exempt from the CSRF header requirement
   (CSRF only applies to cookie-based browser sessions), so no
   `X-CSRF-Token` is needed.

```bash
curl -H "Authorization: Bearer fo_..." https://your-flowops-host/api/runbooks

curl -X POST -H "Authorization: Bearer fo_..." -H "Content-Type: application/json" \
  -d '{"name":"Automated release"}' https://your-flowops-host/api/runbooks
```

## Product roadmap

The next production phases are authentication/RBAC and tenant isolation,
editable dependency maps, CSV import/export, approved templates, automation
workers and signed webhooks, notifications, scheduled starts, rehearsal
snapshots, parent/child runbooks, richer analytics, PostgreSQL, backup/restore,
and security/observability deployment gates.
# FlowOps
