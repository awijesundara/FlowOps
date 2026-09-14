# FlowOps

Operational-orchestration app for planning, rehearsing, and executing
dependency-aware runbooks. Pairs with ServiceOps: ServiceOps owns ITSM
records and governance, FlowOps owns coordinated execution.

Development is tracked in [PRODUCT_BACKLOG.md](PRODUCT_BACKLOG.md).

## Quick start

```bash
git clone https://github.com/awijesundara/FlowOps.git
cd FlowOps
docker compose up --build -d
```

Open <http://localhost:8088> and sign in as `admin` / `FlowOps!Preview2026`
(set `FLOWOPS_BOOTSTRAP_PASSWORD` before running this anywhere shared).
Data persists in the `flowops-data` Docker volume.

Without Docker:

```bash
FLOWOPS_PORT=8088 python3 server.py
```

## Features

- Dependency-aware runbooks with calculated critical path and AND/OR gates
- Draft → ready → live → paused → complete lifecycle with hash-chained audit
- Real-time execution timeline via server-sent events, live elapsed clocks
- Threaded comments, @mentions, and team-scoped task ownership
- Templates, node-map view, and portfolio analytics
- Role-based access (Administrator, Runbook Manager, Operator, Viewer)
- OIDC SSO, SCIM provisioning, encrypted backups, Web Push notifications
- Two-way ServiceOps ticket linking (see below)
- Zero third-party runtime dependencies — pure Python stdlib + OpenSSL

## ServiceOps integration

1. In ServiceOps: **Administration → API access** → create a client with
   `tickets:read` (add `tickets:update`/`workflows:execute` if you want
   FlowOps to write status back).
2. In FlowOps: **Administration → Connections** → paste the `sop_…` key.
3. Link a ServiceOps ticket number when creating a runbook, then use
   **Sync ServiceOps** on the runbook page.

In MicroK8s, use the in-cluster URL
(`http://serviceops.operations.svc.cluster.local`) — the public
Cloudflare Access URL returns an HTML login page to API calls, not JSON.

## API

Every endpoint below also accepts `Authorization: Bearer fo_…` (create one
under **Administration → API tokens**) instead of a browser session — useful
for CI pipelines and scripts.

| Endpoint | Purpose |
|---|---|
| `GET /api/runbooks` | List runbooks |
| `POST /api/runbooks` | Create a runbook |
| `GET /api/runbooks/{id}` | Execution plan and history |
| `POST /api/runbooks/{id}/tasks` | Add a dependency-aware task |
| `PATCH /api/tasks/{id}` | Apply a task transition |
| `POST /api/runbooks/{id}/transition` | Apply a runbook transition |
| `GET /api/events` | Real-time workspace event stream |

```bash
curl -H "Authorization: Bearer fo_..." https://your-flowops-host/api/runbooks
```

## Testing

```bash
python -m pytest test_flowops.py -q          # backend
python -m pytest test_browser.py -v          # Playwright + axe-core a11y
```

## Independence

FlowOps is an original implementation of common operational-orchestration
concepts (runbooks, dependency gates, live execution tracking) — not a copy
of any proprietary product's code, branding, or design.
