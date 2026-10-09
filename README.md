# FlowOps

Operational-orchestration app for planning, rehearsing, and executing
dependency-aware runbooks. Pairs with ServiceOps: ServiceOps owns ITSM
records and governance, FlowOps owns coordinated execution.

Development is tracked in [PRODUCT_BACKLOG.md](PRODUCT_BACKLOG.md).

[![CI](https://github.com/awijesundara/FlowOps/actions/workflows/ci.yml/badge.svg)](https://github.com/awijesundara/FlowOps/actions/workflows/ci.yml)
[![Last commit](https://img.shields.io/github/last-commit/awijesundara/FlowOps/main)](https://github.com/awijesundara/FlowOps/commits/main)
[![Top language](https://img.shields.io/github/languages/top/awijesundara/FlowOps)](https://github.com/awijesundara/FlowOps)
[![Code size](https://img.shields.io/github/languages/code-size/awijesundara/FlowOps)](https://github.com/awijesundara/FlowOps)
[![version](https://img.shields.io/badge/version-0.8.0-003E4C)](VERSION)
[![python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](requirements.txt)
[![docker](https://img.shields.io/badge/docker-compose%20%7C%20kubernetes-2496ED?logo=docker&logoColor=white)](#quick-start)
[![pairs with](https://img.shields.io/badge/pairs%20with-ServiceOps-0C7C68)](https://github.com/awijesundara/ServiceOps)

## Quick start

```bash
git clone https://github.com/awijesundara/FlowOps.git
cd FlowOps
docker compose up --build -d
```

Set `FLOWOPS_BOOTSTRAP_PASSWORD` in `.env` first (see `.env.example`), then
open <http://localhost:8088> and sign in as `admin` with that password. If it
is not set, a one-time password is generated and printed in the container log
when the admin account is created. There is no default password.
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
- Role-based access (Admin, Editor, Member, Stakeholder, plus scoped roles)
- Sign-in like ServiceOps: local accounts, AD/LDAP, Keycloak/OIDC and
  Cloudflare Access, with TOTP multi-factor sign-in and account lockout
  (see below)
- SCIM provisioning, encrypted backups, Web Push notifications
- Two-way ServiceOps ticket linking (see below)
- One runtime dependency (`ldap3`, for directory sign-in); everything else is
  the Python standard library and OpenSSL

## Sign-in and identity

Configure everything under **Administration → Platform & security → Sign-in &
identity**.

| Source | How it works |
|---|---|
| Local accounts | Password sign-in. Can be switched off for everyone except local administrators, who remain as break-glass accounts. |
| AD/LDAP | FlowOps binds to the directory with a service account, finds the user, verifies the password with a user bind and reads their groups (`memberOf`, AD nested groups, or a group search filter for OpenLDAP). Use `ldaps://` or StartTLS; set `FLOWOPS_LDAP_CA_CERT` when the directory uses a private CA. Several servers fail over in order. |
| ServiceOps pass-through | Alternative to direct LDAP: FlowOps asks ServiceOps to verify directory passwords. |
| Keycloak/OIDC | Authorization code flow with PKCE and a nonce. Register `<FLOWOPS_PUBLIC_URL>/auth/oidc/callback` as the redirect URI. Optionally require an assurance level (`acr`) and create accounts on first sign-in. |
| Cloudflare Access | A verified Access identity signs in the matching active account. |

Directory and OIDC accounts are created on first sign-in. Group-to-role and
group-to-team mappings set their role (Admin, Editor, Member or Stakeholder)
and team on every sign-in; with **Only members of a mapped group may sign
in**, everyone else is refused. A directory or OIDC identity never takes over
a local administrator with the same username. **Check a user** shows what a
directory account would get without signing in as them.

Every account can turn on authenticator-app (TOTP) multi-factor sign-in under
**Profile → Security**, with ten single-use backup codes; administrators can
reset it from the user list. After a configurable number of failed sign-ins
(default 5) an account locks for a configurable time (default 15 minutes);
administrators can unlock it. Every outcome is in the audit trail.

## ServiceOps integration

1. In ServiceOps: **Administration → API access** → create a client with
   `tickets:read` (add `tickets:update`/`workflows:execute` if you want
   FlowOps to write status back).
2. In FlowOps: **Administration → Connections** → paste the `sop_…` key.
3. Link a ServiceOps ticket number when creating a runbook, then use
   **Sync ServiceOps** on the runbook page. The change's CTASKs become tasks.

What flows each way:

| Direction | What | How |
|---|---|---|
| ServiceOps → FlowOps | Approval gate before Live | Checked on the ready → live transition |
| ServiceOps → FlowOps | Change withdrawn or re-opened for approval | Signed `change.state_changed` event; the runbook shows an alert |
| ServiceOps → FlowOps | CTASK closed or cancelled in ServiceOps | Signed `change_task.state_changed` event; the live task follows |
| FlowOps → ServiceOps | Change In Progress / Resolved | Live and complete transitions |
| FlowOps → ServiceOps | CTASK state and execution evidence | Queued, retried write-back with an append-only work note |

To receive events, open **Administration → Connections → Events from
ServiceOps**, generate a signing secret, then in ServiceOps add a **Webhook**
integration pointing at `/api/integrations/serviceops/events/<instance>`
with that secret, subscribed to **Change state changes** and **Change task
state changes**. Set `FLOWOPS_INTERNAL_URL` (in a cluster) or
`FLOWOPS_PUBLIC_URL` so the page shows the full receiver URL.

In the same cluster, ServiceOps posts to FlowOps' Service, for example
`http://flowops.operations.svc.cluster.local`. ServiceOps only sends webhooks
to private addresses for hosts listed in its `WEBHOOK_INTERNAL_HOSTS`, so add
FlowOps' Service name there (a ServiceOps release that includes
`WEBHOOK_INTERNAL_HOSTS`), and allow the traffic in both NetworkPolicies. Execution evidence needs ServiceOps 1.109 or later; older
releases still receive CTASK state.

CTASK writes never block task execution. If ServiceOps is unreachable they
retry with backoff, and anything ServiceOps refuses is listed with its error
and a **Retry** action under **Write-back to ServiceOps**.

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
python -m pytest tests/test_flowops.py -q    # backend
python -m pytest tests/test_identity.py -q   # sign-in, MFA, lockout; LDAP against a real slapd
python -m pytest tests/test_browser.py tests/test_identity_browser.py -v   # Playwright + axe-core a11y
```

## Code layout

`server.py` only starts the app; the code lives in the `flowops/` package.

| Path | Holds |
|---|---|
| `flowops/config.py` | Environment settings and product constants |
| `flowops/schema.py`, `db.py`, `audit.py` | SQLite schema and upgrades, connections, hash-chained audit |
| `flowops/crypto.py`, `ratelimit.py`, `net.py`, `sso.py` | Encryption and passwords, sign-in throttling, SSRF-safe HTTP, Cloudflare Access and OIDC tokens |
| `flowops/runbooks.py`, `automation.py` | Planning, task rules, import/export, automation calls |
| `flowops/serviceops.py`, `webhooks.py`, `scim.py` | ServiceOps write-back and events, outbound webhooks, SCIM documents |
| `flowops/mail.py`, `push.py`, `dashboard_email.py`, `backups.py` | Mail, Web Push, scheduled reports, backups |
| `flowops/web/` | HTTP routes, one module per area; `handler.py` dispatches to them |
| `static/` | The single-page UI |
| `tests/` | Backend, browser and opt-in live Keycloak tests |

## Independence

FlowOps is an original implementation of common operational-orchestration
concepts (runbooks, dependency gates, live execution tracking) — not a copy
of any proprietary product's code, branding, or design.

## Project statistics

| Metric | Value |
|---|---|
| Tracked files | 28 |
| Lines of code (non-blank) | 9,612 |
| Languages | Python 8,113, JavaScript 1,011, CSS 172, Shell 136, HTML 109 |
| Automated tests | 195 |
| Commits | 88 |

CI compiles the server, syntax-checks the UI and runs the unit and browser tests on each push to `main`.
