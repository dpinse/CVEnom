# CVEnom

CVEnom is a self-hosted vulnerability and threat radar. It pulls CVE, exploitation, threat-activity and security-news feeds into one live dashboard, and sends email or webhook alerts when something matching your rules gets exploited.

It is built to run on the open internet. A CDN or tunnel such as Cloudflare in front is welcome, but the app does not depend on it for security.

## What you get

- **A live radar.** A globe shows where scanning, botnet C2, outages and ransomware activity are happening. Four lanes sit beside it:
  - **Exploited now:** on the CISA or VulnCheck KEV lists.
  - **Likely next:** high EPSS.
  - **Loud now:** heavy news coverage.
  - **Fresh criticals:** newly published, CVSS 9 or above.
- **CVE and story detail.** A drawer shows scores, affected products, related stories and geo activity. You can share a link straight to a CVE.
- **Live updates** over a WebSocket. The page refreshes itself when new data lands.
- **Alerts.** Admins write rules that fire when a CVE joins KEV: any KEV listing, CVSS minimum, EPSS minimum, or a keyword. Matches go out by email (SMTP) or by HMAC-signed webhooks, which work with Slack, Discord and generic receivers. Deliveries are deduplicated, retried with backoff, and can be tested from the UI.
- **Users.** Admins and members, invite links, password resets, session management, and user deactivation.
- **Public or private.** By default anyone can view the read-only radar, and signing in adds the rest. Set `PUBLIC_READ=false` to put everything behind the login.

## Data sources

| Source | What it adds | Key |
| --- | --- | --- |
| NVD | CVE records and CVSS scores | optional (`NVD_API_KEY`, for higher rate limits) |
| CISA KEV | known-exploited CVEs | none |
| VulnCheck KEV | earlier known-exploited signal | `VULNCHECK_API_TOKEN` (free; skipped without it) |
| FIRST EPSS | exploit prediction scores | none |
| OSV | affected packages | optional (`GITHUB_TOKEN`) |
| News RSS: Krebs, The Hacker News, BleepingComputer, SecurityWeek | stories linked to CVEs | none |
| DShield | scanning activity by country | none |
| abuse.ch | Feodo Tracker (botnet C2): no key needed. ThreatFox: needs a key | `ABUSECH_AUTH_KEY` (ThreatFox only) |
| Cloudflare Radar | outages and BGP events | `CF_RADAR_TOKEN` (off without it) |
| ransomware.live | ransomware victim posts | `RANSOMWARE_LIVE_API_KEY`, the Pro key (off without it) |
| MaxMind GeoLite2 | IP to country, so activity appears on the globe | `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` (free) |

ransomware.live is polled hourly, in line with their fair-use policy. Anonymous visitors see per-country counts only; individual victim records are shown to signed-in users.

## Architecture

```
browser ──► Cloudflare / your proxy ──► nginx (frontend container, 127.0.0.1:8080)
                                          ├── /            React app
                                          ├── /api/*       ──► FastAPI (api)
                                          └── /api/ws/live ──► WebSocket (api)
                                                                 │
                         Celery worker + beat ──► collectors ──► Postgres
                                                  alerts     ──► Redis (queue, cache, rate limits)
```

- **Backend** (`backend/`): Python 3.12, FastAPI, SQLAlchemy and Alembic, Celery, Postgres and Redis.
- **Frontend** (`frontend/`): React, TypeScript, Vite, TanStack Query and MapLibre GL, served by an unprivileged nginx with a strict Content-Security-Policy.
- **Deployment** (`deploy/`): Docker Compose. Only nginx publishes a port, and only on localhost. The api, Postgres and Redis are reachable only on the internal network.

## Quick start (Docker)

You need Docker with Compose, and a way to put HTTPS in front of port 8080, such as Cloudflare Tunnel (`cloudflared`) or Caddy. On the same machine, `http://localhost:8080` works for a trial run.

```sh
cp .env.example .env
# Fill in POSTGRES_PASSWORD, APP_DB_PASSWORD and REDIS_PASSWORD (openssl rand -hex 24),
# SECRETS_KEY (openssl rand -base64 32), and any API keys you have.

docker compose --env-file ./.env -f deploy/docker-compose.prod.yml up -d --build

# Create the first admin. The password comes from your shell, never from .env.
export ADMIN_PASSWORD='a-long-passphrase'
docker compose --env-file ./.env -f deploy/docker-compose.prod.yml run --rm -e ADMIN_PASSWORD api create-admin --email you@example.com
```

Open `http://localhost:8080` and sign in, then invite the rest of your team from **Admin → Invites**. Each collector first runs one full interval after the scheduler starts, so the radar fills in over the first two hours:
- news: after 15 minutes;
- KEV, DShield and abuse.ch: after 1 hour;
- NVD, EPSS and OSV: after 2 hours.

[`docs/deploy.md`](docs/deploy.md) is the full operator guide. It covers Cloudflare and proxy setup, how to check that real visitor IPs reach the app, security headers, key rotation, backups and fair-use notes.

## Local development

Postgres and Redis for development come from the root `docker-compose.yml`:

```sh
docker compose up -d                      # postgres + redis on localhost

cd backend
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
# backend/.env needs at least DATABASE_URL, REDIS_URL and SECRETS_KEY (see .env.example)
alembic upgrade head
uvicorn cvenom.api.app:create_app --factory --port 8000
celery -A cvenom.tasks:celery_app worker --loglevel=INFO   # add --pool=solo on Windows
celery -A cvenom.tasks:celery_app beat --loglevel=INFO

cd ../frontend
npm ci
npm run dev                                # http://localhost:5173, proxies /api to :8000
```

Use `http://localhost` rather than `127.0.0.1`: the sign-in cookie is marked `Secure`, and browsers only allow that over plain http on `localhost`.

## Tests

```sh
cd backend  && python -m pytest -q              # needs the dev Postgres (uses the cvenom_test database)
cd frontend && npm test                          # unit tests (Vitest)
cd frontend && npm run lint && npm run typecheck
cd frontend && npx playwright install && npm run e2e   # Chromium and Firefox, including a CSP check
```

## Security

CVEnom assumes the public can reach it:

- **Passwords and tokens.**
  - Passwords are hashed with argon2id.
  - Access tokens are short-lived EdDSA JWTs, held only in browser memory.
  - Refresh tokens rotate on every use and detect reuse.
  - They travel in a `Secure`, `HttpOnly`, `SameSite=Strict` cookie, plus a CSRF header.
- **Rate limits.** Every route is rate-limited before authentication. Logins fail closed if Redis is down.
- **Webhooks.** Outbound webhooks are checked against SSRF and pinned to the resolved IP. Their URLs and secrets are encrypted at rest.
- **Response headers.** nginx sends a strict CSP with no `unsafe-*` sources, HSTS, `nosniff`, `no-referrer` and frame denial.
- **Containers.** Every container runs as non-root on a read-only filesystem, with all capabilities dropped.

[`docs/superpowers/reports/`](docs/superpowers/reports/) holds the review and security-review records for each build phase.

## Roadmap

Planned and parked ideas, such as breach-catalog monitoring, per-user watch terms and more alert channels, are in [`docs/ROADMAP.md`](docs/ROADMAP.md).
