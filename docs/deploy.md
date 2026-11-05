# Deploying CVEnom

CVEnom is a self-hosted, internet-facing service. Cloudflare in front is welcome but the origin must
be safe without it.

## First run

```sh
cp .env.example .env
# fill in the blanks: POSTGRES_PASSWORD, APP_DB_PASSWORD, REDIS_PASSWORD (openssl rand -hex 24),
# SECRETS_KEY (openssl rand -base64 32), plus any API keys you have
docker compose -f deploy/docker-compose.prod.yml up -d
```

- `migrate` runs automatically (`alembic upgrade head`) and `api` starts only after it succeeds.
- Postgres creates the non-superuser role `cvenom_app` (owner of the `cvenom` database) on first
  init of an empty `pgdata` volume. The app connects as that role.
- Create the first admin (the password is read from `ADMIN_PASSWORD` or stdin, never argv):

  ```sh
  docker compose -f deploy/docker-compose.prod.yml run --rm -e ADMIN_PASSWORD api create-admin --email you@example.com
  ```

  Export `ADMIN_PASSWORD` in your shell first (or pipe it on stdin with `-T`).
- Sign in as the admin and invite further users from the admin API.

Only `api` publishes a port, and only on `127.0.0.1:8000`. Postgres and Redis publish nothing.
All app containers run read-only, as uid 10001, with all capabilities dropped.

## Cloudflare and reverse proxies

**Cloudflare Tunnel (recommended).** Run `cloudflared` on the same host and point it at
`http://127.0.0.1:8000`. Set:

```
TRUSTED_PROXY_CIDRS='["<cloudflared source network>"]'
TRUST_CF_CONNECTING_IP=true
FORWARDED_ALLOW_IPS=<same source address(es), comma separated>
```

`TRUST_CF_CONNECTING_IP=true` is only safe when every request arrives through Cloudflare and
`TRUSTED_PROXY_CIDRS` contains only that hop.

**Any other reverse proxy (nginx, Caddy, Traefik).** Have it strip any client-supplied
`CF-Connecting-IP`, set `X-Forwarded-For` itself, and set `TRUSTED_PROXY_CIDRS` and
`FORWARDED_ALLOW_IPS` to the proxy's address. Leave `TRUST_CF_CONNECTING_IP=false`.

**Lock down the origin.** Do not rely on Cloudflare alone. Keep `127.0.0.1:8000` bound to loopback
(or firewall the port to the proxy), and if the origin is reachable from the internet, require
Cloudflare Authenticated Origin Pulls (mTLS) or restrict the firewall to Cloudflare's published
ranges. A request that bypasses Cloudflare must not be able to spoof client IPs or skip its rate
limits.

`FORWARDED_ALLOW_IPS` is passed to uvicorn `--forwarded-allow-ips`; it must match the proxy that
connects to the container, otherwise forwarded headers are ignored (default `127.0.0.1`).

## Exposure settings

- `PUBLIC_READ` (default `true`): anonymous read-only access to radar data. Set `false` to require
  login for everything.
- `CORS_ORIGINS`: JSON list of exact origins, e.g. `'["https://cvenom.example.com"]'`. No wildcards.
  Empty means same-origin only.
- `API_DOCS` (default `false`): enables `/docs` and `/redoc`. Keep off in production.

## Key rotation

- **JWT signing keys** rotate automatically every 7 days (`JWT_ROTATION_DAYS`); no action needed.
- **`SECRETS_KEY`** rotation is a manual re-encrypt and is **not automated in v1**. Changing the
  value makes everything encrypted under the old key unreadable: stored webhook secrets/URLs show
  as "(unavailable)" (re-enter them), and the stored JWT private keys cannot be decrypted, so new
  JWT keys are generated and **all users are logged out**. Back the key up; do not change it casually.

## Backups

- Database: `docker compose -f deploy/docker-compose.prod.yml exec -T postgres pg_dump -U postgres -Fc cvenom > cvenom-$(date +%F).dump`
- `.env` (notably `SECRETS_KEY`): store it separately from the database dump, in a secrets manager
  or encrypted vault. A dump without the key cannot recover webhook secrets or sessions.
- The `geoip` volume is re-downloadable and need not be backed up.

## Redis memory policy

Redis runs with `--maxmemory 256mb --maxmemory-policy volatile-ttl --appendonly yes`.
`volatile-ttl` evicts only keys that have a TTL, shortest TTL first. API cache entries (30 s) go
before rate-limit counters (60 s and 900 s), and Celery broker messages have no TTL so they are
never evicted. Under memory pressure, caching degrades first and queued work stays safe.

## Free API keys

| Setting | Source |
| --- | --- |
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key |
| `VULNCHECK_API_TOKEN` | https://vulncheck.com/community |
| `GITHUB_TOKEN` | https://github.com/settings/tokens (no scopes needed) |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | https://www.maxmind.com/en/geolite2/signup |
| `CF_RADAR_TOKEN` | Cloudflare dashboard, API Tokens (Radar read) |
| `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ |
| `RANSOMWARE_LIVE_API_KEY` | ransomware.live Pro API. This one is a paid Pro key; leave it blank to use the free public data. |

All are optional; sources run unauthenticated or are skipped when a key is blank.

## Lock file

`backend/requirements.lock` pins every runtime dependency with sha256 hashes, and the image
installs it with `pip install --require-hashes`. It targets Linux and CPython 3.14. Regenerate from
`backend/` (requires [uv](https://docs.astral.sh/uv/)) after changing `[project] dependencies`:

```sh
uv pip compile pyproject.toml --generate-hashes --python-platform linux --python-version 3.14 --no-header -o requirements.lock
```

Then re-add the three-line comment header at the top of the file (it is checked by the tests), run
the test suite, and rebuild: `docker build -t cvenom-backend backend`.
