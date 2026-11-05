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
- DB and Redis passwords must be URL-safe (`openssl rand -hex 24`): compose builds `DATABASE_URL`
  and `REDIS_URL` from them without escaping.
- Sign in as the admin and invite further users from the admin API.

Only `api` publishes a port, and only on `127.0.0.1:8000`. Postgres and Redis publish nothing.
All app containers run read-only, as uid 10001, with all capabilities dropped.

## Cloudflare and reverse proxies

Compose pins the `cvenom` network to `172.28.0.0/24` with gateway `172.28.0.1`. This matters
because the proxy address the app must trust depends on how the proxy reaches it.

**(a) Cloudflare Tunnel or any reverse proxy running on the host** and connecting to
`127.0.0.1:8000`. Docker NATs the published port, so the container sees the bridge **gateway
`172.28.0.1`** as its peer. Set both to it (these are the defaults in compose and `.env.example`):

```
TRUSTED_PROXY_CIDRS='["172.28.0.1/32"]'
FORWARDED_ALLOW_IPS=172.28.0.1
```

Set `TRUST_CF_CONNECTING_IP=true` only for cloudflared (every request must come through Cloudflare).
For a non-Cloudflare host proxy (nginx, Caddy): have it strip any client-supplied
`CF-Connecting-IP`, set `X-Forwarded-For` itself, and leave `TRUST_CF_CONNECTING_IP=false`.

**(b) A reverse proxy running as a container on the `cvenom` network.** The peer is that
container's IP on `172.28.0.0/24`: give it a fixed `ipv4_address` and use `<ip>/32` (or the
subnet) for both settings.

**(c) `127.0.0.1` is wrong for the published-port topology.** The connection arrives from the
bridge gateway, not loopback. Leaving the setting at `127.0.0.1` makes uvicorn ignore forwarded
headers, so every visitor appears as one bridge IP and they all share a single rate-limit and
login-throttle bucket.

**(d) Verify.** Request `/api/health` through the tunnel or proxy, then confirm the client IP the
app sees is the real visitor's, not `172.28.0.1`: temporarily add `--access-log` to the `api` line
in `backend/docker-entrypoint.sh` (or run uvicorn once with it), rebuild, and check
`docker compose -f deploy/docker-compose.prod.yml logs api`. Remove it afterwards.

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

The Redis password is passed as the `--requirepass` argument, so it is visible in
`docker inspect` and `ps`. That is acceptable when only the operator has Docker access; the upgrade
path is a mounted `redis.conf` or a Docker secret.

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
installs it with `pip install --require-hashes`. The build backend (setuptools, wheel) is pinned
the same way in `backend/build-constraints.lock`, generated with
`uv pip compile --generate-hashes --python-platform linux --python-version 3.14 --no-header` from a
file listing `setuptools` and `wheel`; the app is then installed with `--no-build-isolation`. It targets Linux and CPython 3.14. Regenerate from
`backend/` (requires [uv](https://docs.astral.sh/uv/)) after changing `[project] dependencies`:

```sh
uv pip compile pyproject.toml --generate-hashes --python-platform linux --python-version 3.14 --no-header -o requirements.lock
```

Then re-add the three-line comment header at the top of the file (it is checked by the tests), run
the test suite, and rebuild: `docker build -t cvenom-backend backend`.
