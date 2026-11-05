# Deploying CVEnom

CVEnom is a self-hosted, internet-facing service. Cloudflare in front is welcome but the origin must
be safe without it.

## First run

```sh
cp .env.example .env
# fill in the blanks: POSTGRES_PASSWORD, APP_DB_PASSWORD, REDIS_PASSWORD (openssl rand -hex 24),
# SECRETS_KEY (openssl rand -base64 32), plus any API keys you have
docker compose --env-file ./.env -f deploy/docker-compose.prod.yml up -d
```

Always pass `--env-file ./.env` (run from the repo root). Compose treats `deploy/` as the project
directory, so without it the root `.env` is not used to fill the `${VAR:?}` references and the
command aborts.

- `migrate` runs automatically (`alembic upgrade head`) and `api` starts only after it succeeds.
- Postgres creates the non-superuser role `cvenom_app` (owner of the `cvenom` database) on first
  init of an empty `pgdata` volume. The app connects as that role.
- Create the first admin (the password is read from `ADMIN_PASSWORD` or stdin, never argv):

  ```sh
  docker compose --env-file ./.env -f deploy/docker-compose.prod.yml run --rm -e ADMIN_PASSWORD api create-admin --email you@example.com
  ```

  Export `ADMIN_PASSWORD` in your shell first (or pipe it on stdin with `-T`). Do not put it in
  `.env`: that file is handed to every app container.
- DB and Redis passwords must be URL-safe (`openssl rand -hex 24`): compose builds `DATABASE_URL`
  and `REDIS_URL` from them without escaping.
- Sign in as the admin and invite further users from the admin API.

Only `api` publishes a port, and only on `127.0.0.1:8000`. Postgres and Redis publish nothing.
All app containers run read-only, as uid 10001, with all capabilities dropped. They receive `.env`
through `env_file`, but compose blanks `POSTGRES_PASSWORD`, `APP_DB_PASSWORD` and `REDIS_PASSWORD`
in their environment: the app only needs those inside `DATABASE_URL` / `REDIS_URL`.
`REQUIRE_SECRETS_KEY=true` makes the API refuse to start when `SECRETS_KEY` is missing or invalid
(the worker logs the error and keeps running).

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

How the client IP is resolved: uvicorn runs with `--proxy-headers`, so when the peer matches
`FORWARDED_ALLOW_IPS` it rewrites the peer to the right-most untrusted `X-Forwarded-For` hop. The
app then applies its own check (`TRUSTED_PROXY_CIDRS`) to that peer. Cloudflare always sends
`X-Forwarded-For`, so in practice the right-most `X-Forwarded-For` hop is the client IP that is
used.

`TRUST_CF_CONNECTING_IP` is therefore close to inert: `CF-Connecting-IP` is consulted only when a
request from a trusted proxy carries **no** `X-Forwarded-For`. Set it to `true` only for cloudflared
(every request must come through Cloudflare). For a non-Cloudflare host proxy (nginx, Caddy): have
it strip any client-supplied `CF-Connecting-IP`, set `X-Forwarded-For` itself, and leave
`TRUST_CF_CONNECTING_IP=false`.

**(b) A reverse proxy running as a container on the `cvenom` network.** The peer is that
container's IP on `172.28.0.0/24`: give it a fixed `ipv4_address` and use `<ip>/32` (or the
subnet) for both settings.

**(c) `127.0.0.1` is wrong for the published-port topology.** The connection arrives from the
bridge gateway, not loopback. If `FORWARDED_ALLOW_IPS` is `127.0.0.1`, uvicorn ignores the
forwarded headers and the peer stays `172.28.0.1`; the app's own `X-Forwarded-For` walk still
separates visitors as long as `TRUSTED_PROXY_CIDRS` contains the gateway. What actually collapses
every visitor into one rate-limit and login-throttle bucket is a `TRUSTED_PROXY_CIDRS` that does
not contain the real peer (for example `127.0.0.1/32`): the app then never reads the forwarded
headers. Set both settings to the gateway.

**(d) Verify.**

1. Confirm the gateway: `docker network inspect deploy_cvenom --format '{{(index .IPAM.Config 0).Gateway}}'`
   (the network is `<project>_cvenom`; the project name is `deploy` unless you pass `-p`). It
   should print `172.28.0.1`.
2. Request `/api/health` through the tunnel or proxy, then read the access log. uvicorn logs
   access by default, so no rebuild is needed:

   ```sh
   docker compose --env-file ./.env -f deploy/docker-compose.prod.yml logs api
   ```

   The client address on that line must be the real visitor's, not `172.28.0.1`. It shows the
   peer after uvicorn's rewrite, so `172.28.0.1` there means `FORWARDED_ALLOW_IPS` does not match.
3. **Docker Desktop (Windows/macOS):** published ports are forwarded through Docker Desktop's VM,
   so the peer the container sees may not be the bridge gateway. Check the address in the access
   log for a request sent directly to `127.0.0.1:8000`, and set both settings to that peer.

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
- `API_DOCS` (default `false`): enables `/docs` and `/redoc`. Keep off in production. Note that
  the strict `Content-Security-Policy` (`default-src 'none'`) blocks the Swagger UI / ReDoc assets,
  so those pages render blank; `/openapi.json` itself works.

## Alert rules

- Rules fire only on **KEV additions** (CISA KEV or VulnCheck KEV), by design: that keeps alerts
  to "exploited in the wild" and prevents a firehose.
- `kev_added` matches every KEV addition. `keyword` matches the summary or affected products.
- `cvss_min` and `epss_min` filter by **known** scores: a CVE whose CVSS / EPSS percentile is known
  and below the threshold does not fire.
- An **unknown** score fires: a CVE added to KEV before NVD/EPSS have scored it still alerts
  rather than being silently dropped.

## Key rotation

- **JWT signing keys** rotate automatically every 7 days (`JWT_ROTATION_DAYS`); no action needed.
- **`SECRETS_KEY`** re-encryption is **not automated in v1**. Changing the value makes everything
  encrypted under the old key unreadable:
  - **JWT keys rotate automatically** on the first login or refresh after the change: the
    undecryptable signing key is retired (a warning is logged) and a new one is created. Sessions
    survive, and access tokens already issued keep verifying until they expire (verification
    uses only the public key).
  - **Webhook URLs and secrets** become unreadable. The API masks them as "(unavailable)", and
    their deliveries are deferred (retried hourly, no attempts burned) until they expire after 7
    days. An admin must delete and re-add those recipients.

  Back the key up; do not change it casually.

## Backups

- Database: `docker compose --env-file ./.env -f deploy/docker-compose.prod.yml exec -T postgres pg_dump -U postgres -Fc cvenom > cvenom-$(date +%F).dump`
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

There is no dependency vulnerability scan in CI yet. Run one periodically (and before each
release) against the lock file:

```sh
pip-audit -r backend/requirements.lock
```

## Security notes

- After a user is deactivated, an already-open live WebSocket stays connected until its access token
  expires (at most 15 minutes). It carries only "data changed" hints and no data.
