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

Only `frontend` (nginx) publishes a port, and only on `127.0.0.1:8080`. The api, Postgres and Redis
publish nothing: the api is reachable only through nginx. The `frontend` container runs
unprivileged (uid 101) with a read-only root filesystem, tmpfs for `/tmp` and `/var/cache/nginx`,
and all capabilities dropped. All app containers run read-only, as uid 10001, with all capabilities dropped. They receive `.env`
through `env_file`, but compose blanks `POSTGRES_PASSWORD`, `APP_DB_PASSWORD` and `REDIS_PASSWORD`
in their environment: the app only needs those inside `DATABASE_URL` / `REDIS_URL`.
`REQUIRE_SECRETS_KEY=true` makes the API refuse to start when `SECRETS_KEY` is missing or invalid
(the worker logs the error and keeps running).

## Cloudflare and reverse proxies

The `frontend` service is an unprivileged nginx (`frontend/nginx.conf`). It serves the built SPA
and proxies `/api/` and the WebSocket `/api/ws/live` to `api:8000` on the same origin, so the
browser only ever talks to one origin and the CSP needs no remote sources. It is the only
service that publishes a port: `127.0.0.1:8080`. The api publishes nothing.

Compose pins the `cvenom` network to `172.28.0.0/24` with gateway `172.28.0.1`, and pins nginx to
`172.28.0.10`. The chain is:

```
visitor -> Cloudflare -> cloudflared (host) -> 127.0.0.1:8080
        -> bridge gateway 172.28.0.1 -> nginx 172.28.0.10 -> api:8000
```

**(a) Point cloudflared (or any reverse proxy on the host) at `http://127.0.0.1:8080`.** Docker
NATs the published port, so nginx sees the bridge **gateway `172.28.0.1`** as its TCP peer.
Cloudflare puts the visitor in `X-Forwarded-For`. These are the defaults in compose and
`.env.example`:

```
TRUSTED_PROXY_CIDRS='["172.28.0.1/32","172.28.0.10/32"]'
FORWARDED_ALLOW_IPS=172.28.0.1,172.28.0.10
```

How the real client IP is resolved:

1. nginx trusts only the gateway (`set_real_ip_from 172.28.0.1`, `real_ip_recursive on`). It uses
   the real visitor for its own coarse `limit_req` (20 r/s, burst 40 per client), never as a
   security decision.
2. nginx hands the api `X-Forwarded-For: <incoming chain>, 172.28.0.1`, i.e. the gateway is
   appended as the last hop. (This is written out explicitly instead of
   `$proxy_add_x_forwarded_for`, because `real_ip` rewrites `$remote_addr` to the visitor and the
   gateway hop would otherwise be lost.)
3. The api's TCP peer is nginx, `172.28.0.10`, which is in `FORWARDED_ALLOW_IPS`. uvicorn
   (`--proxy-headers`) walks `X-Forwarded-For` right to left, skips every trusted hop
   (`172.28.0.1`) and takes the first untrusted address as the client. A client that forges
   `X-Forwarded-For: 1.2.3.4` only ends up further left, behind the real address that Cloudflare
   appended, so it is never reached.
4. The app's own check (`client_ip`, using `TRUSTED_PROXY_CIDRS`) then sees the visitor as the
   peer, which is not a trusted proxy, and uses it as is. Both settings hold the same two hops so
   that either layer alone resolves the same client.

`CF-Connecting-IP` is **stripped** by nginx (`proxy_set_header CF-Connecting-IP ""`), so it never
reaches the api, and `TRUST_CF_CONNECTING_IP` must stay `false` (the default). Cloudflare's
`X-Forwarded-For` is the source of truth. If you ever want the header forwarded, remove that line
from `nginx.conf` deliberately and set `TRUST_CF_CONNECTING_IP=true` only when every request
comes through Cloudflare.

**(b) A different reverse proxy as a container on the `cvenom` network** (instead of cloudflared
on the host): give it a fixed `ipv4_address`, trust that `<ip>/32` plus nginx in both settings, and
also add that IP to `set_real_ip_from` (and the `$xfp_to_api` map) in `frontend/nginx.conf`.
Otherwise nginx's `limit_req` sees only the proxy and buckets every visitor together.

**(c) `127.0.0.1` is wrong for the published-port topology.** The connection arrives from the
bridge gateway, not loopback. If `FORWARDED_ALLOW_IPS` omitted the gateway or nginx, uvicorn
would ignore the forwarded headers, and every visitor would collapse into one rate-limit and
login-throttle bucket (the nginx peer). Keep both hops in both settings. If you change the
network subnet, also change `set_real_ip_from` in `frontend/nginx.conf`.

**(d) Verify.**

1. Confirm the gateway: `docker network inspect deploy_cvenom --format '{{(index .IPAM.Config 0).Gateway}}'`
   (the network is `<project>_cvenom`; the project name is `deploy` unless you pass `-p`). It
   should print `172.28.0.1`.
2. Request `/api/health` through the tunnel or proxy, then read the api access log. uvicorn logs
   access by default, so no rebuild is needed:

   ```sh
   docker compose --env-file ./.env -f deploy/docker-compose.prod.yml logs api
   ```

   The client address on that line must be the real visitor's, not `172.28.0.1` and not
   `172.28.0.10`. It is the peer after uvicorn's rewrite, so one of those two addresses there
   means `FORWARDED_ALLOW_IPS` does not match the chain.
3. **Docker Desktop (Windows/macOS):** published ports are forwarded through Docker Desktop's VM,
   so the peer nginx sees may not be the bridge gateway. Request `127.0.0.1:8080` directly, read
   which address nginx forwards (`docker compose --env-file ./.env -f deploy/docker-compose.prod.yml logs frontend`, and the api log), and adjust
   `set_real_ip_from`, `FORWARDED_ALLOW_IPS` and `TRUSTED_PROXY_CIDRS` to that hop.

**Lock down the origin.** Do not rely on Cloudflare alone. Keep `127.0.0.1:8080` bound to loopback
(or firewall the port to the proxy), and if the origin is reachable from the internet, require
Cloudflare Authenticated Origin Pulls (mTLS) or restrict the firewall to Cloudflare's published
ranges. nginx's own limits (64 KB request bodies, bounded headers, a per-client request rate) are a
backstop, not a replacement. A request that bypasses Cloudflare must not be able to spoof client
IPs or skip its rate limits.

`FORWARDED_ALLOW_IPS` is passed to uvicorn `--forwarded-allow-ips`; it must match the proxies that
connect to the container, otherwise forwarded headers are ignored (the image default is
`127.0.0.1`; compose sets `172.28.0.1,172.28.0.10`).

## Content Security Policy and security headers

nginx sends these on every response (`always`, including errors); proxied `/api` responses keep
the API's other headers (such as `Cache-Control`):

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-ancestors 'none';
  base-uri 'none'; form-action 'self'; upgrade-insecure-requests
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff    Referrer-Policy: no-referrer    X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin    Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

There is no `unsafe-inline`, `unsafe-eval`, `blob:` or remote origin. `connect-src 'self'` covers
the same-origin `wss://` live socket in current Chromium and Firefox (checked by
`frontend/e2e/csp.spec.ts`, which serves `dist/` with exactly the headers parsed from
`nginx.conf`). Fonts are real files (never `data:` URIs) because of `font-src 'self'`; the map
worker is a same-origin module worker; React and MapLibre set styles through the CSSOM, which
`style-src 'self'` allows. `index.html` carries no inline script or style.

- **API docs.** FastAPI mounts `/docs`, `/redoc` and `/openapi.json` at the root, outside `/api/`,
  so through nginx they fall into `location /` and return the SPA's `index.html`. With
  `API_DOCS=true` they are reachable only by hitting the api container directly (for example
  `docker compose --env-file ./.env -f deploy/docker-compose.prod.yml exec api ...` from inside, or a
  temporary loopback port), and the api's own CSP would blank Swagger UI there anyway. There is
  deliberately no nginx route for them; keep `API_DOCS=false`.
- **Response headers.** The api sets CSP, HSTS, nosniff, Referrer-Policy and X-Frame-Options itself;
  nginx hides those five from `/api/` responses (`proxy_hide_header`) and sends its own, so each
  appears exactly once. nginx's values equal or exceed the api's for JSON. Any other api header
  (`Cache-Control`, ...) passes through untouched.
- **X-Forwarded-Proto.** nginx passes the gateway's `X-Forwarded-Proto` through only when the peer is
  the trusted gateway and the value is exactly `http` or `https` (cloudflared connects over plain
  http, so `$scheme` alone would always say `http`); otherwise it sends `$scheme`.
- **Rate limit and timeouts.** `limit_req` (20 r/s, burst 40 per visitor) covers `/api/` and the
  WebSocket only, never static files. `/api/` waits up to 60 s, above the 45 s alert test-send cap.
- **Adding an origin.** Only when you truly need one (for example a tile server): add it to the
  one directive that needs it in `frontend/nginx.conf` (for tiles, `connect-src 'self'
  https://tiles.example.com`), never to `default-src`, then rebuild the frontend image. The
  packaging tests still require no `unsafe-*`, no `blob:` and no wildcard. Update the e2e and
  `src/test/project.test.ts` (which forbids remote URLs in the bundle) in the same change.
- Headers are declared only at server level in `nginx.conf`: nginx drops inherited `add_header`
  lines in any `location` that declares its own, so do not add one inside a `location`.

## Exposure settings

- `PUBLIC_READ` (default `true`): anonymous read-only access to radar data. Set `false` to require
  login for everything.
- `CORS_ORIGINS`: JSON list of exact origins, e.g. `'["https://cvenom.example.com"]'`. No wildcards.
  Empty means same-origin only.
- `API_DOCS` (default `false`): enables `/docs`, `/redoc` and `/openapi.json` on the api. Keep off in
  production. They are not reachable through nginx (see "Content Security Policy" above).

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

## API keys

Blank = that source is skipped, or runs unauthenticated where it supports that. The ransomware.live,
Cloudflare Radar and abuse.ch ThreatFox collectors are **off** while their key is blank; DShield and
Feodo need no key.

| Setting | Source |
| --- | --- |
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key |
| `VULNCHECK_API_TOKEN` | https://vulncheck.com/community |
| `GITHUB_TOKEN` | https://github.com/settings/tokens (no scopes needed) |
| `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` | https://www.maxmind.com/en/geolite2/signup |
| `CF_RADAR_TOKEN` | Cloudflare dashboard, API Tokens (Radar read) |
| `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ |
| `RANSOMWARE_LIVE_API_KEY` | ransomware.live Pro key (paid). The collector is OFF while this is blank. Polls hourly per their fair-use policy. |

### ransomware.live fair use

- CVEnom polls ransomware.live hourly, which respects their 30-minute cache.
- Anonymous/public viewers see only aggregated per-country victim counts; individual victim
  records (names, groups, post URLs) are shown only to signed-in users and never re-served
  to anonymous viewers.
- Use a single key; do not rotate multiple keys to avoid quotas.
- Raw ransomware.live data must not be exported or published.
- The UI credits the source wherever a ransomware.live story is shown ("Ransomware data:
  ransomware.live", a link to https://www.ransomware.live). Anonymous viewers of a CVE whose story
  count includes hidden sources see "Some sources are visible to signed-in users only."
- Story and per-CVE counts (`recent_story_count`) and lane placement include ransomware.live
  stories for everyone: they are aggregate statistics, not records.

All keys are optional; a source without its key is skipped (or runs unauthenticated where it supports that).

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
