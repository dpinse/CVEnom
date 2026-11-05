# CVEnom API, Auth & Alerts — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a secured, queryable, alerting backend. It has a public read-only REST and WebSocket API for the dashboard, multi-user auth with rotating Ed25519 JWTs, email and webhook alerts driven by a transactional event outbox, and hardened production packaging.

**Architecture:** This plan builds on Plans 1–2 (`feat/geo-news`).

- **FastAPI app factory.** Requests pass through security middleware: headers/CSP, CORS allowlist, trusted-proxy client IP, body-size limit, a Redis rate limiter, and a short-TTL Redis response cache for public reads.
- **Read endpoints.** These wrap the existing read models: `lane_views`, `cve_velocity`, `geo_summary`, `loud_stories`, plus CVE search and detail.
- **Auth.**
  - argon2id password hashes.
  - Short-lived EdDSA access JWTs signed by a rotating key ring. Private keys are encrypted at rest with AES-256-GCM.
  - Opaque refresh tokens, stored hashed per device session, rotated on use with reuse detection.
- **Alerts.**
  - `run_collector` writes each run's `kev_added` events into an `alert_event` outbox inside the same transaction.
  - A dispatcher task evaluates shared alert rules and creates `alert_delivery` rows (unique per rule, CVE, and channel, which gives per-CVE dedupe).
  - Delivery goes through pluggable sinks: SMTP email, and SSRF-hardened, HMAC-signed webhooks.
- **WebSocket.** Live "data changed" pushes go through Redis pub/sub.
- **Packaging.** A non-root Dockerfile, a production compose file, and a hash-pinned lock file.

**Tech Stack:** FastAPI, uvicorn, SQLAlchemy 2 + Alembic, Postgres, Redis (redis-py asyncio), Celery, PyJWT[crypto] (EdDSA), cryptography (AES-256-GCM, Ed25519), argon2-cffi, aiosmtplib, httpx, pytest + httpx ASGI transport.

**Spec:** `docs/superpowers/specs/2026-11-04-cvenom-vuln-threat-radar-design.md` (§5 alerts, §7 security, §8 architecture)

## Global Constraints

- **Monorepo.** Backend paths are relative to `backend/`. Use this worktree's own venv.
- **Shared Postgres.** Use the shared container (compose project `feat-backend-foundation`, port 5432, `cvenom_test`). Never run `docker compose up` from this worktree.
- **Remote git.** Never push, fetch, or pull. Commit locally only, and never stage `.superpowers/`.
- **Deployment posture.** The app faces the internet behind Cloudflare, but Cloudflare is NOT relied on. The origin enforces its own rate limits, security headers, body-size limits, and caching, and trusts forwarded client-IP headers ONLY from configured `trusted_proxy_cidrs`.
- **Stored-text contract.** Stored `title`/`summary`/`label`/`affected` are HTML-entity-escaped plain text, and the API returns them as-is. The frontend decodes once into a text node. Email bodies are **plain text only** (decode entities once). No HTML email in v1.
- **Secrets.** Secrets come only from env: `SECRETS_KEY` (base64, 32 bytes, required for the API and alerts), SMTP credentials, and the CF/abuse.ch/MaxMind tokens.
  - Secrets never appear in logs, URLs, error responses, or API output.
  - Webhook secrets and JWT private keys are encrypted at rest with AES-256-GCM, a random 96-bit nonce, and a key-id prefix.
- **Passwords and tokens.**
  - Passwords use argon2id (argon2-cffi defaults or stronger).
  - Login does constant-time verification against a dummy hash for unknown users and returns one generic error message.
  - Access JWT: EdDSA, TTL 15 min, claims `sub`, `sid`, `role`, `iat`, `exp`, `kid`, with `iss` and `aud` checked.
  - Signing keys rotate every `jwt_rotation_days` (7). Retired keys stay valid for verification until `access TTL + 1h` after retirement.
  - Refresh token: 32 random bytes, stored as SHA-256, TTL 30 days. It rotates on every use. Reusing an already-rotated token revokes that whole session.
  - The refresh token is delivered in an `HttpOnly; Secure; SameSite=Strict; Path=/api/auth` cookie, and the refresh endpoint also requires an `X-CVEnom-CSRF: 1` header.
- **Roles.**
  - `admin` manages users, invites, and alert rules.
  - `member` views authed endpoints and manages its own sessions.
  - Public (anonymous) access covers ONLY `GET` read endpoints, and only while `public_read=True`.
- **Webhooks.**
  - `https` only.
  - The host must resolve ONLY to globally routable IPs. `ipaddress.is_global` must be true for every resolved address. That rejects loopback, private, link-local (incl. 169.254.169.254), CGNAT, multicast, and reserved addresses.
  - This is validated at save time AND re-validated at send time. The connection is pinned to the validated IP (SNI/Host = original hostname), so a DNS rebind cannot redirect it.
  - No redirects. 10s timeout. Response body is not read beyond 64 KB.
  - Payload is HMAC-SHA256 signed: `X-CVEnom-Signature: t=<unix>,v1=<hex>` over `"<t>.<body>"`.
- **API limits.**
  - List endpoints paginate with a max page size of 100.
  - Search terms are length-limited (≤ 200 chars), and LIKE wildcards are escaped.
  - Request bodies are capped at 64 KB.
- **Default rate limits** (tunable settings). Rate-limit hits return `429` with `Retry-After`.
  - Anonymous reads: 60/min per client IP.
  - Login: 10/15 min per IP, plus 10/15 min per email.
  - Authed: 300/min per user.
- **WebSocket.** `/api/ws/live` sends only `{"type":"updated","what":[...]}` notifications, never data. Clients refetch over REST. Limits: max 5 connections per IP. Anonymous connections are allowed only when `public_read=True`.

## Review Focus

- **SSRF via webhooks.** A URL whose host resolves to `127.0.0.1`, `10.x`, `169.254.169.254`, `::1`, or an IPv4-mapped IPv6 private address, or a DNS answer that changes between save and send, must be refused. The connection must go to the validated IP. Tested in Task 12.
- **Auth abuse.** Covers credential stuffing (rate limit, generic errors, constant-time), refresh-token replay (reuse → session revoked), JWT `alg` confusion / `none` / wrong `aud`/`iss` / expired / unknown `kid`, and a member calling admin routes. Tested in Tasks 4, 6, and 7.
- **Data exposure.** Public endpoints must never return password hashes, session data, rule recipients, webhook URLs/secrets, or internal errors/stack traces. Tested in Tasks 5, 8, and 10.
- **Alert floods and duplicates.** One event per CVE per rule per channel. A crash between commit and send must lose nothing (outbox), and sending must not duplicate (delivery uniqueness + status). Tested in Tasks 9 and 11.
- **Injection through query params.** Search `q` with `%`, `_`, `'`, very long strings, and non-UTF8 input. Malformed CVE ids in path params must return 404/422, never 500. Tested in Task 8.

---

### Task 0: Runtime prerequisites

**Files:**
- Modify: `backend/src/cvenom/db.py`, `backend/src/cvenom/tasks.py`, `docker-compose.yml`
- Test: `backend/tests/test_models.py`, `backend/tests/test_tasks.py`

**Interfaces:**
- Produces:
  - `db.get_engine()` and `db.get_sessionmaker()`, lazily created and cached. Nothing connects at import time.
  - `session_scope()` uses them.
  - Existing callers and fixtures are updated, and `import cvenom.db` works without env.
  - A Celery `worker_process_init` signal handler calls `get_engine().dispose(close=False)`.
  - The dev compose file binds `127.0.0.1:5432` and `127.0.0.1:6379`.
- [ ] **Step 1: Write the failing tests.** (a) Importing `cvenom.db` in a subprocess with `DATABASE_URL` unset succeeds. (b) The `worker_process_init` handler is connected and calls `dispose(close=False)` (patched). (c) A test parses `docker-compose.yml` and asserts both published ports start with `127.0.0.1:`.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass**, then run the full suite.
- [ ] **Step 5: Commit.** `fix: lazy DB engine, fork-safe workers, loopback-only dev ports`

---

### Task 1: Security settings and secret encryption

**Files:**
- Create: `backend/src/cvenom/secretbox.py`
- Modify: `backend/src/cvenom/config.py`, `backend/pyproject.toml` (`cryptography`, `argon2-cffi`, `pyjwt[crypto]`, `fastapi`, `uvicorn[standard]`, `aiosmtplib`)
- Test: `backend/tests/test_secretbox.py`

**Interfaces:**
- Produces:
  - Settings fields, all with safe defaults. Secrets are optional at import and required when used:
    - `secrets_key: SecretStr | None` (base64 of 32 bytes)
    - `public_read: bool = True`
    - `cors_origins: list[str] = []`
    - `trusted_proxy_cidrs: list[str] = []`
    - `jwt_issuer: str = "cvenom"`, `jwt_audience: str = "cvenom-api"`
    - `access_ttl_minutes: int = 15`, `refresh_ttl_days: int = 30`, `jwt_rotation_days: int = 7`
    - SMTP: `smtp_host/port/username/password/from_addr/starttls: bool = True`
    - `max_body_bytes: int = 65536`
    - The rate-limit numbers from Global Constraints.
  - Carried from Plan 2: convert EVERY secret setting to `pydantic.SecretStr | None`. The ones still plain `str` after Plan 2 are `nvd_api_key`, `vulncheck_api_token`, and `github_token`. The new Plan 3 secrets must also be `SecretStr`: `secrets_key` (so `secrets_key: SecretStr | None`, not str) and `smtp_password`. `maxmind_license_key`, `ransomware_live_api_key`, `cf_radar_token`, and `abusech_auth_key` already are. Call `.get_secret_value()` only at the point of use, and add a test that `repr(get_settings())` contains none of those values.
  - `secretbox.encrypt(plaintext: bytes) -> str` produces `"v1:<b64 nonce+ciphertext+tag>"`.
  - `secretbox.decrypt(token: str) -> bytes`. Both use AES-256-GCM with the key from `secrets_key`.
  - `class SecretsKeyMissing(Exception)`.
- [ ] **Step 1: Write the failing tests.**
```python
def test_secretbox_roundtrip_and_tamper(monkeypatch):
    import base64, os, pytest
    monkeypatch.setenv("SECRETS_KEY", base64.b64encode(os.urandom(32)).decode())
    from cvenom.config import get_settings; get_settings.cache_clear()
    from cvenom import secretbox
    tok = secretbox.encrypt(b"hook-secret")
    assert tok.startswith("v1:") and b"hook-secret" not in tok.encode()
    assert secretbox.decrypt(tok) == b"hook-secret"
    assert secretbox.encrypt(b"x") != secretbox.encrypt(b"x")            # random nonce
    bad = tok[:-4] + ("A" if tok[-4] != "A" else "B") + tok[-3:]
    with pytest.raises(Exception):
        secretbox.decrypt(bad)                                          # GCM tag check
```
  Also test that a missing or wrongly-sized key raises `SecretsKeyMissing` / `ValueError`, and that the error message never contains key material.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: security settings and AES-256-GCM secret encryption`

---

### Task 2: Auth, alert, and outbox models (migration 0003)

**Files:**
- Modify: `backend/src/cvenom/models.py`
- Create: `backend/migrations/versions/0003_auth_alerts.py`
- Test: `backend/tests/test_migrations.py`, `backend/tests/test_models.py`

**Interfaces:**
- Produces these models (all timestamps tz-aware):
  - `User`: `id`, `email` (unique, lower-cased), `password_hash`, `role` (`admin|member`), `is_active`, `created_at`.
  - `Invite`: `id`, `email`, `role`, `token_hash` (unique), `expires_at`, `used_at`, `created_by`.
  - `UserSession`: `id` (uuid), `user_id`, `refresh_hash` (unique), `prev_refresh_hash`, `user_agent`, `ip`, `created_at`, `last_used_at`, `expires_at`, `revoked_at`.
  - `SigningKey`: `kid` (pk), `private_enc` (secretbox token), `public_pem`, `created_at`, `retired_at`.
  - `AlertEvent` (outbox): `id`, `type`, `cve_id`, `source`, `payload` (JSONB), `created_at`, `processed_at`. Indexed on (`processed_at`, `created_at`).
  - `AlertRule`: `id`, `name`, `kind` (`kev_added|cvss_min|epss_min|keyword`), `threshold` (float, nullable), `keyword` (nullable), `enabled`, `created_by`, `created_at`.
  - `AlertRecipient`: `id`, `rule_id`, `channel` (`email|webhook`), `email` (nullable), `webhook_url` (nullable), `webhook_secret_enc` (nullable).
  - `AlertDelivery`: `id`, `event_id`, `rule_id`, `recipient_id`, `cve_id`, `status` (`pending|sent|failed`), `attempts`, `last_error` (truncated, secret-free), `created_at`, `sent_at`. It carries **UNIQUE(rule_id, recipient_id, cve_id)**, which is the per-CVE dedupe.
- The migration adds all of the above, and downgrade reverses it.
- [ ] **Step 1: Write the failing tests.** (a) `upgrade head` creates the tables and the unique constraint (assert via `pg_constraint`/`pg_indexes`). (b) Duplicate `(rule, recipient, cve)` raises IntegrityError. (c) `downgrade` to 0002 removes them. (d) `User.email` is unique case-insensitively: normalize to lower case on set, and test it.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: auth, alert, and outbox models`

---

### Task 3: Passwords, bootstrap admin, invites

**Files:**
- Create: `backend/src/cvenom/auth/passwords.py`, `backend/src/cvenom/auth/users.py`, `backend/src/cvenom/cli.py`
- Test: `backend/tests/auth/test_users.py`

**Interfaces:**
- Produces:
  - `hash_password(pw) -> str` and `verify_password(hash, pw) -> bool` (argon2id). The password policy is length ≥ 12 and ≤ 256, otherwise `WeakPassword`.
  - `authenticate(session, email, pw) -> User | None`. It runs constant-time verification against a module-level dummy hash when the user is unknown or inactive.
  - `create_admin(session, email, pw) -> User`. It refuses if any admin already exists, unless `force=True`.
  - `create_invite(session, admin, email, role, ttl_hours=72) -> str`. It returns the raw token once and stores only its SHA-256.
  - `accept_invite(session, token, pw) -> User`. It is single-use and checks expiry.
  - CLI: `python -m cvenom.cli create-admin --email E` reads the password from the `ADMIN_PASSWORD` env var or from stdin (never a CLI argument).
- [ ] **Step 1: Write the failing tests.**
  - Hashes are argon2id (`$argon2id$`), and verification works.
  - `authenticate` for an unknown email still calls the verifier (patch it and assert it was called once). Unknown user and wrong password return the identical `None`.
  - `create_admin` twice raises.
  - An invite token works once, then fails. It fails after expiry and after a wrong token. The DB stores no raw token.
  - The CLI rejects a password passed as an argument.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: argon2id passwords, bootstrap admin CLI, invites`

---

### Task 4: Rotating Ed25519 JWT key ring and tokens

**Files:**
- Create: `backend/src/cvenom/auth/tokens.py`
- Test: `backend/tests/auth/test_tokens.py`

**Interfaces:**
- Produces:
  - `KeyRing.current(session, now)`. It returns the active `SigningKey`, creating one if none exists or if the newest is older than `jwt_rotation_days`. The previous key is marked retired.
  - `KeyRing.verification_keys(session, now) -> dict[kid, Ed25519PublicKey]`. It covers the active key plus retired keys within `access_ttl + 1h` of retirement.
  - `issue_access(session, user, sid, now) -> str`.
  - `decode_access(session, token, now) -> AccessClaims`. It accepts ONLY `algorithms=["EdDSA"]`, requires `exp`/`iat`/`sub`/`sid`/`kid`, and verifies `iss`/`aud`. An unknown `kid` raises `InvalidToken`.
  - Refresh tokens:
    - `new_refresh() -> tuple[raw, sha256]`.
    - `rotate_refresh(session, raw, now, ua, ip) -> tuple[UserSession, new_raw]`.
    - Presenting a token equal to a session's `prev_refresh_hash` (already rotated) revokes that session and raises `TokenReuse`.
    - Revoked or expired sessions raise `InvalidToken`.
- [ ] **Step 1: Write the failing tests.**
  - The token round-trips.
  - These are all rejected: `alg=none`, `HS256` signed with the public key bytes, a wrong `aud`, a wrong `iss`, an expired token, an unknown `kid`, and a tampered payload.
  - Rotation: after `jwt_rotation_days` a new kid is issued, and an old token still verifies within the grace window but not after it.
  - Refresh: rotate works; reusing the old token raises `TokenReuse` and the session is now revoked, so even the new token fails.
  - Expired refresh tokens fail.
  - Private keys are stored encrypted, with no PEM `PRIVATE KEY` in the DB value.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: rotating Ed25519 JWT key ring and refresh-token rotation`

---

### Task 5: App factory and security middleware

**Files:**
- Create: `backend/src/cvenom/api/app.py`, `backend/src/cvenom/api/middleware.py`, `backend/src/cvenom/api/deps.py`
- Test: `backend/tests/api/test_app.py`

**Interfaces:**
- Produces:
  - `create_app(settings=None, *, redis=None, session_factory=None) -> FastAPI`.
  - Middleware:
    - Security headers on every response:
      - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` for the API.
      - `Strict-Transport-Security: max-age=63072000; includeSubDomains`.
      - `X-Content-Type-Options: nosniff`.
      - `Referrer-Policy: no-referrer`.
      - `X-Frame-Options: DENY`.
      - `Cache-Control: no-store` on authed and auth routes.
    - CORS limited to the `cors_origins` allowlist, with credentials allowed only for listed origins.
    - Bodies over `max_body_bytes` return 413, enforced on streaming input as well, not only `Content-Length`.
    - `client_ip(request)` returns the socket peer, unless the peer is in `trusted_proxy_cidrs`. In that case it takes `CF-Connecting-IP`, otherwise the right-most untrusted `X-Forwarded-For` entry.
    - A generic exception handler returns `{"error":"internal_error"}` with status 500, with no traces, and logs server-side.
  - `GET /api/health` returns `{"status":"ok","public_read":<bool>}`. The frontend uses `public_read` to decide whether to show a login gate and whether the WebSocket needs auth.
  - Deps: `get_session` (request-scoped, overridable), `current_user` (optional), `require_user`, `require_admin`, `public_or_user`. The last one allows anonymous access only when `public_read` is set and otherwise returns 401.
- [ ] **Step 1: Write the failing tests.**
  - The headers are present, with the exact CSP.
  - A disallowed CORS origin gets no ACAO header.
  - A 70 KB body returns 413, including a chunked body with no Content-Length.
  - `client_ip`: an untrusted peer that sends a spoofed `X-Forwarded-For` keeps the peer IP; a trusted peer's `CF-Connecting-IP` is used.
  - A route that raises returns the generic 500 body, and the traceback text is absent.
  - `public_read=False` makes anonymous reads return 401.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: API app factory with security middleware`

---

### Task 6: Rate limiting and public read cache

**Files:**
- Create: `backend/src/cvenom/api/ratelimit.py`, `backend/src/cvenom/api/cache.py`
- Test: `backend/tests/api/test_ratelimit.py`

**Interfaces:**
- Produces:
  - `RateLimiter(redis)`. `hit(key, limit, window_s) -> (allowed, retry_after)` is a fixed-window counter using an atomic `INCR` plus `EXPIRE` in a Lua script.
  - A FastAPI dependency factory `rate_limit(scope, limit_setting)`. It keys anonymous callers by `client_ip` and authed callers by user id, and returns 429 with `Retry-After` when exceeded.
  - The login limiter is applied per IP AND per normalized email.
  - `ResponseCache(redis)`. A decorator caches GET JSON for public routes for 30s, keyed by path plus sorted query. It applies ONLY to anonymous requests (never to authed responses) and sets `Cache-Control: public, max-age=30` on public responses.
  - Both components take an injectable fake Redis for tests.
- [ ] **Step 1: Write the failing tests.**
  - Request N+1 within the window gets 429 with `Retry-After`. The counter resets after the window (fake clock or fake Redis TTL).
  - Separate IPs have separate buckets.
  - Login is limited by email even when the IP rotates.
  - The cache serves a second anonymous call without hitting the handler (handler call count stays 1). It never caches when an `Authorization` header is present.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: Redis rate limiting and public response cache`

---

### Task 7: Auth API

**Files:**
- Create: `backend/src/cvenom/api/routes_auth.py`
- Test: `backend/tests/api/test_auth_api.py`

**Interfaces:**
- Produces:
  - `POST /api/auth/login`, body `{email, password}`. On success it returns `{access_token, token_type:"bearer", expires_in}` and sets the refresh cookie (`HttpOnly; Secure; SameSite=Strict; Path=/api/auth`). On failure it returns 401 `{"error":"invalid_credentials"}`, identical for an unknown user and a wrong password. It is rate limited.
  - `POST /api/auth/refresh`. It requires the cookie AND the `X-CVEnom-CSRF: 1` header, rotates the token, and returns a new access token. On reuse it returns 401 and the session is revoked.
  - `POST /api/auth/logout`. It revokes the current session and clears the cookie.
  - `GET /api/auth/me`.
  - `GET /api/auth/sessions` lists the caller's sessions (ua, ip, created, last_used, current flag). It never includes hashes.
  - `DELETE /api/auth/sessions/{id}` revokes one of the caller's own sessions. Another user's session returns 404.
  - `POST /api/auth/invites` (admin only) returns the invite token once.
  - `POST /api/auth/invites/accept`, body `{token, password}`.
- [ ] **Step 1: Write the failing tests.**
  - The login → me → refresh → logout flow works. The cookie attributes are asserted exactly.
  - Refresh without the CSRF header returns 403. A replayed refresh token returns 401, and that session can no longer refresh.
  - The unknown-user and wrong-password response bodies are byte-identical.
  - A member hitting the invites endpoint gets 403.
  - Session list contains no hash fields. Revoking another user's session returns 404.
  - An access token from a revoked session is rejected: `require_user` checks that the session is not revoked.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: auth API with cookie refresh, sessions, invites`

---

### Task 8: Public read API

**Files:**
- Create: `backend/src/cvenom/api/routes_read.py`, `backend/src/cvenom/api/schemas_api.py`
- Test: `backend/tests/api/test_read_api.py`

**Interfaces:**
- Produces these endpoints. All are GET, all go through `public_or_user`, and all are rate limited and cached:
  - `/api/lanes`: the four lanes. Each item has `cve_id`, `cvss`, `epss_percentile`, `kev`, `kev_added`, `kev_source`, `poc_badge`, `patch_available`, `published`, `summary`, and `recent_story_count`. Each lane is capped at 100 items.
  - `/api/cves/{cve_id}`: detail, including linked stories (title/url/source/published) and geo events referencing it. A malformed id returns 404 (validate it with the shared validator).
  - `/api/cves?q=&source=&lane=&min_cvss=&kev=&from=&to=&page=&page_size=`:
    - `q` is ≤ 200 chars, and LIKE `%`/`_`/`\` are escaped with an explicit `ESCAPE`.
    - `page_size` is ≤ 100.
    - Results are ordered by published desc, then cve_id.
    - `lane` uses `lane_views` membership.
  - `/api/velocity?cve_id=&days=`:
    - `days` must be between 1 and 30 (default 7).
    - Plan 2's `cve_velocity` does not guard `days <= 0`, so the API validates it. The value 0 returns 422.
  - `/api/geo?window_hours=`:
    - `window_hours` must be between 1 and 168. Values of 0 or 169 return 422.
    - The response includes each country's ongoing outage. Plan 2 made `observed_at` = run time for outages with no `endDate`.
    - Geo items in any response, including CVE detail, expose `kind`, `country_code`, `label`, `magnitude`, `observed_at`, and `details`. They never include `external_id` or `asn`/`ip`-level internals beyond what `details` holds. `external_id` is feed-derived and not passed through `sanitize_text` (Plan 2 security note), so the API never returns it.
  - `/api/stories/loud?limit=` (≤ 100).
  - Response models are explicit pydantic models, which act as an allowlist of fields. Text is returned as stored (entity-escaped).
- [ ] **Step 1: Write the failing tests.**
  - Shapes and the field allowlist: no internal columns.
  - `q='%'` matches a literal `%` only. A 5,000-char `q` returns 422. Non-UTF8 bytes in the query string return 422, not 500.
  - The CVE path value `../../etc` returns 404.
  - Pagination bounds hold, and the ordering is stable.
  - With `public_read=False`, anonymous requests get 401 and authed requests succeed.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: public read API for lanes, CVEs, velocity, geo, loud stories`

---

### Task 9: Transactional event outbox

**Files:**
- Modify: `backend/src/cvenom/tasks.py`, `backend/src/cvenom/pipeline.py`
- Test: `backend/tests/test_outbox.py`

**Interfaces:**
- Produces: `run_collector` persists every event returned by `ingest` as an `AlertEvent` row in the SAME transaction as the data and the seen-state. A rollback leaves no events, and a commit includes them.
- [ ] **Step 1: Write the failing tests.**
  - A successful run commits `AlertEvent` rows with the right `type`/`cve_id`/`source`/`payload`.
  - If ingest raises, nothing is committed: no events, no state change.
  - Re-running with no new events adds no rows.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: transactional alert-event outbox`

---

### Task 10: Alert rules API

**Files:**
- Create: `backend/src/cvenom/api/routes_alerts.py`, `backend/src/cvenom/alerts/rules.py`
- Test: `backend/tests/api/test_alerts_api.py`

**Interfaces:**
- Produces:
  - CRUD under `/api/alerts/rules`. Create, update, and delete require admin; list and get require any authed user.
  - Rule kinds:
    - `kev_added` (no threshold)
    - `cvss_min` (threshold in 0–10)
    - `epss_min` (percentile in 0–1)
    - `keyword` (1–100 chars, matched case-insensitively against the cve summary or affected)
  - Recipients are nested:
    - Email recipients are validated with pydantic `EmailStr`. Add the `email-validator` dependency to `pyproject.toml` in this task.
    - Webhook recipients carry `{url, secret?}`. The URL is validated with `alerts.webhook.validate_url` (Task 12, which needs a stub until then; see Ruling). The secret is encrypted with secretbox. If no secret is given, 32 random bytes are generated and returned ONCE in the create response.
    - API responses show `url` masked to scheme+host+"/…" and NEVER the secret.
- [ ] **Step 1: Write the failing tests.**
  - A member trying to create a rule gets 403.
  - An invalid threshold returns 422.
  - A webhook URL of `http://`, `https://127.0.0.1`, or `https://169.254.169.254` returns 422.
  - The secret is returned exactly once. The list and get responses contain no secret and no full URL.
  - The DB `webhook_secret_enc` value starts with `v1:`.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.** Implement `validate_url` in Task 12's module now, with full behavior. Task 12 adds pinning and sending.
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: alert rules and recipients API with masked, encrypted webhooks`

---

### Task 11: Alert dispatcher

**Files:**
- Create: `backend/src/cvenom/alerts/dispatch.py`, `backend/src/cvenom/alerts/sinks.py`
- Modify: `backend/src/cvenom/tasks.py`. Add a beat entry `alerts-dispatch` that runs every 60s with a Redis lock. Its sinks dict is populated by Task 12; until then, use an empty dict and leave deliveries pending.
- Test: `backend/tests/alerts/test_dispatch.py`

**Interfaces:**
- Produces the sink protocol, which is shared with Task 12. It lives in `alerts/sinks.py`:
  - `class SinkError(Exception)`
  - `class SinkNotConfigured(SinkError)`
  - `class Sink(Protocol)`: `def send(self, delivery: AlertDelivery, cve: Cve, rule: AlertRule, recipient: AlertRecipient) -> None`
  - `send` is synchronous. Async sinks wrap their I/O with `asyncio.run` internally. Success is a normal return; failure raises `SinkError`, and its message must be secret-free.
- Produces `dispatch_once(session_factory, now, sinks: dict[str, Sink]) -> dict`. It is synchronous and works in three stages. It takes a session *factory* because the send stage opens one short transaction per delivery.
  - **Evaluate.**
    - Selects unprocessed `AlertEvent`s with `FOR UPDATE SKIP LOCKED`, in batches of 200.
    - For each enabled rule that matches: `kev_added` matches `type == "kev_added"`. The `cvss_min`/`epss_min`/`keyword` rules are evaluated against the CVE row whenever a `kev_added` event arrives for it, since v1 events are KEV-driven.
    - Inserts an `alert_delivery` row per recipient with `ON CONFLICT (rule_id, recipient_id, cve_id) DO NOTHING`, which is the per-CVE dedupe.
    - Marks the event processed.
  - **Send.**
    - Pending deliveries whose backoff has elapsed are sent via `sinks[recipient.channel].send(delivery, cve, rule, recipient)`.
    - On success the delivery becomes `sent`.
    - On failure `attempts` increases and `last_error` is set (secret-free, ≤ 300 chars), with exponential backoff (next attempt after `2^attempts` minutes). It becomes `failed` after 6 attempts.
    - A delivery is marked `sent` only after the sink returns success.
  - **Crash safety.** The send stage runs in its own short transaction per delivery, so a crash after commit re-sends at most that one delivery.
- [ ] **Step 1: Write the failing tests.**
  - One KEV event plus a rule with 2 recipients produces 2 deliveries sent via fake sinks.
  - The same CVE arriving again from the other source produces no new deliveries (dedupe).
  - A sink failure increments attempts, a retry after the backoff succeeds, and the 6th failure marks the delivery failed.
  - A disabled rule produces nothing.
  - Two concurrent dispatchers do not double-process. Use SKIP LOCKED with two sessions, or document why that can't be tested and assert on the SQL instead.
  - Errors stored in `last_error` never contain the webhook secret.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: alert dispatcher with outbox consumption, dedupe, retries`

---

### Task 12: Email and SSRF-hardened webhook sinks

**Files:**
- Create: `backend/src/cvenom/alerts/email.py`, `backend/src/cvenom/alerts/webhook.py`
- Test: `backend/tests/alerts/test_sinks.py`

**Interfaces:**
- Produces:
  - Both sinks implement Task 11's `Sink` protocol (`send(delivery, cve, rule, recipient) -> None`, raising `SinkError`/`SinkNotConfigured`), and are registered as `{"email": EmailSink(...), "webhook": WebhookSink(...)}` in the dispatch task.
  - `EmailSink.send(...)`:
    - aiosmtplib with STARTTLS (or implicit TLS on 465), using SMTP settings. Missing SMTP config gives a clear `SinkNotConfigured`.
    - Plain-text body only. The subject is `[CVEnom] <CVE-ID> exploited in the wild` with CR/LF stripped (header-injection safe).
    - Stored text is entity-decoded exactly once.
  - `validate_url(url) -> ValidatedTarget(host, port, ips)`:
    - `https` only.
    - No userinfo (`user:pass@`).
    - Port 443 by default, or any explicit port ≥ 1.
    - Resolve all A/AAAA records via `getaddrinfo`. EVERY address must satisfy `is_global`. IPv4-mapped IPv6 addresses are unwrapped before the check, and IPv6 zone ids and IP-literal hosts that are non-global are rejected.
  - `WebhookSink.send(...)`:
    - Re-validates at send time.
    - Connects to the first validated IP through a custom httpx transport that rewrites the connection target to the IP while keeping `Host` and the TLS SNI equal to the hostname (`extensions={"sni_hostname": host}`).
    - `follow_redirects=False`, timeout 10s, response read capped at 64 KB.
    - JSON body `{event, cve_id, rule, cve:{...}, sent_at}`.
    - `X-CVEnom-Signature: t=<unix>,v1=<hmac_sha256(secret, f"{t}.{body}")>`.
    - Only a 2xx response counts as success.
- [ ] **Step 1: Write the failing tests.**
```python
import pytest
@pytest.mark.parametrize("url", [
    "http://example.com/h", "https://user:pw@example.com/h", "https://127.0.0.1/h",
    "https://[::1]/h", "https://169.254.169.254/latest", "https://10.0.0.5/h",
    "https://[::ffff:192.168.0.1]/h", "https://100.64.0.1/h", "https://0.0.0.0/h",
])
def test_validate_url_rejects_non_global(url):
    from cvenom.alerts.webhook import validate_url, UnsafeWebhookURL
    with pytest.raises(UnsafeWebhookURL):
        validate_url(url)

def test_validate_url_rejects_dns_that_resolves_private(monkeypatch):
    import socket, pytest
    from cvenom.alerts import webhook
    monkeypatch.setattr(webhook.socket, "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 443)),
                         (socket.AF_INET, 0, 0, "", ("10.1.2.3", 443))])
    with pytest.raises(webhook.UnsafeWebhookURL):
        webhook.validate_url("https://mixed.example/h")
```
  Also test:
  - DNS rebinding: a host that is public at save time and private at send time is refused at send.
  - The request goes to the pinned IP with the original Host header (assert on the captured request in a respx/mock transport).
  - Redirects are not followed.
  - The HMAC verifies with the secret.
  - The email subject strips `\r\n`, and the body is plain text with decoded entities.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: email and SSRF-hardened signed webhook sinks`

---

### Task 13: Live WebSocket notifications

**Files:**
- Create: `backend/src/cvenom/api/routes_ws.py`, `backend/src/cvenom/live.py`
- Modify: `backend/src/cvenom/tasks.py` (publish after a successful collector run)
- Test: `backend/tests/api/test_ws.py`

**Interfaces:**
- Produces:
  - `live.publish(redis, what: list[str])` publishes on channel `cvenom:live` the message `{"type":"updated","what":[...],"at":iso}`. The `what` values include `lanes` and `geo`/`stories`.
  - `run_collector` publishes after commit, best effort. A publish failure is logged and never fails the run.
  - `/api/ws/live`:
    - Accepts anonymous connections only when `public_read` is set.
    - Otherwise the client must send a first message `{"type":"auth","token":"<access JWT>"}` within 5 s. The token is validated, including the session-not-revoked check. If the message is missing, late, or invalid, the server closes with 4401.
    - **Never accept a token in the URL query.** Access logs record query strings.
    - Allows max 5 connections per `client_ip` (close 4429).
    - Relays pub/sub messages, sends a ping every 30s, and ignores client text beyond 1 KB.
- [ ] **Step 1: Write the failing tests.**
  - A published message reaches a connected test client.
  - The 6th connection from the same IP is closed with 4429.
  - With `public_read=False`:
    - No auth message within the timeout closes with 4401. Use a short timeout injected for the test.
    - An invalid token closes with 4401.
    - A valid first-message token connects and receives updates.
    - A `?token=` query parameter is ignored: the connection still requires the auth message.
  - A publish failure doesn't fail `run_collector`.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them and confirm they pass.**
- [ ] **Step 5: Commit.** `feat: live WebSocket update notifications`

---

### Task 14: Production packaging

**Files:**
- Create:
  - `backend/Dockerfile`
  - `deploy/docker-compose.prod.yml`
  - `deploy/postgres-init/01-app-role.sh`
  - `.env.example`
  - `backend/requirements.lock`
  - `docs/deploy.md`
- Test: `backend/tests/test_packaging.py`

**Interfaces:**
- Produces:
  - **Dockerfile:**
    - Multi-stage `python:3.14-slim`, which matches the dev venv (3.14). Fall back to 3.13 only if a pinned dependency has no wheel, and say so in the report.
    - Installs with `pip install --require-hashes -r requirements.lock`.
    - Runs as non-root uid 10001.
    - One image, three commands: `api` (uvicorn behind `--proxy-headers` with `--forwarded-allow-ips` from env), `worker`, and `beat`.
  - **requirements.lock:** generated with hashes (pip-tools `pip-compile --generate-hashes`, or `uv pip compile --generate-hashes`), covering all runtime dependencies.
  - **Production compose:**
    - Services `api`, `worker`, `beat`, `postgres`, `redis`, plus an optional `frontend` placeholder.
    - Postgres and Redis publish **no ports**.
    - Postgres credentials come from `${POSTGRES_PASSWORD:?}`. The init script creates a **non-superuser** `cvenom_app` role that owns the `cvenom` DB, and the app's `DATABASE_URL` uses that role.
    - Redis runs with `--requirepass ${REDIS_PASSWORD:?}`, and `REDIS_URL` includes the password.
    - Only `api` publishes, on `127.0.0.1:8000` (Cloudflare Tunnel or a reverse proxy sits in front).
    - Healthchecks, `restart: unless-stopped`.
  - **.env.example:** every setting, with secrets blank. It includes the `openssl rand -base64 32` hint for `SECRETS_KEY`.
  - **docs/deploy.md:** first-run steps (migrate, create-admin, invite users), Cloudflare notes, and key rotation.
- [ ] **Step 1: Write the failing tests.** Parse the YAML and the Dockerfile text, and assert:
  - Postgres and Redis have no `ports`.
  - `api` publishes only on `127.0.0.1`.
  - There is no literal password anywhere in the compose file (every secret is `${VAR:?}`).
  - The Dockerfile has a non-root `USER` and `--require-hashes`.
  - The lock file has `--hash=` for every requirement.
  - `.env.example` has no non-empty secret values.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Implement.** If a Docker build is feasible locally, run `docker build` once as a smoke test and report the result. Do not push images.
- [ ] **Step 4: Run them and confirm they pass**, then run the full suite.
- [ ] **Step 5: Commit.** `feat: hardened production packaging and hash-pinned lock file`

---

## Self-Review

- **Spec coverage:**
  - §5 alerts (rules, email + webhook): Tasks 10–12.
  - §7:
    - Stored XSS contract: Task 8 returns stored-escaped text; email is plain text.
    - SSRF: Task 12.
    - Supply chain: Task 14 lock + hashes.
    - Outbound manners: pre-existing.
    - Exposure / defense-in-depth: Tasks 5–6.
    - Auth (Ed25519 rotation, public read-only, multi-device sessions): Tasks 4, 7, and 8.
    - AES-256 secrets: Task 1, used in Tasks 4 and 10.
  - §8:
    - REST and WebSocket: Tasks 8 and 13.
    - Users & auth: Tasks 3, 4, and 7.
    - Packaging: Task 14.
  - Carried from Plans 1–2:
    - Outbox: Task 9.
    - Per-CVE dedupe: Task 11.
    - Webhook validation at send time: Task 12.
    - Production compose hardening, lock file, and worker fork safety: Tasks 0 and 14.
    - Lazy engine: Task 0.
- **Review Focus:** SSRF (T12), auth abuse (T4, T6, T7), data exposure (T5, T8, T10), floods/duplicates (T9, T11), query injection (T8). Each has a named test.
- **Type consistency:**
  - `secretbox` (T1) is used by T4 and T10.
  - Models (T2) are used by T3, T4, T7, T9, T10, and T11.
  - `client_ip` (T5) is used by T6 and T13.
  - `validate_url` (T12) is introduced early in T10.
- **Proportion:** code bodies appear only for security-critical tests. Everything else is signatures and rules.

## Ruling (pre-flight, plan-author)
- **Webhook URL validation dependency.** T10 needs `validate_url` before T12 exists. T10 therefore implements `alerts/webhook.validate_url` in full, and T12 adds sending and pinning in the same module. Cost if wrong: none, since T12's tests cover the same function.
