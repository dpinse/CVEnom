# Plan 3 security review (`feat/api-alerts`, 17b5515..88277cb)

**Result: no High findings.** One Medium finding (an insider-persistence gap; reviewer confidence 7/10) has been fixed as hardening. Everything below was checked by reading the code. Where noted, it was also probed against the test database, fakeredis and the local resolver, with no real network access.

## Finding fixed after review
- **A deactivated admin's outstanding invite and reset tokens stayed valid.** `update_user` consumed only the reset tokens addressed *to* the deactivated user. It did not consume the ones that user had *issued*. In a probe, a rogue admin minted two tokens: a reset for another admin and an invite with admin role. After being deactivated, the rogue admin could still accept both. That gave a takeover of the other admin's account and a fresh admin account. The fix:
  - Deactivating or demoting a user consumes every unused invite and reset that user created.
  - Accepting an invite now also requires the creator to still be an active admin.
  - The invite list shows `created_by`, so pending invites can be audited.
  - Tests reproduce the probe.

## Verified safe
- **AuthZ and JWT**
  - Admin checks read the role from the database row, never the JWT claim.
  - EdDSA is pinned. The kid must be a string that exists in the database key ring, and the header kid must equal the payload kid.
  - The `iss`, `aud`, `exp`, `iat`, `sub` and `sid` claims are all required.
  - Private keys are encrypted with AES-256-GCM.
  - The rotation lock and grace window are bounded.
  - Every request re-checks that the session is live and the user is active.
- **Refresh rotation**
  - The refresh lookup takes a `FOR UPDATE` row lock by token hash.
  - Reusing any already-rotated token revokes the session. The revocation is committed before the error is raised.
  - A 10 s grace window covers two tabs racing to refresh.
- **CSRF**
  - The refresh cookie is `HttpOnly; Secure; SameSite=Strict; Path=/api/auth`.
  - The refresh endpoint also requires an `X-CVEnom-CSRF` header, which forces a CORS preflight.
  - The CORS allowlist is validated and never `*`.
  - Every other endpoint authenticates with a Bearer token only.
- **User enumeration and timing.** Every login path runs exactly one argon2 verify and returns the same 401 bytes.
- **IDOR.** Sessions, rules, recipients, users, invites and deliveries are all scoped by ownership or admin role.
- **Invites and resets**
  - Tokens are 256-bit, stored as SHA-256, single-use under a row lock, and they expire.
  - A reset can never create an account or change a role.
  - A password change or deactivation consumes the user's outstanding resets.
  - An admin cannot reset their own password.
  - The last-admin invariant uses row locks; a real two-transaction probe confirmed it.
- **SSRF.** Webhook URLs must be https with no userinfo. Every resolved IP must be global after unwrapping ipv4-mapped, 6to4, Teredo and NAT64 addresses. At send time the URL is re-validated (which defeats DNS rebinding) and the connection is pinned to the checked IP with SNI and Host set to the hostname. Redirects are not followed, env proxies are ignored, and the response read is capped. The probes covered numeric and hex IPs, `localhost`, IPv6 forms, metadata IPs, fullwidth dots and fragment tricks.
- **Secrets**
  - Webhook URLs and secrets are encrypted at rest.
  - Errors store only the exception type name or scrubbed text.
  - 422 responses never echo input.
  - `hide_parameters=True` is set on the database engine.
  - The generic 500 response leaks nothing.
- **Injection**
  - All database access goes through the ORM with bound parameters.
  - LIKE searches escape `\`, `%` and `_`.
  - CVE ids must match a strict regex.
  - A NUL byte or non-UTF-8 query string returns 422.
  - Email uses `policy=SMTP`, a single parsed recipient, and a CR/LF-stripped subject.
- **XSS.** The API returns JSON only, with `CSP default-src 'none'`, `nosniff` and `DENY`. The WebSocket relays a re-serialized allowlist.
- **Cache.** Only anonymous GET requests on four aggregate routes are cached, only when public read is on, and only 200 JSON responses without a cookie. Requests with unknown parameters bypass the cache.
- **WebSocket**
  - Authentication uses the first message, never a cookie or URL.
  - The Origin check rejects with 4403.
  - Connections are capped per IP with a heartbeat ZSET, plus a global cap.
- **Client IP.** Forwarding headers are honoured only from trusted proxies. The `X-Forwarded-For` walk goes right to left and stops at the first invalid hop.
- **Deploy**
  - Image and dependencies: dependencies are hash-pinned, including the build backend. The container runs as non-root on a read-only filesystem with `cap_drop ALL` and `no-new-privileges`.
  - Network: the API listens on loopback only, and Postgres and Redis publish no ports.
  - Credentials: the database role is not a superuser. Infrastructure passwords are blanked inside the app containers, and Redis requires a password.

## Known, accepted
- After a user is deactivated, an already-open live WebSocket stays connected until the access token expires (≤15 min). It carries only "data changed" hints. This is documented.
- There is no CI dependency scan yet. `docs/deploy.md` recommends running `pip-audit -r backend/requirements.lock`.
