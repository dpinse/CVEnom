# Plan 4 summary: React frontend & packaging

**Branch:** `feat/frontend`, stacked on `feat/api-alerts` (8063372). Nothing is merged, and `main` is untouched.

**Result:**
- All 13 tasks (0–12) are done, and each passed its own review.
- The whole-branch final review (opus) found no Critical issues and 3 Important ones. One fix wave addressed them, and its scoped re-review said "ready to merge: Yes".
- The security review found no High or Medium issues. The extra hardening it prompted is in fee07e0 (see `2026-11-05-plan4-security-review.md`).

**Tests:**
- frontend: 642 unit tests, plus 30 e2e tests (15 each on chromium and firefox);
- backend: 1116 passed;
- lint, typecheck and build are clean.

**Full decision record:** `2026-11-05-plan4-ledger.md`.

## What exists now
- **The radar:**
  - a lazy-loaded MapLibre globe, with a fallback panel and a screen-reader summary;
  - four lanes: Exploited now, Likely next, Loud now and Fresh criticals;
  - search, a situation readout, an alert bar, and a CVE/story drawer that you can share with `?cve=` and `?story=`;
  - light and dark themes, and a mobile layout down to 400px;
  - live updates over a WebSocket, which carries only "data changed" hints and authenticates in its first message, never in the URL.
- **Auth in the browser:**
  - the access token is kept only in memory;
  - the refresh cookie has a CSRF header, and refresh is single-flight across tabs (Web Locks plus BroadcastChannel);
  - logging out in one tab logs out the others;
  - the data cache is wiped whenever the signed-in person changes.
- **Account and admin pages:**
  - sign-in, change password, and your own sessions with revoke;
  - invite and reset links carry their token after the `#`, so it never reaches nginx or Cloudflare logs;
  - admins manage users, invites, alert rules (recipients and webhook secrets are shown once, then masked), deliveries and test-send.
- **Public vs signed-in:**
  - anonymous visitors get the read-only radar;
  - ransomware.live appears to them only as per-country counts, filtered in SQL. Individual victim records are signed-in only, and the UI credits ransomware.live;
  - `PUBLIC_READ=false` puts everything behind the login.
- **Packaging:**
  - an unprivileged, read-only nginx container is the **only** published port, `127.0.0.1:8080`. The api, Postgres and Redis have no host ports;
  - a strict CSP (no `unsafe-*`) plus HSTS, nosniff, `no-referrer`, COOP/CORP and frame-deny;
  - the real visitor IP is resolved through cloudflared → gateway → nginx → api, and can't be spoofed;
  - an e2e test checks the CSP using headers parsed from `nginx.conf` itself.
- **Backend changes on this branch:**
  - a CISA listing alerts only if no KEV alert was ever sent (`kev_alerted_at`, migration 0005);
  - rule recipients and deliveries are admin-only;
  - ransomware.live is polled hourly (fair use);
  - the refresh-race cookie fix;
  - a same-origin WebSocket default.

## How to run it
- Production style: follow `docs/deploy.md`. In short:
  1. Copy `.env.example` to `.env` and fill in the secrets.
  2. Run `docker compose -f deploy/docker-compose.prod.yml --env-file .env up -d --build`.
  3. Create the first admin with the `create-admin` one-off.
  4. Point cloudflared at `http://127.0.0.1:8080`.
- HTTPS is required in front of nginx; `http://localhost` works for local evaluation.

## Decisions that need you
1. **Keyed collectors stay off.** ransomware.live (Pro), Cloudflare Radar and abuse.ch run only once their keys are in `.env`. The globe also needs a free MaxMind GeoLite2 key to place events.
2. **Confirm the real-IP chain after the first deploy.** Check that the api access log shows visitor IPs, not `172.28.0.x` (see `deploy.md`). It was verified by reading the code and by a probe, but not on a live stack.
3. **Deferred hardening and cleanup** (listed in the ledger):
   - a stricter per-URI CSP on `/api` responses;
   - Prettier formatting;
   - a few stronger auth regression tests;
   - a minimum-count threshold for very small ransomware country counts.

## Deferred / known
- If a peer tab switches user and `/auth/me` then fails, other tabs keep the old identity until their next request. This predates the branch and is unlikely.
- Old-style `/invite/<token>` links no longer resolve. None were ever issued.
- See `docs/ROADMAP.md` for parked features (breaches and watchlists, Telegram, SMS and more).
