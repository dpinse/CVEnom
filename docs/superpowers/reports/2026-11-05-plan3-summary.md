# Plan 3 summary: API, auth & alerts

**Branch:** `feat/api-alerts`, stacked on `feat/geo-news` (17b5515) and pushed to GitHub. Nothing is merged, and `main` is untouched.

**Result:**
- All 16 tasks (0–15) are done and each passed its own review. Most needed one fix round, usually for security hardening that the reviewers proved with live probes.
- The whole-branch final review (opus) found no Critical issues and 5 Important ones. One fix wave addressed them, and its scoped re-review was clean. Task 15 was added as a follow-up because of that review.
- The security review found no High issues. Its one Medium finding is fixed (see `2026-11-05-plan3-security-review.md`).

**Tests:** 1093 passed, 0 warnings (Plan 2 ended at 497).

**Full decision record:** `2026-11-05-plan3-ledger.md` lists every ruling and what it costs if it is wrong.

## What exists now
- **API.** A FastAPI app factory with pure-ASGI security middleware:
  - headers on every response, a body limit that also covers chunked requests, generic 500s, and 422s that never echo input;
  - an allowlisted CORS policy; API docs are off by default;
  - trusted-proxy client IP resolution.
- **Public read API.** Lanes, CVE search and detail, velocity, geo, and loud stories, with a field allowlist, escaped LIKE patterns, and NUL and non-UTF-8 rejection. Anonymous responses are cached for 30 s.
- **Rate limits** on every route, enforced before authentication, including for invalid tokens:
  - 60/min anonymous, 300/min authed;
  - login: 10 per 15 min per IP and per email;
  - login and refresh fail closed if Redis is down.
- **Authentication:**
  - argon2id passwords with constant-time login;
  - EdDSA JWTs that expire after 15 min, signed by a weekly-rotating Ed25519 key ring. Private keys are AES-256-GCM encrypted, and the ring recovers by itself if `SECRETS_KEY` changes;
  - refresh tokens in a `SameSite=Strict` cookie plus a CSRF header. They rotate on every use, and reusing any old token revokes the whole session;
  - multi-device session management, invites, password change, admin password reset, and user management (deactivate, roles, revoke sessions), with a last-admin guard.
- **Alerts.** A transactional outbox feeds a dispatcher:
  - deliveries are deduplicated per CVE, retried with exponential backoff, and expire after 7 days;
  - it never sends the same alert twice;
  - an email sink (plain text) and a webhook sink. Webhooks are HMAC-signed, re-validated against SSRF at send time, pinned to the resolved IP, and compatible with Discord and Slack;
  - webhook URLs and secrets are encrypted at rest;
  - admins can see delivery status and send a test alert.
- **Live WebSocket.** It sends "data changed" hints only. Auth is the first message the client sends (never a URL parameter), the Origin header is checked, and connections are capped per IP and globally.
- **Packaging.**
  - A non-root, read-only Docker image built from a hash-pinned lock file.
  - A production compose file with no exposed database or Redis ports, a non-superuser DB role, and Redis behind a password.
  - `docs/deploy.md`, which covers the Cloudflare Tunnel topology.

## Decisions that need you
1. **Alert rules are triggered by KEV listings, and an unknown score counts as a match.** Rules fire when a CVE enters KEV. A `cvss_min` or `epss_min` rule also fires if that score isn't known yet, so a freshly exploited, still-unscored CVE alerts instead of being silently dropped. The alternative is to skip those, or to re-check once scores arrive.
2. **Velocity is global.** `/api/velocity` shows CVEs published per day across everything, not per CVE. That's what the data supports.
3. **Telegram webhooks aren't supported natively.** The webhook body works with Discord, Slack, and generic receivers. Telegram's bot API needs a different payload shape.
4. **Members can see rule recipient emails.** Webhook URLs are always masked. This fits a small team; ask if you want recipients visible to admins only.
5. **If Redis is down, nobody can log in.** This is deliberate: login rate limits must not silently disappear, so they fail closed.
6. **Rotating `SECRETS_KEY` is partly manual.** JWT keys recover by themselves, but every webhook recipient has to be re-added.
7. **Carried from Plans 1 and 2:**
   - the CISA-after-VulnCheck alert rule;
   - a ransomware.live Pro key (and a check of its field names);
   - optional Cloudflare Radar and abuse.ch tokens;
   - the Firefox globe issue, which Plan 4 tests explicitly.

## Deferred (see the ledger)
- **Minor test and style items:** listed in the ledger. Ruff isn't configured.
- **Not built yet:**
  - CI or pip-audit dependency scanning;
  - re-running alert evaluation when enrichment data arrives;
  - an ACCESS_LOG toggle.
- **Known limitations:**
  - an open WebSocket stays connected for up to 15 minutes after its user is deactivated;
  - test-send skips the remaining recipients once its deadline passes, but a send already in progress can finish after the 504.
