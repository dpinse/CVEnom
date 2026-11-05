# Plan 4 security review (`feat/frontend`, 8063372..542d7d2)

**Result: no High or Medium findings at confidence 8 or above.** Everything below was checked by reading the code. Where a line says "probed", the reviewer also ran scratchpad scripts: an esbuild bundle of `safeHref`, `safeNext` and `decodeEntities`, and a Python probe of uvicorn's `ProxyHeadersMiddleware` combined with the app's `client_ip`. nginx and Docker were not run, so the CSP and nginx behaviour was verified by reading `nginx.conf` and by the CSP e2e, which parses that file.

## Hardening applied after review
- **The WebSocket now defaults to same-origin.** The Origin check (`routes_ws.py`) used to run only when `CORS_ORIGINS` was set, so the default deployment accepted any Origin. That had no practical impact: the socket authenticates with a first-message bearer token, never a cookie, and a cross-site page gets only the "updated" hints anonymous clients already receive. Now, with `CORS_ORIGINS` empty, a browser Origin must match the request's Host.
  - The comparison ignores case and treats a missing port as the scheme's default.
  - A `null` or malformed Origin is rejected.
  - A missing Origin (a non-browser client) is still accepted.
  - The nginx WebSocket location now forwards `Host $http_host`, which keeps the port, so `http://localhost:8080` still passes.
- **Retry-After is capped at 3600 s.** A huge value from a misbehaving upstream could overflow the browser timer and cause a hot refetch loop.
- **401 and 403 errors no longer poll.** Only an identity change can fix those, and an identity change already resets the cache.

## Verified safe
- **Access token in memory only.**
  - The token lives only in the `createTokenStore` closure.
  - Nothing in `frontend/src` puts a token in `localStorage`, `sessionStorage`, cookies, URLs or `console.*`. `localStorage` holds only the theme, and `sessionStorage` holds only the dismissed alert's CVE id.
  - The WebSocket sends the token only in its first `auth` message, and its URL has no query string.
- **Refresh.**
  - The refresh POST carries `X-CVEnom-CSRF: 1` and `credentials: "same-origin"`.
  - It is single-flight within a tab and across tabs (Web Locks). An epoch guard drops any result that lands after a logout.
  - A guest's 401 never triggers a refresh, and the form endpoints are exempt from refresh-on-401.
- **Cross-tab messages.**
  - The `cvenom-auth` BroadcastChannel is same-origin by browser design, and every message is shape-checked.
  - A guest tab ignores `refreshed`, and a `logout` for a different user is ignored.
  - Only same-origin script, which would already be XSS, could spoof a message.
- **Grace adoption.** A peer token is adopted only if it is under 15 s old and belongs to the same user, and the server still re-checks session liveness on every request.
- **Identity-scoped cache.** Any identity change resets every query except `/health`, and reads wait for the auth bootstrap. An in-flight fetch from the old identity is cancelled by `Query.reset()` and cannot write after the reset.
- **XSS** (probed).
  - There is no `dangerouslySetInnerHTML`, `innerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, iframe or `srcdoc` in non-test `src`.
  - Feed text is rendered as React text through `<Text>`. Probing confirmed that `decodeEntities` decodes exactly once.
  - The only data-driven `href` is `ExternalLink`, which goes through `safeHref` and sets `rel="noopener noreferrer"`. `safeHref` allows http(s) only; probes confirmed it rejects `javascript:` variants (space, tab, case, NBSP, entity), `data:`, `vbscript:`, protocol-relative URLs and NULs.
  - The MapLibre globe has no popups, text layers or remote sources.
- **Redirects** (probed).
  - `safeNext` rejects `//`, `/\`, tab-split forms, `%2f`/`%5c`, `..`, whitespace and absolute URLs. Every accepted value resolves to the same origin and is used only with router navigation.
  - `?cve=` must match a strict regex.
  - `?story=` is only ever looked up in the fetched feed. When it isn't found, it is never echoed or linked.
- **Invite and reset tokens.** The token travels in the URL fragment, so it never reaches nginx or Cloudflare. It is read once, and the history entry is replaced. It is kept only in component state and the POST body, and it is protected by `no-referrer` (both a meta tag and an nginx header).
- **Data exposure.**
  - **Anonymous users.** `restricted_sources(None)` filters the ransomware.live story and geo sources in SQL before LIMIT, on loud stories and CVE detail. The source strings match exactly what the collector writes.
    - `/geo`, `/lanes`, `/velocity` and `/cves` return aggregates or counts only.
    - The WebSocket relays only allowlisted `what` values.
    - The anonymous Redis cache never stores a request that carries `Authorization`.
    - An invalid bearer token returns 401; it never falls back to anonymous.
    - A regression test checks every anonymous read path, plus a cache hit, against a seeded ransomware.live title.
  - **Members.** Rule endpoints return `recipient_count` only, based on the role in the database row. `/api/alerts/deliveries` is admin-only.
- **Backend changes on this branch.**
  - `RefreshGrace` only skips clearing the cookie on the existing grace path. It never mints a token or touches the session.
  - Migration 0005 adds a column and runs a static backfill.
  - The `kev_alerted_at` stamp uses a bound-parameter update.
  - In `routes_read`, the router-level `public_or_user` gate still runs before every endpoint.
- **nginx and proxy trust** (client-IP chain probed).
  - `set_real_ip_from` trusts only the gateway, 172.28.0.1. Probes covered a client-supplied XFF, gateway or nginx IPs injected into XFF, garbage hops and `CF-Connecting-IP`; all still resolve to the real visitor.
  - `CF-Connecting-IP` is blanked, and `TRUST_CF_CONNECTING_IP=false`.
  - XFP passes through only an exact `http` or `https` value, and only when it comes from the gateway.
  - The CSP has no `unsafe-*`, `blob:` or remote origin, and sets `frame-ancestors 'none'` and `base-uri 'none'`.
  - HSTS, nosniff, `no-referrer`, COOP/CORP, XFO DENY and Permissions-Policy are all sent with `always`, at server level only.
  - Only `/api/` and `= /api/ws/live` are proxied, and nginx normalises `..`, `//` and percent-encoding before it picks a location.
- **Containers.**
  - The frontend runs as `nginx-unprivileged`, uid 101, with `read_only`, tmpfs, `cap_drop ALL` and `no-new-privileges`.
  - The only published port is `127.0.0.1:8080`. The api, postgres and redis publish none.
  - `.dockerignore` excludes `.env*`, and the final image contains only `dist` and `nginx.conf`.

## Accepted and known
- **CSP on `/api` responses.** The SPA's CSP replaces the API's stricter `default-src 'none'` there. This is acceptable because those responses are JSON with `nosniff`. A per-URI CSP is listed as future hardening.
- **Peer-tab user switch.** If one tab switches user and `/auth/me` then fails, other tabs keep showing the old identity until their next request. This predates the branch and is very unlikely.
