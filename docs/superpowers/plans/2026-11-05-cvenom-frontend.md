# CVEnom Frontend: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the CVEnom dashboard, the design the user approved in the mockup. The layout is:
- a full-width 3D MapLibre globe on top, with country outage shading and threat hotspots;
- a CVE-velocity readout under the globe;
- four radar lanes below (Exploited now / Likely next / Loud now / Fresh criticals);
- a drill-down drawer.

The app also includes search, login/sessions, admin alert rules and invites, dark and light themes, and hardened nginx packaging.

**Architecture:**
- **Stack:** Vite + React + TypeScript in `frontend/`.
- **Server data:** TanStack Query, with a WebSocket hook that invalidates queries when the server says data changed.
- **Auth:** the access token lives in memory. Refresh uses the httpOnly cookie plus the `X-CVEnom-CSRF: 1` header (Plan 3 contract).
- **Globe:** MapLibre GL in globe projection. It draws country polygons from a bundled Natural Earth TopoJSON, with **no third-party tile, glyph, or font requests**.
- **Production:** an unprivileged nginx serves the SPA with a strict CSP and reverse-proxies `/api` and `/api/ws` to the API. Same origin means no CORS, and SameSite=Strict cookies work.

**Tech Stack:**
- Node 26 (`.nvmrc` = `26`, `engines.node >=22`), Vite, React, TypeScript (strict), React Router, TanStack Query, MapLibre GL (CSP build), topojson-client.
- Fonts: `@fontsource/ibm-plex-sans`, `/ibm-plex-sans-condensed`, `/ibm-plex-mono`.
- Tests: Vitest + React Testing Library + MSW, plus Playwright (chromium + firefox) for e2e smoke.

**Spec:** `docs/superpowers/specs/2026-11-04-cvenom-vuln-threat-radar-design.md` (§1 product, §5 lanes, §7 XSS contract, §8 frontend). The API contract is Plan 3's routes under `/api`.

## Global Constraints

- Monorepo: frontend code lives in `frontend/`. Never touch `backend/` except via the API contract. The one exception is Task 12, which may edit `backend/tests/test_packaging.py`, `deploy/`, `docs/deploy.md`, and `.env.example`. That covers the nginx front door and its proxy-trust defaults.
- Design reference: the approved mockup is `docs/superpowers/design/cvenom-radar-mockup.html`. Open it, and match its layout, palette, type, and row treatment. Its globe rendering is NOT a reference (it failed in Firefox). Task 4 builds the globe fresh with MapLibre.
- Globe geometry: take `countries-110m.json` from the pinned npm package `world-atlas` and copy it into `src/assets/` at build time, or import it. Do not hand-edit it. Run `npm ci`, `npm test`, `npm run build`, and `npm run e2e` from `frontend/`. Use exact dependency versions (`save-exact`) and commit `package-lock.json`.
- Never run `git push`, `git fetch`, or `git pull`. Commit locally only, and never stage `.superpowers/`.
- **Stored-text contract.** API text fields (`summary`, `title`, `label`, `affected`, story `source`) arrive HTML-entity-escaped.
  - Render them ONLY through `<Text>` / `decodeEntities()` into React text nodes. That is one decode, and React escapes on output.
  - **`dangerouslySetInnerHTML` is forbidden.** ESLint enforces `react/no-danger: error`, and a test asserts no source file contains it.
- **Links.** A story URL is rendered as `<a>` only if `safeHref()` returns it (http/https only, parsed with `new URL`). Every external link uses `target="_blank" rel="noopener noreferrer"`. Anything else is plain text.
- **No third-party runtime requests.** Fonts are self-hosted via @fontsource, and globe geometry is bundled. The only network calls go to same-origin `/api` and `/api/ws`.
- **Design (approved mockup).**
  - Layout: globe full width on top, velocity readout beneath it, four lanes in a row (2 columns under 1040px, 1 under 580px), and a right drawer.
  - Color is reserved for signal. The chrome is cool graphite. Hue appears only in the severity ramp (crit/high/med/low) and the in-the-wild red.
  - Interaction uses a muted "scope" blue, used sparingly.
  - Type: IBM Plex Sans Condensed for headers, Plex Sans for body, Plex Mono ONLY for IDs, scores, and coordinates.
  - Lane items are hairline rows with a severity edge, not floating cards.
  - The Situation readout lives in the command bar.
  - Theme is dark by default, plus a light theme, both defined as CSS tokens.
- **Accessibility.**
  - Keyboard reachable throughout, with visible focus.
  - The drawer is a dialog with a focus trap, closes on Esc, and returns focus.
  - `prefers-reduced-motion` stops globe auto-rotate and pulses.
  - Text contrast meets WCAG AA in both themes.
- **Performance.** The initial JS bundle (excluding MapLibre, which is lazy-loaded with the globe) is ≤ 250 KB gzip. Lanes render ≤ 100 rows each.

## Review Focus

- **XSS through API data.** Covers script or HTML in summaries and titles, entity-encoded tags (`&lt;script&gt;` must display literally, not execute), `javascript:` / `data:` story URLs, and HTML in geo labels. Tested in Tasks 1, 6, and 7.
- **Token handling.** The access token is never stored in localStorage or sessionStorage, and never appears in any URL, including WebSocket URLs. The WebSocket authenticates with a first message `{"type":"auth","token":...}` when `public_read=False`. A 401 triggers exactly one refresh attempt, then logout. Concurrent 401s share a single refresh. That refresh is single-flight **across tabs**: wrap it in the Web Locks API (`navigator.locks.request("cvenom-refresh", ...)`), and fall back to BroadcastChannel where Web Locks is unavailable. Two tabs must never present the same refresh token, because the backend revokes the session on reuse, with only a 10s grace window. Tested in Task 1.
- **Degraded data.** The UI must survive empty lanes, a null `cvss`/`epss`/`published`, unknown country codes, an empty geo summary, an API error or 429, and a WebSocket disconnect, without crashing or blanking. Tested in Tasks 2, 4, 6, and 11.
- **Globe rendering in Firefox.** The user's browser is Firefox. A Playwright firefox smoke test proves the canvas renders with non-blank pixels. Tested in Task 11.
- **CSP compliance.** The production build runs under the nginx CSP with no violations: MapLibre CSP build, worker from self, no inline scripts or styles. Tested in Task 12.

---

### Task 0: Scaffold and design tokens

**Files:** Create `frontend/` (Vite React-TS), `frontend/.nvmrc`, `frontend/eslint.config.js`, `frontend/src/styles/tokens.css`, `frontend/src/styles/base.css`, `frontend/vitest.config.ts`, `frontend/src/test/setup.ts`.

**Interfaces:**
- Produces:
  - npm scripts `dev`, `build`, `preview`, `test`, `lint`, `typecheck`, `e2e`.
  - TS `strict: true`.
  - ESLint (typescript-eslint + react + react-hooks + jsx-a11y) with `react/no-danger: error` and `no-restricted-syntax` banning `innerHTML` assignments.
  - `tokens.css` (dark-first, light override), using the mockup's palette:
    - graphite chrome
    - `--sev-crit` / `--sev-high` / `--sev-med` / `--sev-low`
    - `--live`
    - `--scope`
    - geo tokens `--ocean` / `--land` / `--border-geo`
    - font tokens using the self-hosted Plex families
  - Theme switching via `data-theme` on `<html>`, with `prefers-color-scheme` as the default.
  - `vite.config.ts` dev proxy: `server.proxy = {"/api": {target: "http://127.0.0.1:8000", ws: true}}`, so local dev stays same-origin, as in production.
- [ ] **Step 1: Write the failing tests.**
  - `npm run lint` fails on a fixture file using `dangerouslySetInnerHTML`. Implement this as a Vitest test that runs ESLint's Node API on a temporary snippet and asserts the error.
  - A test asserts `tokens.css` defines every token name the components will use. Keep a list in the test.
  - `.nvmrc` is `26`.
  - `package.json` `engines.node` is `>=22`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** Pin dependency versions to releases at least 2 weeks old.
- [ ] **Step 4: Run the tests and confirm they pass.** Also confirm `npm run build`, `lint`, and `typecheck` are clean.
- [ ] **Step 5: Commit.** `feat(frontend): scaffold Vite React app with design tokens and lint guards`

---

### Task 1: API client, auth store, and safe-text utilities

**Files:** Create `frontend/src/lib/api.ts`, `frontend/src/lib/auth.ts`, `frontend/src/lib/text.tsx`, `frontend/src/lib/types.ts`. Tests: `frontend/src/lib/*.test.ts(x)`.

**Interfaces:**
- Produces:
  - `decodeEntities(s: string): string`. Decodes `&amp; &lt; &gt; &quot; &#39; &#x27; &#NNN; &#xHH;` exactly once. Anything else is left as-is. It never uses the DOM.
  - `<Text value={s} />`, which renders `decodeEntities(s)` as a text node.
  - `safeHref(u: string): string | null`. Returns the URL only for `http:`/`https:`, otherwise null.
  - `api<T>(path, init?)`:
    - Base `/api`, JSON, `credentials: "same-origin"`.
    - Adds `Authorization: Bearer <token>` when an in-memory token exists.
    - On 401: one refresh (`POST /api/auth/refresh` with `X-CVEnom-CSRF: 1`), then retry once. If the refresh fails, clear auth and throw `AuthError`. Concurrent 401s share one in-flight refresh promise.
    - **Exempt from refresh-on-401:** `/api/auth/login`, `/api/auth/password` (a wrong current password returns 401 `invalid_credentials`), `/api/auth/refresh` itself, and `/api/auth/invites/accept`. These routes surface the error to the form and never log the user out.
    - On 429: throw `RateLimited(retryAfter)`.
    - Other errors: `ApiError(status, code)`.
  - `auth` store: `token` (memory only), `user`, `login(email, pw)`, `logout()`, `subscribe`.
  - `types.ts`: TS types mirroring Plan 3's response models. Derive them from the actual backend code, `backend/src/cvenom/api/schemas_api.py` plus the route modules (`routes_read.py`, `routes_auth.py`, `routes_alerts.py`, `routes_ws.py`). Do not guess. The errors are flat `{"error": "<code>"}`.
- [ ] **Step 1: Write the failing tests.**
```ts
import { decodeEntities, safeHref } from "./text";
test("decodes once, never twice", () => {
  expect(decodeEntities("5 &lt; 6 &amp;&amp; x")).toBe("5 < 6 && x");
  expect(decodeEntities("&amp;lt;script&amp;gt;")).toBe("&lt;script&gt;");
});
test("entity-encoded tags render literally, not as elements", () => {
  const { container } = render(<Text value="&lt;img src=x onerror=alert(1)&gt;" />);
  expect(container.querySelector("img")).toBeNull();
  expect(container.textContent).toBe("<img src=x onerror=alert(1)>");
});
test("safeHref allows only http(s)", () => {
  expect(safeHref("https://x.org/a")).toBe("https://x.org/a");
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "JaVaScRiPt:x", "//evil", "", "ftp://x"])
    expect(safeHref(bad)).toBeNull();
});
```
  Add MSW-backed tests for the `api()` client:
  - 401 → refresh → retry succeeds.
  - Refresh fails → `AuthError` and the store is cleared.
  - Two concurrent 401s → exactly one refresh call.
  - A 401 from `/api/auth/password` does NOT trigger a refresh or a logout.
  - The refresh request carries `X-CVEnom-CSRF: 1`.
  - The token never appears in `localStorage` or `sessionStorage`.
  - 429 → `RateLimited` with `retryAfter`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): API client with single-flight refresh and safe text/link utilities`

---

### Task 2: Data hooks and live updates

**Files:** Create `frontend/src/lib/queries.ts`, `frontend/src/lib/live.ts`. Test: `frontend/src/lib/queries.test.tsx`.

**Interfaces:**
- Produces:
  - Query hooks: `useLanes()`, `useVelocity()`, `useGeo(windowHours=24)`, `useLoudStories()`, `useCve(id)`, `useCveSearch(params)`.
  - Defaults: `staleTime` 30s, `retry` 2 except on `AuthError`/`RateLimited`.
  - `useLiveUpdates()`:
    - Opens `/api/ws/live` (`wss` when the page is https). When the server reports `public_read=false` (via `GET /api/health`, which returns `{"status":"ok","public_read":bool}`) and the user is authed, the hook sends `{"type":"auth","token":<access>}` as the first message after the socket opens. It never puts the token in the URL. A 4401 close triggers one token refresh and then a reconnect. All other reconnects use exponential backoff with full jitter: base 1 s, cap 60 s, and the backoff resets after 60 s connected. A 4429 or 4403 close waits at least 60 s before retrying. On every `{"type":"updated"}` message, invalidate the matching queries. Ignore `{"type":"ping"}`.
    - On `{"type":"updated","what":[...]}`, invalidates the matching queries (`lanes` → lanes + loud; `geo` → geo; `stories` → loud).
    - Reconnects with jittered exponential backoff (max 60s) and stops when unmounted.
    - Exposes `status: "live" | "reconnecting" | "offline"`.
- [ ] **Step 1: Write the failing tests.** Use MSW plus a mock WebSocket class.
  - An `updated: ["lanes"]` message refetches lanes but not velocity.
  - A disconnect leads to reconnect with backoff (fake timers).
  - An unmount closes the socket and schedules no reconnect.
  - A 429 on lanes surfaces `RateLimited`, and the hook does not hammer the API with retries.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): query hooks and live WebSocket invalidation`

---

### Task 3: App shell, command bar, routing

**Files:** Create `frontend/src/App.tsx`, `frontend/src/components/CommandBar.tsx`, `frontend/src/components/AlertBar.tsx`, `frontend/src/routes.tsx`, `frontend/src/main.tsx`. Test: `frontend/src/components/CommandBar.test.tsx`.

**Interfaces:**
- Produces:
  - Routes:
    - `/` dashboard
    - `/search`
    - `/login`
    - `/invite/:token`
    - `/account/sessions`
    - `/account/password`
    - `/admin/alerts`
    - `/admin/invites`
    - `/admin/users`
    - `/reset/:token`, which reuses the AcceptInvite page in reset mode
  - The admin routes are guarded: a non-admin is redirected, and a guest is sent to `/login`.
  - `CommandBar`:
    - Wordmark "CVEnom" with the radar mark.
    - **Situation readout:** a 4-segment gauge plus a level derived from the Exploited lane. Levels: `Calm` (0), `Elevated` (1–2), `High` (3–5), `Severe` (≥ 6 OR any KEV added in the last 24h). Severe uses the `--live` color.
    - Live status dot from `useLiveUpdates().status`, plus a "last updated" time.
    - Theme toggle, persisted in localStorage inside try/catch.
    - User menu: login, or the user's email, sessions, admin links (if admin), and logout.
  - `AlertBar`: shows the most recent `kev_added` CVE from the last 24h, taken from the lanes' `kev_added` dates. It links to the drawer and can be dismissed for this session.
- [ ] **Step 1: Write the failing tests.**
  - The Situation level is computed correctly for 0, 2, 5, and 6 exploited items, and for a KEV added 2h ago, which is Severe.
  - The theme toggle flips `data-theme`.
  - The guard redirects a member away from `/admin/alerts`.
  - The user menu shows admin links only for admins.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): app shell, command bar with Situation readout, routing`

---

### Task 4: Globe centerpiece

**Files:** Create `frontend/src/components/Globe.tsx` (lazy-loaded), `frontend/src/components/globeData.ts`, and asset `frontend/src/assets/countries-110m.json` (world-atlas TopoJSON, bundled). Test: `frontend/src/components/globeData.test.ts`.

**Interfaces:**
- Produces:
  - `globeData.ts`:
    - `toCountryShading(geoSummary)` returns a `Map<iso2, level 0–3>`. Outage magnitude is bucketed into levels.
    - `toHotspots(geoSummary)` returns GeoJSON Point features at country centroids, with `kind` and `magnitude`. Centroids are computed once from the bundled polygons. Unknown or NULL countries are skipped.
    - `iso2FromFeature(f)` maps world-atlas numeric ids to ISO-2 using a bundled table.
  - `<Globe>`:
    - MapLibre with `projection: {type: "globe"}`.
    - The style has a background (ocean token), a countries fill (land token, or the severity tint by shading level via a `match` expression), a hairline border line layer, and a hotspots circle layer colored by kind (`scan` → live red, `outage` → sev-high, `victim`/`c2`/`bgp` → scope/med).
    - **No `glyphs` and no remote sources.**
    - Auto-rotates unless `prefers-reduced-motion`, pausing on interaction. Drag to rotate.
    - `flyTo(country)` is exposed for drawer selection.
    - Overlays a legend and a title.
    - Shows a small attribution line: "IP geolocation by DB-IP.com", linked to https://db-ip.com, with `rel="noopener noreferrer"`. This is required by DB-IP Lite's CC-BY 4.0 license, carried from Plan 2. The line is visible whenever geo hotspots render.
    - Re-reads token colors on theme change.
    - Uses the MapLibre CSP build with the worker URL served from self.
- [ ] **Step 1: Write the failing tests.**
  - Shading buckets are correct.
  - Hotspots skip NULL and unknown countries.
  - Numeric → ISO-2 mapping works for 840→US, 528→NL, 392→JP.
  - Centroids fall inside their country's bbox.
  - Rendering `<Globe>` with a mocked maplibre module adds the expected layers and sources, with no remote URLs (assert the style JSON has no `http` strings). The DB-IP attribution link is in the DOM.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): MapLibre globe with outage shading and threat hotspots`

---

### Task 5: Velocity readout

**Files:** Create `frontend/src/components/Velocity.tsx`. Test: `Velocity.test.tsx`.

**Interfaces:**
- Produces: `<Velocity data={useVelocity()} />`.
  - Shows the label "CVEs published / day" with the current count in the display font.
  - Inline SVG sparkline over the series: area fill plus a line, with the endpoint emphasized. Colors come from tokens.
  - A trend chip: "rising" (severity) or "steady" (muted).
  - Empty and error states.
- [ ] **Step 1: Write the failing tests.**
  - With N points, the path has N points and the endpoint circle sits at the last point.
  - An all-zero series renders a flat line with no NaN in the path.
  - The rising chip appears only when `rising`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): CVE velocity readout`

---

### Task 6: The four lanes

**Files:** Create `frontend/src/components/Lanes.tsx`, `frontend/src/components/LaneRow.tsx`. Test: `Lanes.test.tsx`.

**Interfaces:**
- Produces:
  - `<Lanes>` lays out Exploited now / Likely next / Loud now / Fresh criticals with a tick color, title, subtitle, and count.
  - Rows are hairlines with a severity edge.
  - CVE rows show:
    - the mono ID;
    - an "in the wild" strobe when `kev`;
    - the decoded summary, clamped to 2 lines;
    - chips: CVSS (severity-colored), EPSS percentile, KEV + date, PoC, "no patch" when `patch_available === false`, and "news ×N".
  - Loud now additionally merges `useLoudStories()`. CVE-less stories appear as story rows: decoded title, source · time, and either a "no CVE" chip or linked CVE chips. Stories are ordered by recency after CVE rows.
  - Rows are buttons that open the drawer.
  - Each lane has an empty state ("Nothing exploited right now" and similar), and each lane scrolls independently.
- [ ] **Step 1: Write the failing tests.**
  - Fixtures cover the quiet-foil case: it appears only in Fresh, with no "in the wild" marker.
  - A KEV CVE shows the strobe in every lane it appears in.
  - Null `cvss`/`epss` omit their chips without crashing.
  - A summary `&lt;script&gt;alert(1)&lt;/script&gt;` renders as literal text with no `<script>` element.
  - CVE-less stories appear in Loud now.
  - Clicking a row calls `onSelect` with the id.
  - Empty states render.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): four radar lanes with signal-colored rows`

---

### Task 7: Drill-down drawer

**Files:** Create `frontend/src/components/Drawer.tsx`, `frontend/src/components/CveDetail.tsx`, `frontend/src/components/StoryDetail.tsx`. Test: `Drawer.test.tsx`.

**Interfaces:**
- Produces:
  - A `<Drawer>` dialog: `role="dialog" aria-modal`, focus trapped, closes on Esc and on scrim click, and returns focus to the opener.
  - `CveDetail` (`useCve`):
    - CVSS and EPSS meters.
    - Chips: KEV (source + date), PoC, patch status.
    - Decoded summary.
    - The `affected` list.
    - Linked stories as safe links (`safeHref`, `rel="noopener noreferrer"`, `target="_blank"`); an unsafe URL shows plain text.
    - Geo events.
    - When the CVE has geo, it calls `globe.flyTo`.
  - `StoryDetail` covers CVE-less items.
- [ ] **Step 1: Write the failing tests.**
  - Focus moves into the dialog and Tab cycles within it.
  - Esc closes and focus returns to the row.
  - A story whose url is `javascript:alert(1)` renders with no `<a>` element.
  - Every external link has `rel="noopener noreferrer"`.
  - Loading and error states render.
  - Meter widths are clamped to 0–100%.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): accessible drill-down drawer`

---

### Task 8: Search page

**Files:** Create `frontend/src/pages/Search.tsx`. Test: `Search.test.tsx`.

**Interfaces:**
- Produces:
  - Filters: `q` (≤ 200 chars, enforced client-side as well), lane, source, min CVSS, KEV-only, date range.
  - Results table with mono IDs and severity chips. Prev/next pagination with a page size of 50.
  - URL query params mirror the filter state, so links can be shared.
  - Debounced input (300ms). Rows open the drawer.
- [ ] **Step 1: Write the failing tests.**
  - Typing debounces and fires a single request.
  - Params round-trip through the URL.
  - A 201-character `q` is truncated or blocked.
  - Pagination requests page=2.
  - The empty state renders.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): CVE search with shareable filters`

---

### Task 9: Login, invites, and sessions

**Files:** Create `frontend/src/pages/Login.tsx`, `frontend/src/pages/AcceptInvite.tsx`, `frontend/src/pages/Sessions.tsx`. Tests alongside.

**Interfaces:**
- Produces:
  - **Login:** an email + password form. A failed login shows the generic message "Email or password is incorrect" (never which one was wrong). Shows the 429 message with its retry time. On success, navigates to the route the user came from.
  - **AcceptInvite:** the token comes from the route. Requires a password of at least 12 characters with a confirmation field. `POST /api/auth/invites/accept` returns 201 `{id,email,role}` and does NOT log the user in. On success, the page calls `auth.login(email, password)` using the returned email. `400 invalid_invite` shows "This invite is invalid or expired". `422 weak_password` shows the policy message.
  - **Sessions:** lists sessions (device/UA, IP, last used, and "this device"). Each row has a revoke button; revoking the current session logs the user out.
- [ ] **Step 1: Write the failing tests.**
  - Unknown-user and wrong-password errors show the identical message.
  - The 429 message includes the retry time.
  - A short password is blocked on the client.
  - Revoking the current session triggers logout.
  - Password fields use `autocomplete` values `current-password` / `new-password`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): login, invite acceptance, and session management`

---

### Task 10: Admin: alert rules and invites

**Files:** Create `frontend/src/pages/AdminAlerts.tsx`, `frontend/src/pages/AdminInvites.tsx`. Tests alongside.

**Interfaces:**
- Produces:
  - **Rules:** list, create, edit, and delete. Rule kinds are `kev_added`, `cvss_min` (0–10), `epss_min` (0–1), and `keyword`. The API contract:
    - `PATCH` may change only name, threshold, keyword, and enabled. `kind` is immutable, so the edit form shows it read-only.
    - The API rejects extra fields with 422.
  - **Recipients:** email addresses or webhooks (https only, validated on the client too).
    - Add a recipient with `POST /rules/{id}/recipients` and remove one with `DELETE /rules/{id}/recipients/{rid}`. There is no in-place edit: to change a recipient, remove it and add a new one.
    - The server's `422 unsafe_webhook_url` is shown as "That webhook address isn't allowed (must be a public https endpoint)".
  - **Webhook secret:** shown **once** right after creation, in a copy-to-clipboard panel with a "won't be shown again" warning. It is never stored in client state after the panel is dismissed.
  - **Webhook URLs:** shown masked, exactly as the API returns them.
  - **Invites:** create an invite (email + role), then show the invite link once with a copy button. List pending invites and revoke them (`GET` / `DELETE /api/auth/invites`).
  - **Users (`/admin/users`, from Plan 3 Task 15):**
    - List users with role, active state and session count.
    - Deactivate or reactivate a user, change their role, and revoke all of their sessions. Each of these needs an in-page confirmation.
    - Reset a user's password. This shows the reset link once.
    - Handle these API errors with clear messages: `409 cannot_modify_self` and `409 last_admin`.
  - **Deliveries (on `/admin/alerts`):**
    - A delivery-status table (`GET /api/alerts/deliveries`) with status chips and `last_error`.
    - A "Send test" button per rule (`POST /rules/{id}/test`) that shows a result for each recipient.
  - **Account:** a change-password form at `/account/password` (`POST /api/auth/password`). It needs the current password plus a confirmed new password, and must tell the user that their other devices will be signed out.
- [ ] **Step 1: Write the failing tests.**
  - The secret panel appears once, and after dismissal the secret is not in the DOM.
  - An `http://` webhook is blocked on the client.
  - An out-of-range threshold is blocked.
  - Delete asks for confirmation inside the page (no `window.confirm`).
  - Non-admins never render these pages (guard).
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): admin alert rules and invites`

---

### Task 11: Dashboard composition, responsive polish, e2e smoke

**Files:** Create `frontend/src/pages/Dashboard.tsx`, `frontend/playwright.config.ts`, `frontend/e2e/smoke.spec.ts`, `frontend/e2e/fixtures/*.json`.

**Interfaces:**
- Produces:
  - **Dashboard:** AlertBar, then the Globe (full width), then Velocity, then Lanes, with the Drawer on top.
  - **Breakpoints:** lanes show 4 columns, then 2 below 1040px, then 1 below 580px. Side gutter ≥ 16px with safe-area insets. No horizontal page scroll.
  - **Playwright:**
    - Runs on chromium and firefox against `vite preview`.
    - Uses `page.route('/api/**')` with the JSON fixtures, and a stubbed WS.
    - Smoke checks:
      - The dashboard renders all four lanes.
      - The globe canvas exists, and a pixel sample from the canvas center is not uniform background. This proves WebGL actually drew, which is the user's Firefox concern.
      - Clicking a row opens the drawer, and Esc closes it.
      - Zero console errors.
      - At 400px width there is no horizontal scroll.
- [ ] **Step 1: Write the failing tests** (the e2e specs).
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** If the Playwright firefox browser download is unavailable, run chromium and report firefox as not run. Do NOT skip it silently.
- [ ] **Step 4: Run the tests and confirm they pass.** Run `npm run e2e`, plus unit tests, lint, and typecheck.
- [ ] **Step 5: Commit.** `feat(frontend): dashboard composition, responsive layout, cross-browser smoke`

---

### Task 12: Production packaging (nginx + CSP)

**Files:** Create `frontend/Dockerfile`, `frontend/nginx.conf`. Modify `deploy/docker-compose.prod.yml` (add the `frontend` service, created by Plan 3), `docs/deploy.md`, `.env.example`, and `backend/tests/test_packaging.py` (update the api-port and proxy-default assertions). Test: `frontend/e2e/csp.spec.ts`, `frontend/src/test/packaging.test.ts`.

**Interfaces:**
- Produces:
  - **Dockerfile:** multi-stage. Builds on `node:26-slim` with `npm ci`, then serves from `nginxinc/nginx-unprivileged` (non-root).
  - **nginx.conf:**
    - SPA fallback.
    - Long-cache hashed assets, and `no-store` on `index.html`.
    - `proxy_pass` for `/api/` and `/api/ws/live` (WebSocket upgrade headers) to the `api` service.
    - Request limits.
  - **Response headers:**
    - `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' wss: ws:; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. The implementer tightens this as far as MapLibre allows and justifies each source.
    - HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`.
  - **Compose:**
    - The `frontend` service publishes `127.0.0.1:8080` only.
    - Pin the frontend's address on the Plan 3 `cvenom` network: `ipv4_address: 172.28.0.10`.
    - REMOVE the api's host port publish, since it is reachable only through nginx.
    - Update the api defaults to `FORWARDED_ALLOW_IPS=172.28.0.1,172.28.0.10` and the `.env.example` value to `TRUSTED_PROXY_CIDRS='["172.28.0.1/32","172.28.0.10/32"]'`.
    - Under these defaults, the chain is cloudflared on the host, then the bridge gateway, then nginx, then the api, and the api resolves the real client from X-Forwarded-For by walking right to left past both trusted hops. `proxy_add_x_forwarded_for` appends the gateway.
    - Update the topology section of `docs/deploy.md` to match, and update the Plan 3 packaging tests that assert the api port.
  - **nginx proxy settings:**
    - Sets `X-Forwarded-For $proxy_add_x_forwarded_for`, `X-Forwarded-Proto`, and `Host`.
    - `client_max_body_size 64k`.
    - The WebSocket `proxy_read_timeout` must exceed the 30 s server ping; use 75s.
  - **CSP:** prefer `connect-src 'self'`. Modern Chromium and Firefox treat same-origin ws/wss as covered by `'self'`. Add `wss:` only if the CSP e2e shows a violation, and justify it.
- [ ] **Step 1: Write the failing tests.**
  - The packaging test parses `nginx.conf` and asserts each header directive is present, that the CSP has no `unsafe-inline` and no `unsafe-eval`, and that the frontend's compose port is loopback-only.
  - The CSP e2e serves the production build through a local nginx container, or through a small Node static server that applies the same headers. It loads the dashboard with the fixtures and asserts no `securitypolicyviolation` events fired and the globe canvas renders.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.** Run `docker build` once as a smoke test if feasible, and report the outcome.
- [ ] **Step 4: Run the tests and confirm they pass.**
- [ ] **Step 5: Commit.** `feat(frontend): hardened nginx packaging with strict CSP`

---

## Self-Review

- **Spec coverage:**
  - §1 globe centerpiece, lanes, drill-down, email/webhook config UI, and dark/light: Tasks 3–7, 10, and 11.
  - §5 four lanes (CVE-less stories in Loud) and velocity: Tasks 5 and 6.
  - §7:
    - Stored-XSS contract (decode once, no `dangerouslySetInnerHTML`), safe links, CSP: Tasks 0, 1, 6, 7, and 12.
    - Public read-only / multi-device sessions: Tasks 2, 3, and 9.
  - §8 frontend, search/filter, and packaging: Tasks 8 and 12.
  - Approved mockup decisions (globe on top, lanes below, color reserved for signal, Plex type, Situation readout): Global Constraints and Tasks 3–6.
  - The user's Firefox concern: Task 11's firefox pixel check.
- **Review Focus:** XSS (T1, T6, T7), tokens (T1), degraded data (T2, T4, T6, T11), Firefox globe (T11), CSP (T12). Each has a named test.
- **Type consistency:**
  - `types.ts` (T1) is used across T2–T10.
  - `decodeEntities`, `Text`, and `safeHref` (T1) are used in T6, T7, and T10.
  - The `useLiveUpdates` status (T2) feeds the CommandBar (T3).
  - `globe.flyTo` (T4) is used by the drawer (T7).
- **Proportion:** code bodies appear only for the security-critical text/link tests. Everything else is given as signatures plus required assertions.
