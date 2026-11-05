# SDD ledger — plan: docs/superpowers/plans/2026-11-05-cvenom-frontend.md

Spec: docs/superpowers/specs/2026-11-04-cvenom-vuln-threat-radar-design.md (reachable)
Worktree: .worktrees/feat-frontend (branch feat/frontend, stacked on feat/api-alerts @ 8063372, pushed)
Base commit at start: 5e85897 (Plan 4 + design mockup committed)
Prior records: docs/superpowers/reports/2026-11-05-plan{1,2,3}-*.md
Design reference: docs/superpowers/design/cvenom-radar-mockup.html (layout/palette/type; its globe is NOT a reference)

## Environment
- Node v26.13.0, npm 11.20.0. Frontend lives in `frontend/` (doesn't exist yet; Task 0 scaffolds).
- The backend venv is not needed (tests mock /api through MSW and Playwright route fixtures). Never compose-up.
- Push policy: controller pushes at checkpoints; subagents never push; main untouched.

## Pre-flight scan

### Cross-task (shared file / interface)
| Produces | Consumes | Finding |
|---|---|---|
| T0 tokens.css, lint guards, vite proxy | all | OK |
| T1 decodeEntities/Text/safeHref, api(), auth store, types.ts | T2–T10 | OK. types.ts is derived from backend schemas_api.py and the route modules (ruled in the plan) |
| T2 useLiveUpdates status | T3 CommandBar | OK |
| T4 globe.flyTo | T7 drawer | OK — needs a shared handle. Ruling 2 |
| T3 routes incl. /admin/users, /account/password, /reset/:token | T9, T10 | OK — T9 owns AcceptInvite (reset mode) and Password; T10 owns admin users/invites/deliveries |
| T12 compose/nginx | backend/tests/test_packaging.py | Conflicted with the "never touch backend/" rule → amended in the plan (exception list) |
| T11 e2e fixtures | T12 CSP e2e | Reuses the fixtures — OK |

### Intra-task self-consistency
- **T9 password page.** T9's file list lacks the Password page, but T3 routes `/account/password`. Ruling 1.
- **T10.** Scope grew (users, deliveries, test-send) after Task 15. It is still one coherent admin task; watch its size.
- No test asserts nothing. The token-storage test is real.

### Rulings
- Ruling 1: T9 also creates `frontend/src/pages/ChangePassword.tsx` (`/account/password`) and makes AcceptInvite handle `/reset/:token` (reset mode: no email field, same accept endpoint). Cost if wrong: none.
- Ruling 2: The globe handle is shared through a small React context, `GlobeContext` with `{flyTo(iso2)}`. Globe registers it and Drawer consumes it. When the globe hasn't loaded (it is lazy), flyTo is a no-op. Cost if wrong: trivial refactor.
- Ruling 3: The Task 12 backend-file exception is limited to `backend/tests/test_packaging.py`, `deploy/`, `docs/deploy.md` and `.env.example` (amended in the plan before commit 5e85897).

## Task log
- Task 0: BASE=5e85897, dispatched (sonnet).
- Task 0: implemented 063abf0; 33 vitest tests (RED 5F + 3 files), lint/typecheck/build clean, initial JS 58 KB gzip. eslint 9.39.5 (plugin-react peer cap). Severity/live/scope/faint tested at 3:1 only. Review dispatched (sonnet).
- Task 0 review (sonnet): spec ✅ with an AA gap; Changes requested. Theme media query and mockup fidelity verified.
  - I1: sev/live/scope are tested at only 3:1, yet are used as text (light sev-crit is 4.32 on bg).
  - I2: --faint is a text token at ~4.2–4.4.
  - Minors: no-http test misses //host, ws(s) and dist/; lossy comment stripper; innerHTML guard bypassable via computed keys, document.write, setHTMLUnsafe, Object.assign.
- Ruling: every sev/live/scope/faint token ≥4.5:1 on all surfaces in both themes (text tier), plus the 3:1 non-text tier. Darken light sev-crit and raise faint. Fold M1–M3. W3C SVG namespace allow-listed for T4.
- Ruling (→ T6 dispatch): severity is conveyed by tint, edge, dot or icon. Chip text may use severity colours only because the tokens now clear 4.5. Never lower contrast via opacity, glow or strobe.
- Task 0: fix round 1 resumed; FIX_BASE=063abf0.
- Task 0: fix round 1/5 (I1, I2 and M1–M3 addressed, 0 open; commits 063abf0..cf29c06). 48 tests.
- Task 0: **complete** (commits 5e85897..cf29c06, clean after 1 round).
  - Deferred: unquoted `src=//host` is not flagged; the dist scan only runs after a build (gate order is lint, typecheck, build, test).
- Task 1: BASE=cf29c06, dispatched.
- Ruling (Task 1):
  - Decode once via a single regex callback; invalid numeric entities stay literal; no DOM.
  - safeHref: new URL with no base, http(s) only, no whitespace or control chars. ExternalLink always emits rel="noopener noreferrer" and target="_blank".
  - The api() client:
    - exempts login/password/refresh/accept from refresh-on-401;
    - single-flight refresh within a tab and across tabs (Web Locks, BroadcastChannel fallback), with the new token broadcast so other tabs never re-present the cookie;
    - proactive refresh 60s before expiry;
    - bootstrap refresh once, falling back to guest on 401.
  - Token is held in memory only.
- Task 1: implemented 8d19a4e, 100 tests, gates clean, msw 2.15.0. Notes: tokenStore.ts extra; only 401/403 on refresh logs out; BroadcastChannel fallback not fully exclusive; login doesn't broadcast. Review dispatched (opus).
- Task 1 review (opus): spec ✅, Changes requested. XSS/decode/safeHref probes all pass, single-flight confirmed, types mostly exact.
  - I1: cross-tab identity: a guest tab adopts a peer token; a user switch shows the wrong identity; logout isn't propagated.
  - I2: the BroadcastChannel lock fallback lets two tabs present the same refresh token. The loser gets AuthError, and the backend clears the SHARED cookie on that grace-window 401, so every tab is logged out. Timers fire in sync.
- Ruling (I1): broadcast login/logout events carrying the user id. Adopt a refreshed token only when this tab already holds a token or is awaiting one, and reload /me if sub differs.
- Ruling (I2): drop the BC lock fallback and use Web Locks only. Without locks, there is no proactive timer (reactive only). Jitter 0–20s. Adopt a peer broadcast on a refresh 401. Cost if wrong: browsers without Web Locks refresh reactively only.
- Ruling (backend follow-up, controller-dispatched, explicit exception to "no backend"): the grace-window InvalidToken in /auth/refresh must NOT clear the refresh cookie (the legit concurrent loser shouldn't wipe the winner's cookie). Real reuse and expired/invalid tokens keep clearing. Do as a small separate commit with tests after the T1 fix.
- Minors folded: skip refresh when no token was sent; nullable types; clamp timer; logout on /me failure.
- → T6/T7: render API text with unicode-bidi: isolate (<bdi> or CSS) against bidi overrides.
- Task 1: fix round 1 resumed; FIX_BASE=8d19a4e.
- Task 1 fix: e49f10f, 114 tests. Re-review dispatched (sonnet). Backend grace-cookie fix dispatched in parallel (sonnet; backend-only files; the backend venv was created in this worktree, baseline 1093).
- Task 1: fix round 1/5 (I1, I2 and 4 minors addressed; 1 new Important open: a logout doesn't cancel an in-flight refresh or the lastPeer adoption, so the session can resurrect; commits 8d19a4e..e49f10f).
- Task 1: fix round 2 dispatched. Fix: an epoch counter bumped on clear; refresh/adopt/loadMe discard their result on epoch change; clear resets lastPeer.
- Backend grace fix: 0eeab61 (RefreshGrace(InvalidToken); grace 401 has no Set-Cookie; reuse/unknown still clear). Backend suite 1094. Review dispatched.
- Backend grace fix 0eeab61: review Approved, no Critical/Important. The single raise site is confirmed and the attacker gains nothing (no DB mutation, no token issued). Deferred minors: assert pytest.raises(RefreshGrace) explicitly at unit level; assert no-store on the grace 401.
- Task 1: fix round 2 committed f7ce63b (epoch guard; 118 tests). Re-review dispatched.
- Task 1: fix round 2/5 (the logout-race Important was addressed, 0 open; commits 0eeab61..f7ce63b, excluding the backend commit). The epoch guard is verified, and login doesn't bump the epoch.
- Task 1: **complete** (commits cf29c06..f7ce63b, clean after 2 rounds).
  - Deferred to the final review: tests (b) and (c) of round 2 don't discriminate (the lastPeer reset and the !t check alone pass them). A discriminating (c) needs logout, then login, while /me is pending.
  - Deferred: a logout→login→old-refresh caller gets AuthError while the tab is signed in (benign).
- Task 2: BASE=f7ce63b, dispatched.
- Task 2: implemented b5dad98, 152 tests, gates clean. Notes: a failed 4401 refresh goes offline even on network blips (ruling-literal); a reconnect invalidates all roots; __proto__ bug found and fixed. Ruling (pending fix): a non-AuthError refresh failure on 4401 → backoff, not offline. Review dispatched (sonnet).
- Task 2 review (sonnet): Changes requested.
  - Hygiene, leaks, URL encoding and backoff math verified.
  - I1: a transient refresh failure leaves the socket offline forever.
  - I2: an unthrottled 4401 loop on server-side auth errors burns refresh rotations.
- Ruling: AuthError → offline/anonymous; other errors → backoff. Only the first consecutive 4401 refreshes; later ones back off.
- Minors folded:
  - a shared ref-counted controller per QueryClient, so multiple hook callers make one socket;
  - RateLimited mount gating;
  - a direct offline path with no token;
  - health honors retryAfter and re-fetches after a 4401;
  - lastUpdated bumps only on known keys.
- Task 2: fix round 1 resumed; FIX_BASE=b5dad98.
- Task 2: fix round 1/5 (I1, I2 and 6 minors addressed, 0 open; commits b5dad98..328b9a2). 161 tests.
- Task 2: **complete** (commits f7ce63b..328b9a2). Deferred:
  - unstable deps object churn (no production callers);
  - stale openedAt after dropSocket (could cause a rare extra refresh);
  - the M5 test exercises only logout-during-connect.
- Task 3: BASE=328b9a2, dispatched.
- Ruling (Task 3):
  - Routing: React Router, with placeholder pages for later tasks plus a 404 page.
  - Auth: bootstrap runs once behind a loading state, so the user isn't redirected before auth is known. useAuth is built on useSyncExternalStore.
  - Guards:
    - The login `next` param is validated as same-app relative, so it can't be used as an open redirect.
    - In private mode, guests are sent to /login.
    - Members hitting admin pages get an "Admins only" notice, not a crash.
  - situationLevel is a pure function. "kev_added within 24h" = today or yesterday in UTC, since it is a DATE.
  - AlertBar: selection lives in the `?cve=` search param (shareable link), and dismissal is per session (sessionStorage).
  - Theme: localStorage `cvenom-theme` in a try/catch.
- Task 3: implemented 1823c1e, 240 tests, gates clean, 88.6 KB gzip. react-router-dom 7.18.4. Added 3 inert react-router strings to the dist allow-list. → T9: Login must use safeNext. → T7: drawer opens from ?cve=. Review dispatched (sonnet).
- Task 3: review spec ✅ Approved, no Critical/Important. Open-redirect probes all safe; no guard flicker; mockup fidelity close.
- Task 3: **complete** (commits 328b9a2..1823c1e).
  - Minors routed:
    - → T4: tighten the dist allow-list `http://localhost` entry so it strips only the exact literal (followed by a quote or backtick).
    - → T9: UserMenu hides until ready (avoids a "Sign in" flash); Login uses safeNext; skip nested next on /login; add redirect tests for /%2F%2F, /..//, long strings, plus a length cap (2048).
  - Deferred: "Admins only" notice reappears on history reload; local-time hh:mm; render-time applyTheme.
- Task 4: BASE=1823c1e, dispatched.
- Ruling (Task 4): opus implementer, since this is the centerpiece and Firefox is the user's concern.
  - Geometry: world-atlas JSON bundled; numeric→ISO-2 table; largest-polygon centroid; antimeridian check.
  - Style: no glyphs, sprite or remote sources; DOM overlays for title, legend and attribution.
  - Runtime: MapLibre CSP build with a self-hosted worker; lazy-loaded.
  - Rotation: auto-rotate respects reduced motion and pauses when hidden.
  - Map setup: explicit container height; sources added only after `load`.
  - Resilience: WebGL fallback panel; GlobeContext flyTo.
  - Testing: dev harness for e2e; one-off headless Firefox screenshot if feasible.
  - Allow-list tightened (T3 minor).
- Task 4: implemented cda9226 (opus). 311 tests (324 with the harness build); gates clean; initial chunk 88.7 KB gzip; Globe chunk 331 KB gzip, lazy.
  - Headless Firefox 157 renders countries in both themes, with no antimeridian stripes and a WebGL fallback. The controller viewed globe-firefox-dark.png and confirmed polygons, shading, hotspots and attribution.
- Ruling: accept maplibre-gl 6.15.0 instead of 5.x. Every 5.x is affected by critical advisory GHSA-jrc7-96c5-q579, an XSS sanitizer bypass. v6 supports the globe and uses a module worker from self, so CSP needs only worker-src 'self'. Cost if wrong: the API differs from 5.x docs.
- Notes:
  - → T11: the Dashboard mounts LazyGlobe and needs an MSW /api/geo handler; check axe nested-interactive on the role=img canvas container.
  - → final review: setup.ts doesn't register RTL cleanup globally.
  - Harness: /globe-harness.html.
- Review dispatched (opus).
- Task 4 review (opus): ❌ two gaps, otherwise solid.
  - Verified: the CSP no-eval default path, 0 off-origin requests in Firefox, XSS-validated inputs, full cleanup, StrictMode producing a single canvas, antimeridian OK, fallback usable.
  - I1: the globe hijacks page scroll after any drag (reproduced in Firefox).
  - I2: victim is colored sev-crit, which is ≈ the scan color; the brief says scope/med.
- Ruling:
  - zoom only on Ctrl/Cmd+wheel;
  - kind colors: scan=live, outage=sev-high, victim=scope, c2=sev-med, bgp=sev-low, from one shared mapping;
  - folded minors: drop role=img around the focusable canvas; fallback reason; map error → fallback; no idle RAF and ~30fps rotation; hint uses --faint; content-sized fallback.
- Ruling (#8): the drawer flyTo holds rotation until the next interaction. Kept, so the selected country stays in view.
- Task 4: fix round 1 resumed; FIX_BASE=cda9226.
- Task 4: fix round 1/5. I1, I2 and minors 3–7 addressed. One new Important finding: the watchdog can false-fallback on slow devices, after a post-load error grace of 1.5s or the 6s deadline. Commits cda9226..ba54308.
- Ruling: watchdog timings:
  - pre-load error: immediate fallback;
  - post-load error: fall back only if there is still no data 5s later;
  - no error: fall back at a 15s deadline;
  - the timer is paused while the tab is hidden.
- Ruling: the hint goes back to --muted (light --faint on the translucent backdrop is ~4.3:1). The contrast test is extended to that pair.
- Task 4: fix round 2 resumed.
- Task 4: fix round 2/5 (the watchdog Important plus 2 minors were addressed, 0 open; commits ba54308..d94d872). 345 tests.
- Task 4: **complete** (commits 1823c1e..d94d872, clean after 2 rounds). The watchdog uses earliest-deadline-wins, so it can't be postponed forever. Deferred: no dedicated test that a second error doesn't extend the window.
- Task 5: BASE=d94d872, dispatched.
- Task 5: implemented 105547b, 361 tests, gates clean. Review dispatched (sonnet).
- Task 5 review: Changes requested. Important: velocity.css uses undefined --console, so the card is transparent. Path math, dot, AA and days=30 all verified.
- Ruling: use --panel. Add a systemic guard test: every var(--x) in CSS/TSX must be defined in tokens.css or locally. Folded minors: skeleton role=status, chip right-aligned when wrapped, days derived from a constant.
- Task 5: fix round 1 resumed; FIX_BASE=105547b.
- Task 5: fix round 1/5 (all addressed; commits 105547b..8ec9b3e). The CSS token guard was proven to catch --console. 362 tests.
- Task 5: **complete** (commits d94d872..8ec9b3e).
- Task 6: BASE=8ec9b3e, dispatched.
- Ruling (Task 6):
  - Severity edge: crit ≥9, high ≥7, med ≥4, else low. KEV forces the live edge.
  - Text: bidi isolate on API text; mockup tokens mapped to existing ones (raise→panel-2, fg→text, faint text→muted).
  - Loud lane: LOUD CVEs first, then stories (newest first) deduped against those CVEs, capped at 100. The story link lives only in the drawer.
  - Selection: `?cve=` and `?story=` URL params via useSelection, each validated (CVE regex / safeHref).
  - RateLimited: show a banner.
- Task 6: implemented 3d54fab, 405 tests, gates clean. No genuine RED (tests written alongside). Story rows = div + inner buttons. Review dispatched (sonnet; asked to check test discrimination).
- Task 6: review spec ✅ Approved; 4/4 key tests discriminate under mutation, with one caveat: the XSS test doesn't catch innerHTML, though lint does.
- Task 6: **complete** (commits 8ec9b3e..3d54fab).
  - Minors routed → T7:
    - add double-encoded `&amp;lt;` decode-once tests to Lanes and Drawer;
    - replace aria-label on the span (Lanes.tsx:72) with sr-only text.
  - Deferred: raw cve_id/kev_added rendering (benign), story key duplicates, memoization.
- Task 7: BASE=3d54fab, dispatched.
- Ruling (Task 7):
  - DrawerHost reads the selection. Close clears the selection with history replace.
  - Accessibility: modal dialog with a focus trap, Esc and scrim close, focus returned, background made `inert`, scroll lock, and reduced motion respected.
  - Data display: meters use role=meter and are clamped. Geo details keys and values render as text, with nested values shown as JSON text and capped at 12. Affected items cap at 50.
  - Globe: flyTo runs once, to the top valid country.
  - StoryDetail: there's no single-story API, so it finds the story in cached loud stories. If missing, it falls back to the safe ExternalLink.
- Task 7: implemented e5939cd, 437 tests, gates clean. Code-first (no clean RED). selection.ts gained replace/clear. Review dispatched (sonnet; mutation-check key tests).
- Task 7: review spec ✅ Approved. Mutation checks: focus trap, inert, javascript: URL, and double-decode all discriminate; the flyTo refetch guard is untested.
- Task 7: **complete** (commits 3d54fab..e5939cd).
  - Minors routed → T11:
    - a flyTo-once refetch test;
    - inert also covers the skip link, the AlertBar aside, and .notice;
    - scope the header selector to `body > header`/`#app > header`;
    - StoryDetail on query error shows "couldn't load stories" instead of "no longer in feed".
- Task 8: BASE=e5939cd, dispatched.
- Task 8: implemented a714833, RED 16/16 → GREEN, 454 tests. Review dispatched (sonnet).
- Task 8 review: ❌ one gap. Important: q is not trimmed, so a whitespace-only q gets sent. Verified: strict dates, params validated, no loops.
- Ruling: trim q on read and write. Fold minors:
  - back/forward race → cancel debounce on external URL change;
  - test wait tied to DEBOUNCE_MS;
  - focus to the results count after paging;
  - explicit ARIA table roles on mobile.
- Task 8: fix round 1 resumed; FIX_BASE=a714833.
- Task 8: fix round 1/5 (all 5 items addressed; 1 new Important: a file-wide eslint disable of 2 jsx-a11y rules; commits a714833..022c7ed). 457 tests.
- Reviewer note: a reviewer's command included `sed -i`/`git checkout` on Search.tsx. The permission classifier denied it, and the controller verified the tree is clean. Reviewers have been told they're read-only; their mutation checks must use the copy/restore method.
- Task 8: fix round 2 resumed (scope the lint disables to the 8 sites, plus a scroll-into-view test).
- Task 8: fix round 2/5. Lint disables scoped to the 8 sites; the controller grepped and lint is clean. Scroll test added (459 tests). Commits 022c7ed..388c5af.
- Task 8: **complete** (commits e5939cd..388c5af). Deferred: one line-scoped react-hooks/exhaustive-deps disable at Search.tsx:182.
- Task 9: BASE=388c5af, dispatched.
- Ruling (Task 9):
  - Login: a single generic failure message; uses safeNext with a 2048 cap; the user menu hides until auth is ready.
  - Accepting an invite logs the user in automatically.
  - Reset: no auto-login; log out locally, then go to /login with a notice.
  - Invite/reset links: the token is stripped from history with replace; the token pages have no external resources; Referrer-Policy no-referrer (meta, plus nginx in T12).
  - Sessions: revoking the current session logs out; a 404 on revoke triggers a refetch.
  - ChangePassword: a 401 doesn't log out.
  - Shared passwordProblems helper; error summary receives focus.
- Task 9: implemented 31153f6, 508 tests (RED 29), gates clean. Notes: stricter safeNext; vitest testTimeout raised to 15s (lint-guard cold start); referrer meta on mount. Review dispatched (opus; auth UI).
- Task 9 review (opus): spec ✅ Approved, no Critical/Important. Token/credential/enumeration/open-redirect/revoke-race checks pass.
  - Minors:
    - the Sign-in link carries the invite/reset token in `next`;
    - ChangePassword maps any 401 to a wrong-password message;
    - any 422 is treated as the policy error;
    - maxLength 256 silently truncates;
    - reset logs out an unrelated admin;
    - global testTimeout;
    - history-replace and `..` tests don't discriminate;
    - sessions confirm focus;
    - nits.
- Ruling: fold all of the minors into a hardening round (they touch secrets and credentials).
  - Reset logic: if no user or the same user → logout + /login; if a different user is signed in → no logout, show a notice, go to /.
  - Non-credential 401 on change-password → one refresh + retry, then "session expired".
- Task 9: hardening round resumed; FIX_BASE=31153f6.
- Task 9: hardening round (9/9 addressed; commits 31153f6..7b954a9). 530 tests.
- Task 9: **complete** (commits 388c5af..7b954a9).
  - → final review: add .prettierrc (printWidth 120, double quotes, semicolons, trailingComma all). Prettier at its default 80 cols rewrapped 4 files; reformat consistently.
  - Deferred: duplicate redirect fixture.
- Task 10: BASE=7b954a9, dispatched.
- Ruling (Task 10):
  - Secrets: a one-time secret panel for the webhook secret and for invite/reset links. Secrets are kept only in panel-local state. They never enter the React Query cache (strip before caching, then invalidate), the URL, storage or logs. Done or unmount discards them. There is no auto-copy. A test walks the query cache.
  - Rules: PATCH covers editable fields only. Recipients are add/remove only.
  - Deliveries: a table with the drawer link. Test-send has a 429/504 UX.
  - Users: 409 errors are mapped to messages. Self-row controls are disabled.
  - All confirms are in-page.
- Task 10: implemented 6de4536 + 2f8d9c5, 583 tests, gates clean. Code-first (no RED). Secrets avoid the mutation cache (plain async). Contract for users/invites not re-read against the backend. Review dispatched (opus; secrets + contract check).
- Task 10 review (opus): spec ✅ Approved, no Critical or Important findings.
  - Secret tests M1–M5 all caught by mutation. The security-hook alert on doneSecret was the reviewer's transient mutation; the controller verified the committed code clears the secret and the tree is clean.
  - The backend contract was checked line by line; no mismatches.
  - Minors: reset has no confirm; the edit form decodes raw fields and rewrites them; the password manager may capture the webhook secret; remove-recipient has no confirm; empty test-send; nits; Login.test flake; no test for the 30s refetch.
- Ruling: fold all of these into a hardening round.
- Task 10: hardening round resumed; FIX_BASE=2f8d9c5.
## USER DECISIONS (2026-11-05 ~10:34)
1. CISA-after-VulnCheck → (c) alert on a CISA listing iff no alert was ever sent for that CVE. Backend change: a durable cve.kev_alerted_at marker (migration 0005).
2. ransomware.live: user will get a Pro key later. Collector stays OFF without the key (current behaviour).
3. CF Radar + abuse.ch: user will get keys later. Same OFF-without-key behaviour. deploy.md must list exactly which env var enables each.
4. Unscored KEV CVEs keep matching cvss/epss rules → (a) keep.
5. Telegram: deferred.
6. Login fail-closed when Redis is down: keep.
7. LOCK DOWN. Rule recipients are visible to admins only; deliveries are admin-only. User note: "there is a chance the public uses this tool", so also audit the other member-visible endpoints for exposure.
8. Merge: (a) four PRs in order (backend-foundation → geo-news → api-alerts → frontend) when Plan 4 is done. The user explicitly authorized opening them.
- Backend follow-up (decisions 1 + 7) dispatched (sonnet) in parallel with the T10 hardening; backend-only files.
- USER CONFIRMED (10:36): globe-harness renders correctly in the user's own Firefox. The Firefox concern is resolved. T11's Firefox e2e stays as a regression guard.
- Task 10: hardening round (8/8 addressed; commits 2f8d9c5..0d3c5a2). 587 tests, stable across 3 runs.
- Task 10: **complete** (commits 7b954a9..0d3c5a2). Deferred: no test for a threshold changed to 0 (code verified correct).
- Task 11: BASE=0d3c5a2, dispatched. The backend decisions agent is still running in parallel (backend files only).
- Backend decisions: 8e5cd45 (CISA kev_alerted_at, migration 0005, backfill) + c96e878 (admin-only recipients/deliveries + exposure audit). Backend 1103. Review dispatched (sonnet).
- USER provided the ransomware.live Fair Usage Policy (10:56): their data is cached 30 min, so poll no faster than that; no redistribution as an API; no raw publishing; one key only; no relaying customer queries; no cloning their site.
- Ruling (compliance):
  - Ransomware cadence 900 → 3600s.
  - All ransomware.live-derived data (its stories in loud/lanes/search/detail, victim geo events in geo_summary and CVE detail) is served ONLY to authenticated users. Anonymous/public responses exclude it, and the anonymous cache can't hold it.
  - The UI credits "Ransomware data: ransomware.live".
  - deploy.md gets a fair-use note.
  - Why: the user said the public may use the tool, and anonymous record-level serving = re-serving to third parties.
  - Cost if wrong: anonymous viewers miss the victim layer.
- Dispatched backend compliance fix (sonnet).
- Backend decisions 8e5cd45+c96e878: review Approved (concurrent CISA/VulnCheck double event is harmless thanks to delivery dedupe; backfill correct; member paths verified). Deferred: comment on the stale ORM kev_alerted_at after the Core UPDATE. → Frontend follow-up: types need recipient_count (members); admin pages unaffected.
- USER DECISION (11:01): anonymous viewers see AGGREGATED ransomware victim counts (geo_summary per country/kind). Individual victim records (stories, CVE-detail geo events, labels/urls/details) are authenticated-only. Sent to the compliance agent as an amendment.
- PLAN 5 (breach/watchlist) PARKED by the user (11:03): do not propose, design, or build now. Notes for later: the product is a GENERIC news aggregator the user provides to companies (nothing tailored); per-user profile watch terms (vendors/domains/keywords) → alerts; HIBP breach catalog feed + Pwned Passwords check; paid HIBP domain search is out of the core. OPEN: does one shared instance serve many companies (multi-tenancy) or does each company get its own deployment?
- Compliance fix f99e2c0 (hourly; anonymous gets aggregates only; story counts include ransomware). docs/ROADMAP.md committed. Compliance review dispatched.
- Compliance f99e2c0 review: Approved. Every anonymous path checked; filters run in SQL before LIMIT; the cache is safe.
  - Minors → final wave:
    - (2) move the deploy.md fair-use section below the "All are optional" sentence;
    - (3) duplicate User import / redundant Depends;
    - (5) anonymous regression guard: search and lanes must omit ransomware titles.
  - Minors → T11/T12 frontend:
    - (1) the drawer copes when recent_story_count > visible stories ("some sources are visible to signed-in users only" note for anonymous viewers);
    - also add the "Ransomware data: ransomware.live" credit wherever a story's source == "ransomware.live".
  - Deferred: (4) min-count threshold for low-count geo aggregates.
- Task 11: implemented 5b1057b; unit 593; e2e chromium 6/6 firefox 6/6; axe clean; initial 109 KB gzip; pixel stddev chromium 15.1 / firefox 8.8 (threshold 4). workers=2 to avoid flakes under software WebGL. Review dispatched (sonnet).
- Task 11: review Approved (12/12 e2e, axe clean, the fallback fails the pixel check, the console exception is narrow).
- Task 11: **complete** (commits 42fea8d..5b1057b).
  - Minors routed → T12:
    - (1) e2e XSS fixture;
    - (2) assert the WS URL is same-origin and token-free;
    - (6) 400px drawer case;
    - (3) comment justifying the blob:/data: schemes;
    - (5) minimum canvas size.
  - Compliance frontend follow-ups → T12:
    - ransomware.live credit;
    - drawer note when count > visible stories for anonymous users;
    - types: recipient_count.
- Task 12: BASE=5b1057b, dispatched.
- Task 12: implementer DONE (516a5c3, dcaab62). vitest 613, e2e 28/28, packaging 36/36, backend 1112, docker build OK. Deviations: XFF via map, resolver+variable proxy_pass, server-level headers, fonts not inlined. Review dispatched.
- Task 12 review: spec ❌ (stale ransomware.live "blank key = free data" text in .env.example:67,77 and deploy.md:229 contradicts the user decision); quality: 3 Important, 5 Minor.
  - Important: (1) nginx /api/ proxy_read_timeout 30s < 45s test-send; (2) deploy.md topology (b) omits set_real_ip_from; (3) ransomware text.
  - Minor: (4) limit_req hits /assets; (5) XFP always http; (6) duplicate api security headers; (7) wrong /docs note; (8) the anonymous note false-positives at the 50-story cap and before auth is ready.
  - Real-IP trace verified non-spoofable.
- Task 12 fix round 1: resumed implementer with Important 1-3 + Minors 4-8 (all small, same files).
  - Ruling: fold in the minors now — they are cheap, in files already touched, and 5 and 8 are user-visible — cost if wrong: a slightly bigger fix diff.
- Task 12 fix round 1: e14433d (vitest 615, e2e 28/28, backend 1112). Scoped re-review dispatched.
- Task 12 re-review: spec ✅, quality Approved.
  - Minor routed → final wave: give /api a per-URI CSP map (default-src 'none'; frame-ancestors 'none') so it matches the API's own policy; fix the deploy.md:164 sentence.
- Task 12: **complete** (commits 5b1057b..e14433d, review clean).
- ALL TASKS COMPLETE. Next: final whole-branch review.

## Final whole-branch review (opus), range 8063372..e14433d
Verdict: With fixes. No Critical findings.
- I1: query cache not reset or keyed on identity → leaks across users, and signed-in users get the anon view on deep links.
- I2: ?story= renders an attacker link in the drawer.
- I3: the error banner promises retries that never happen.
- Minors: M1 WS 4401 extra refresh; M2 invite/reset tokens in the URL path reach the nginx/CF logs; M3 deploy.md accuracy + TLS note; M4 routes_read tidy; M5 no signed-in e2e; M6 RTL cleanup; M7 dup story keys.

Rulings:
- Ruling: fix I1-I3, M1-M7, the anonymous ransomware regression guard, and the deploy.md:164 sentence in ONE fix wave — all small, and I1/I2/M2 are security/privacy — cost if wrong: a larger fix diff.
- Ruling: M2 → move invite/reset tokens into the URL fragment (#token); the fragment never reaches nginx/Cloudflare; the accept pages strip it with history.replace — frontend-built links, nothing shipped yet, so no compat path — cost if wrong: an old-format link from a dev test won't open.
- Ruling: defer the /api per-URI CSP map — not exploitable (JSON + nosniff) and it complicates the csp-server header parser; deploy.md states the truth instead — cost if wrong: defense in depth lost for a future HTML endpoint.
- Ruling: defer .prettierrc + reformat to a formatting-only follow-up — keeps the PR diff readable — cost if wrong: style drift in 4 files.
- Ruling: defer the T1 r2 non-discriminating tests (except the M5 signed-in e2e) and the RefreshGrace unit asserts — behavior verified by mutation — cost if wrong: a weaker regression net.
- Ruling: keep PublicOrUser → /login when /health is unreachable (T3 ruling) — never expose on a guess — cost if wrong: an unreachable API shows a login page instead of an error.
- Fix wave dispatched.
- Final fix wave: 78b67d5, 3de1044, 542d7d2 (vitest 638, e2e 30/30, backend 1113). Deviations: M4 kept Depends(current_user) for the value; M1 kept the full invalidate after 4401 (missed-push gap). Scoped re-review dispatched.
- Final fix wave re-review: all findings Fixed; ready to merge: Yes.
  - New Minors: (a) uncapped Retry-After → interval > 2^31 ms → hot loop; (b) a persistent 401/403 polls every 30 s.
  - Out of scope: a peer-tab user switch with /me failing keeps the old identity (pre-existing); old /invite/<token> links 404 (no deployments).
  - Ruling: fold (a)+(b) into the security-review fix commit (or a standalone commit if security is clean) — both are tiny and (b) burns the anonymous rate limit — cost if wrong: one small extra commit.
- Final review: **clean** (commits 8063372..542d7d2). Next: security review.
- Security review (opus): no High/Medium findings ≥8.
  - Sub-threshold note: the WS Origin check runs only when CORS_ORIGINS is set (pre-existing); no impact, since auth is first-message bearer.
  - Ruling: add a same-origin default for the WS Origin check (Origin host must equal Host when CORS_ORIGINS is empty) as defense in depth, alongside the two re-review Minors (Retry-After cap; no error polling on 401/403) — the user said "lock it down" for public use — cost if wrong: a reverse proxy that rewrites Host would break WS (nginx passes $host; the Vite proxy preserves Host).
- Hardening commit dispatched.
- Hardening fee07e0: Retry-After cap 3600, no polling on 401/403/AuthError, WS same-origin default (nginx WS Host → $http_host). vitest 642, e2e 30/30, backend 1116. Controller-checked the diff. Plan 4 DONE.
