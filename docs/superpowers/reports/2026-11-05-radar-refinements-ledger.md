# SDD ledger — plan: docs/superpowers/plans/2026-11-05-radar-refinements.md

Spec: docs/superpowers/specs/2026-11-05-radar-refinements-design.md (sections A–E only; F/G/H out of scope)
Branch: feat/radar-refinements, start HEAD edf2dfb. Local only — no push/fetch/pull/PR.
Track lead: subagent-driven-development; model table per controller dispatch.

## Pre-flight scan

| Pair / task | Shared file or interface | Finding |
| --- | --- | --- |
| T1 ↔ T5 | `/api/cves` (`lane=` via `lane_views`, new `sort`/`kev_from`/`kev_to`), `test_read_api.py` | Compatible: T1 changes lane membership; T5 adds orthogonal params. T5 default sort applies to the non-lane path; `lane=` keeps lane_views order. |
| T1 ↔ T2 | `pipeline.py` (`lane_views` vs `_sanitized`/`_ingest_story`) | Different functions; sequential, no conflict. |
| T2 → T3 | `NormalizedCve` new fields, `upsert_cve` merge rules | T3 consumes exactly the fields T2 defines (`None` = not provided). Consistent. |
| T2 → T4 | `NormalizedStory.details`, `validate_http_url` .onion rejection | Consistent. T4 depends on `_ingest_story` storing `_sanitize_details(details)` (T2). |
| T2 → T5 | Cve columns → `CveDetail` | Consistent; reader tolerates legacy `[]`/NULL. |
| T5 ↔ T6 | `readmodels.py`, `routes_read.py`, `schemas_api.py` | Same files, distinct functions; sequential. `CACHE_PATHS["/api/geo"]` prefix already covers `/api/geo/{cc}`. |
| T5/T6 → T7 | response shapes → `types.ts`, hooks | Consistent per Self-Review. |
| T7 → T8 | `useStorySearch`, `StoryQuery`, `CveQuery.sort` | T8 stories page size 50 within API max 100. Consistent. |
| T7 → T9 | `refLinks`, `safeHref`, `useStory` | Consistent. |
| T7 → T10 | `Selection.country`, `isIso3166Alpha2`, `useCountry` | Consistent. |
| T8 ↔ T9 ↔ T10 | `e2e/harness.ts`, `smoke.spec.ts` (T8,T10), `drawer.css`/`Drawer.test.tsx` (T9,T10) | Sequential edits to the same files; each task appends. No contradiction. |
| T1 self | tests vs interfaces | Agrees (boundary today−30 in, −31 out, NULL kev_added out). |
| T2 self | migration SQL vs test | Agrees: test expects permalink rs story + clearnet news remain; SQL deletes non-permalink rs + any .onion. |
| T3 self | | Agrees. |
| T4 self | | Agrees; `id` quoting `safe=""` matches expected `a%2F..%2Fb%20c`. |
| T5 self | | Agrees. |
| T6 self | | Agrees. |
| T7 self | Situation rule vs spec | Spec says "any listing in the last 24 h"; plan says today-or-yesterday UTC (date granularity, existing `isRecentKevDate`). See ruling R1. |
| T8 self | | Agrees. |
| T9 self | | Agrees; CSS change gated on red e2e. |
| T10 self | | Agrees. |

Note: the controller said "the planner made 15 rulings listed in the plan"; the plan contains no separately labelled rulings list — its decisions are inline in task Interfaces and Global Constraints, and are treated as binding.

Ruling: R1 Situation "last 24 h" = kev_added is today or yesterday UTC (plan wording, existing isRecentKevDate) — kev_added is a date with no time, so 24 h can't be exact; plan's reading is the faithful conservative one — if wrong, Severe fires up to ~24 h longer than intended; one-line change in situation.ts.

## Tasks
BASE edf2dfb; T1 implementer a5b637fa41c17c04b (sonnet) dispatched
Baseline: controller backend run at edf2dfb produced no output (likely the IPv6 localhost hang; pipe exit 0 is tail's) — baseline unknown. Controller rule from 17:xx: every backend pytest sets PGHOSTADDR=127.0.0.1 (added to hard-rules.md, sent to T1).
T1 implementer DONE 19fce1e (1121 backend passed). T1 reviewer a89d3d7e937416c2e (sonnet) dispatched on review-edf2dfb..19fce1e.diff
T1 review (sonnet): spec ✅, quality Approved, 0 Crit/0 Imp. ⚠️ NULL kev_added untested at DB/API level (Review Focus "quiet month") — confirmed real gap → fix round 1 (resume a5b637fa41c17c04b), plus minor #3 (non-UTC now test) folded in.
Task 1: minor (deferred): SQL lane boundary not tested at exactly today-30/today-31 via lane_views (scoring covers it; same predicate).
T1 fix round 1 implementer DONE: 4b7ac68 test(lanes): NULL kev_added stays out of the lane but in History; non-UTC now (55 passed in test_scoring + test_read_api). NEXT: scoped re-review 19fce1e..4b7ac68, then ledger "Task 1: fix round 1/5 ..." and "Task 1: complete", then Task 2 (opus).
Track lead handed back to controller (forced interim hand-back) after this point.
Controller resumed the track (same tiers/rules). Added scope:
Ruling: Task 11 (added by controller) — fix the OSV collector, which fails on every run with ResponseTooLarge because the 157 MB index exceeds the 25 MB cap. Switch it to OSV's incremental source (per-ecosystem modified_id.csv / recently-modified feed, or the querybatch API), keep the response caps, don't raise the cap, add tests; sonnet implementer + sonnet reviewer, after Task 10 and before the final review — the controller ordered it, and an incremental fetch is the only way to stay under the cap. Cost if wrong: OSV data stays stale or partial until the collector is reworked; the change is contained to collectors/osv.py and its tests.
Task 1: fix round 1/5 (2 addressed, 0 open — NULL kev_added DB/API test; non-UTC now test; commits 19fce1e..4b7ac68)
Task 1: complete (commits edf2dfb..4b7ac68, review clean)
BASE for T2: 4b7ac68
T2 implementer a595a6deaf645fd8c (opus) dispatched, BASE 4b7ac68
T2 implementer DONE 32dca4a (1153 backend passed). Concerns noted below.
Ruling: R2 migration 0006 keeps the plan's ONION regex verbatim even though it does not match a bare host "onion" (validate_http_url does reject it) — a bare single-label "onion" host can't be a real stored ransomware/news URL, and widening an irreversible DELETE beyond the plan's text is riskier than the gap — cost if wrong: a hypothetical row with host exactly "onion" survives 0006 (the frontend safeHref still renders no link).
Note for T5/T7/T9: stored reference URLs are entity-escaped at ingest (& → &amp;); the frontend must render them via safeHref(decodeEntities(url)) (per Global Constraints).
T2 review (opus): spec ✅, Needs fixes — 1 Important (geo UPDATE ONION clause untested in isolation). Fix round 1 → resume a595a6deaf645fd8c, folding in minors 1(comment),2(%2E / IDNA-dot onion hosts pass backend),3(non-str cvss_vector fails record).
Task 2: minor (deferred): _SEVERITIES duplicates CvssSeverity literal (use get_args).
Task 2: minor (deferred): upsert_cve uses hasattr(v,"model_dump") duck-typing for references.
Task 2: minor (deferred): sanitised tags can exceed 64 chars after entity escaping.
Task 2: minor (deferred, R2): migration regex misses bare "onion" host and multiple trailing dots.
Task 2: fix round 1/5 (4 addressed, 0 open — geo ONION clause isolated test; non-str cvss_vector→None; comment; %2E/IDNA-dot onion host normalisation; commits 32dca4a..d119946)
Task 2: minor (deferred, security review should look): validate_http_url onion check is not full UTS46 — default-ignorable code points (soft hyphen, ZWSP, U+034F, variation selectors) inside "onion" still pass; frontend safeHref (WHATWG) is the second layer.
Task 2: complete (commits 4b7ac68..d119946, review clean)
BASE for T3: d119946
T3 implementer DONE_WITH_CONCERNS 7f02141: collectors tests 293 passed, 4 errors = DB connection timeouts (test PG 5434 container gone — `docker ps -a` shows no cvenom-testpg-*). New DB test test_kev_rerun_backfills_existing_row + full suite UNVERIFIED. Messaged controller (main). Pending DB verification: T3.
Controller recreated cvenom-testpg-5434; order stays T4→T5→T6 before frontend. Never touch cvenom-dev-* (user's dev stack on 5432). T3 implementer resumed to run DB verification.
T3 DB verification after PG restore: collectors 297 passed, full suite 1172 passed (no fix needed).
T3 review (sonnet): spec ❌/Needs fixes — 3 Important: NVD lastModified drops record; _cwes/_refs raise on malformed shapes; duplicated _date/_str/ransomware helpers. Fix round 1 → resume ad4cac08fc875fc66.
Task 3: minor (deferred): V3.0 fallback not covered by a test.
Task 3: fix round 1/5 (3 addressed, 0 open — tolerant lastModified; guarded _cwes/_refs; helpers in collectors/base.py; commits 7f02141..e7f7731)
Task 3: minor (deferred, final review to check): NVD _cwes passes non-str description "value" (e.g. 5) and _refs unchecked url/tags types to NormalizedCve — whether its validators drop or raise (record loss) is unverified.
Task 3: complete (commits d119946..e7f7731, review clean)
BASE for T4: e7f7731
T4 implementer a5fa9f3a03c4d62c6 (opus) DONE 128fe6b (ransomware+geo 76 passed; full 1219 passed).
Ruling: R3 keep the T4 implementer's extra guard that stores details.website as None when it contains ".onion"/"%2eonion" — the spec's goal is "no .onion anywhere" and website is display-only text, so dropping a leak-site-looking value is defence in depth — cost if wrong: a victim whose site text mentions .onion shows no website line in the drawer.
T4 review (opus): spec ✅, Needs fixes — 1 Important: R3 website .onion guard bypassed by &#46;/&period;/fullwidth dot (ingest decodes entities → stored .onion). Fix round 1 → resume a5fa9f3a03c4d62c6 (+ minor 1: onion-bearing permalink path/query falls back to id).
T4 ⚠️ legacy story rows matched via content_hash fallback: covered by migration 0006 deleting non-permalink ransomware.live stories (Task 2) — no action.
Task 4: minor (deferred): story-validation failure now also drops the geo event (matches "skipped entirely"), not pinned by a test.
Task 4: minor (deferred): no test asserts the skip warning carries no record data; fragile "ransom'" string assertion in test.
Task 4: minor (deferred): ruff not installed in backend venv — lint not run on backend changes.
Task 4: fix round 1/5 (2 addressed, 0 open — shared normalize_onion_text/contains_onion before website check; onion-bearing permalink falls back to id; commits 128fe6b..4ac4af8)
Task 4: minor (deferred, final-review candidate): contains_onion runs NFKC on an uncapped website/permalink string — ~1M expanding chars could stall the worker for minutes; cap length (~2K) before the check.
Task 4: minor (deferred): press URLs like http://x.onion&#46;/ pass validate_http_url (hostname "x.onion&") — press not filtered with contains_onion.
Task 4: complete (commits e7f7731..4ac4af8, review clean)
BASE for T5: 4ac4af8
T5 implementer a5e5fe71b599b1c53 (sonnet) DONE f968cd6 (tests/api 308; full 1259). Commit carried a "Claude Sonnet 5.5" trailer, contrary to hard rule; controller amended trailer only (tree identical) → 5a8c1b4. (--no-verify was passed by mistake; repo has no hooks, so no effect.)
T5 reviewer (sonnet) dispatched on review-4ac4af8..f968cd6.diff (head 5a8c1b4).
T5 review (sonnet): spec ✅, Approved. 1 Important (plan-mandated): CACHE_PATHS["/api/stories"] allows free-text `source` (≤64), so distinct strings create distinct anon cache keys.
Ruling: R4 keep the plan's /api/stories cache allow-list including `source` — the plan explicitly lists it; each entry is ~100 B of empty result, 30 s TTL, created only after the anon per-IP rate limit, so Redis growth is bounded by request rate; only unbounded free text (`q`) was the plan's concern — cost if wrong: an anonymous caller can churn short-lived cache keys at the read rate limit; fix is one line (drop `source` from the allow-list).
Task 5: minor (deferred): test_history_api imports helpers from test_read_api (no __init__/conftest) — fragile under import modes.
Task 5: minor (deferred): private _escape_like imported across modules; no test for anon hiding of `ransomware_live` underscore spelling in stories; no kev_from/kev_to+lane or invalid-date 422 test.
Task 5: complete (commits 4ac4af8..5a8c1b4, review clean — 1 Important ruled R4)
BASE for T6: 5a8c1b4
T6 implementer a63849d9739c1e6ce DONE 3d08815 (country tests 12; full 1271). Stray no-op sed -i on its own uncommitted test file (no effect) — noted.
T6 review (sonnet): spec ✅, Approved, 0 Crit/0 Imp. Trend hour-alignment vs counts window: harmless (trend total ≤ counts); frontend must not assert sum(trend)==total.
Task 6: minor (deferred): no test that an authed call doesn't poison the anon cache (middleware does bypass); trend test doesn't pin last bucket; import order (ruff I001 likely); timezone.utc vs UTC.
Task 6: complete (commits 5a8c1b4..3d08815, review clean)
BASE for T7: 3d08815
T7 implementer ad7d8ee447ef6adf4 (sonnet) DONE eaae384 (vitest 632 passed/5 skipped; lint+typecheck clean). Touched DrawerHost (country→null placeholder), CommandBar.test, Drawer.test fixture to stay green.
T7 reviewer ae39034b4502e75aa (opus) dispatched on review-3d08815..eaae384.diff.
User asked (mid-run) for a subagent per open task.
Ruling: R5 run Task 11 (OSV, backend-only files) in parallel with the frontend Tasks 8–10, but keep Tasks 8→9→10 sequential — T8/T9/T10 share harness.ts, smoke.spec.ts, drawer.css, Drawer.test.tsx and build on each other's output, while T11 shares no file with them and frontend tests don't use the test DB; concurrent commits are handled by path-only staging and index.lock retry — cost if wrong: an index.lock collision or a commit that picks up the other agent's file, detectable in review packages; the remedy is a follow-up commit.
T11 implementer a765ea7f8d6958a26 (sonnet) dispatched in parallel, BASE eaae384 (backend files only).
T7 review (opus): spec ✅, Approved, 0 Crit/0 Imp. ⚠️ dist allow-list scan skipped (no dist) — carried to T8 (must run build + project.test after refLinks gains a consumer).
Task 7: minor (deferred): stale test name live.test.tsx:193 ("stories -> loud only") contradicts code; stale selection.ts doc comments (:557,:571) omit ?country=; refLinks imports CVE_ID_RE from router-importing selection.ts; future kev_added counts toward 7-day span.
Task 7: complete (commits 3d08815..eaae384, review clean)
BASE for T8: eaae384 (T11 committing concurrently; T8 review package must exclude T11 commits)
T11 implementer DONE 02b101d (collectors 365; full 1280). Streams via new base.http_stream_lines. T11 reviewer (sonnet) dispatched on review-task11-02b101d.diff.
T11 review (sonnet): Needs fixes — 1 Important: http_stream_lines retries after bytes were yielded (duplicates lines, resets budget → up to 3x cap). Fix round 1 → resume a765ea7f8d6958a26 (+ minor 1 import order, minor 2 quadratic pending split).
Task 11: minor (deferred): no test that the response closes on early exit; budget counts decoded (gzip-expanded) bytes, undocumented; parse_index now test-only.
T11 fix round 1 DONE e615e77 (test_base+test_osv 69; full 1283). Re-review (sonnet) dispatched on review-task11-fix1-e615e77.diff.
Task 11: fix round 1/5 (3 addressed, 0 open — no retry after first chunk; import order; linear split; commits 02b101d..e615e77)
Task 11: complete (commits 02b101d, e615e77 — interleaved with T8 work; review clean)
T8 implementer ae383ec0573e1839e DONE a0a503c (vitest 653/5 skipped; e2e 16+16; build clean; dist scan ran+passed; refLinks still unconsumed → T9). Added historyShared.tsx and .cnav in shell.css.
T8 review (sonnet): ❌/Needs fixes — 3 Important: sort default ignores lane (plan-mandated wording); vacuous /EPSS pd/ assertion; Stories source blur drops page. Fix round 1 → resume ae383ec0573e1839e (+ minor .cnav mobile rule).
Ruling: R6 History's default sort mirrors the backend — "Newest KEV listing" only when KEV-only is on AND no lane is set, else "Newest published" — the spec's intent is that the label shows the order the user actually gets, and the backend (T5) keeps lane order unless sort is explicit — cost if wrong: with a lane plus KEV-only the default shows published order and the user must pick "Newest KEV listing" explicitly.
Task 8: minor (deferred): Stories source input uncommitted text lost on tab switch (accepted design); OutOfRange link hardcodes /history.
Task 8: fix round 1/5 (4 addressed, 0 open — sort default kev&&!lane (R6); /EPSS p\d/ regex; source blur keeps page; .cnav mobile; commits a0a503c..d5c0e9e). e2e 16+16 reported in implementer's reply (report file lacks it).
Task 8: complete (commits a0a503c..d5c0e9e on top of eaae384; review clean)
BASE for T9: d5c0e9e
T9 implementer a44b77ca9ed5224f6 (sonnet) BLOCKED: worktree found mid-merge of origin/main (MERGE_HEAD fb4ade7, MERGE_MSG "Merge branch 'main' of https://github.com/dpinse/CVEnom into feat/radar-refinements") — not started by this track (reflog ends at d5c0e9e). 7 conflicted frontend files. T9 uncommitted work: e2e/drawer-overflow.spec.ts (new, unrun), e2e/fixtures/story.json (new), e2e/harness.ts (/api/story route).
STOP (outside-worktree-scope decision): messaged controller with options (a) they finish/abort, (b) I abort, (c) I resolve. Holding T9.
Controller: user chose (c) — resolve the user-started merge of origin/main (fb4ade7) inside this track. Opus merge implementer dispatched (resolve 7 files, prettier, all gates, commit without -a, preserve T9 WIP in worktree, backup in task9-wip/). Next: opus reviewer on conflict resolutions, then T9, T10, final etc.
Merge DONE 22e44d3 (backend 1293; vitest 672/3 skip; e2e 19+19; lint/typecheck/format:check/build clean). T9 WIP intact & uncommitted. Merge reviewer (opus) next.
Merge review (opus): Approved, 0 issues — all 7 conflicts were main-side Prettier-only; branch versions kept & reformatted; Search.* removed cleanly; 7 branch-only files reformatted (formatting-only, needed for main's format:check); no main work reverted; T9 WIP excluded.
Merge: complete (22e44d3). Gates now include format:check.
T9 resumed (a44b77ca9ed5224f6) on BASE 22e44d3.
T9 DONE 3f7c9f6 (vitest 679/3; e2e 23+23=46; lint/typecheck/format/build clean; dist scan passed). Overflow element: span.chip.quiet (reference tag, global .chip nowrap).
T9 reviewer (sonnet) dispatched on review-22e44d3..3f7c9f6.diff.
T9 review (sonnet): ❌/Needs fixes — 2 Important: Scores section never omitted for all-NULL rows; ?story=<.onion> opens no drawer (plan focus says "not found") and untested. Fix round 1 → resume a44b77ca9ed5224f6.
Ruling: R7 any present-but-unsafe ?story= param (.onion, javascript:, malformed) opens the story drawer in the not-found state without calling /api/story and never echoes the URL — the plan's Review Focus explicitly wants "not found" for old .onion links and a silent no-op looks broken; skipping the fetch keeps the unsafe string off the network — cost if wrong: a javascript: link now shows a not-found drawer instead of nothing (still no anchor, no echo).
Task 9: minor (deferred): CWE ExternalLink relies on href "" degrading to text (tested, indirect).
Task 9: fix round 1/5 (2 addressed, 0 open — Scores omitted when no score data; unsafe ?story= → not-found drawer, no fetch, no echo (R7); commits 3f7c9f6..b887ac7)
Task 9: minor (deferred): unsafe-story test's toHaveTextContent("") is vacuous; ?story=<bad>&country=XX now resolves to story not-found rather than country.
Task 9: complete (commits 22e44d3..b887ac7, review clean)
BASE for T10: b887ac7
T10 implementer a94d37f504e43eb20 DONE 1e237ac (vitest 693/3; e2e 26+26; gates clean). Back/forward e2e uses programmatic el.click() on hotspot (main is inert under open drawer).
T10 review (sonnet): ❌/Needs fixes — 1 Important: back/forward Review Focus e2e uses programmatic el.click() on an inert element; no real CVE→country path exists. Fix round 1 → resume a94d37f504e43eb20 (+ minors: trend isFinite guard, omit rejected story_url text, Enter-coverage comment).
Ruling: R8 add country chips (buttons → select country) to the CVE drawer's existing Geo activity section and make the back/forward e2e use real clicks — the plan's focus item explicitly says "CVE → country → story through chips and hotspots", and with the drawer making the page inert, a chip inside the drawer is the only reachable path — cost if wrong: a small extra UI affordance in the CVE drawer the spec didn't list by name.
Task 10: minor (deferred): unverified useGlobe() stability (flyTo may re-fire per render); focus return to hotspot button after Esc untested.
Task 10: fix round 1/5 (4 addressed, 0 open — CVE drawer country chips + real-click back/forward e2e (R8); trend isFinite; rejected story_url omitted; Enter-coverage comment; commits 1e237ac..8d91c9a)
Task 10: minor (deferred): chip test doesn't assert QQ renders as text.
Task 10: complete (commits b887ac7..8d91c9a, review clean)
ALL TASKS (1–11) COMPLETE. Final review next.
Final review (opus) a867dd5940fbb8b8b dispatched on review-fb4ade7..8d91c9a.diff (merge-base with origin/main).
Final review (opus): Ready to merge "With fixes" — 0 Critical, 2 Important: (1) ?story= stores WHATWG-normalised href but /api/story exact-matches raw stored URL → not-found regression for non-canonical URLs; (2) entity-obfuscated .onion press/reference URLs (http://x.onion&#46;/) accepted at ingest and echoed as text in StoryDetail/CveDetail. Minors 1–7. Rulings R1–R8 + T11 all "Agree". Deferred minors triaged: T4 press onion → fix-before-merge; T3 non-str cwes/refs & T10 useGlobe stability → closed (resolved); rest stay-deferred.
Ruling: R9 keep Situation's 7-day span as kev_added >= isoDate(now − 7 days) (8 calendar dates incl. today) — the plan states this formula and its boundary test (2026-10-29 at 11-05T23:30Z counts) — cost if wrong: High/Severe trigger on one extra day of listings; one-line change.
Fix wave scope: Important 1, 2; minors 1 (out-of-range shows real total — plan focus), 2 (dead description branch), 5 (OSV truncation must not advance window), 7 (import order), plus T4 deferred cap website/permalink length before contains_onion. Minors 3 (R9), 4 (indexes), 6 (sort memory) stay deferred.
Fix wave DONE 8d4da5c, 3d19dcf (backend 1310; vitest 698/3; e2e 26+26; gates clean). Onion rule: host of entity-decoded form (narrower than whole-string). OSV truncation keeps a backlog in collector state.
Fix-wave re-review (opus) ab118d01d2a6653f2 + security review (opus) a2594f176a59f6f00 dispatched in parallel (both read-only).
Fix-wave re-review (opus): I1, I2-frontend, M1, M2, M5, M7, T4-cap ADDRESSED; I2-backend NOT ADDRESSED — validate_http_url's decoded check ignores sanitize_text's bleach tag/comment stripping, so http://x.onion&lt;b&gt;/, http://x<b>.onion</b>/, http://x.on<i>ion</i>/ are accepted and stored as a .onion host (frontend still blocks render). Minor: OSV backlog merge refetches a covered gap once.
Holding the I2-backend residual adjudication until the security review returns, to batch with any security findings.
Security review (opus): 0 High, 1 Medium, 2 Low, 5 Info. M1 = same as fix-wave I2-backend residual (tag/comment markup splits .onion past validate_http_url and the website guard; bleach strip at ingest stores .onion; frontend never links it). L1: validate_http_url has no length cap (NFKC super-linear; 1M-char host 211 s). L2: default-ignorable code points in website text display as a .onion name. Access control, cache, rate-limit order, SQL filtering, identical 404s, SSRF, XSS, allow-list, migration 0006: clean.
Ruling: R10 one targeted hardening commit after the single fix wave (the residual is load-bearing: spec E "no .onion anywhere" + hard rule "backend rejects the same hosts", security-sensitive, and the fix is ~10 lines) — validate_http_url rejects '<' '>' '"' '`' in raw and entity-decoded forms and any URL > 2048 chars; the ransomware website guard runs contains_onion on the sanitize_text'd value with default-ignorable code points (Cf, U+034F, U+180B–180F, U+FE00–FE0F) removed; tests for every probed case; scoped opus re-review — cost if wrong: a legitimate URL containing a literal < > " ` or longer than 2048 chars is dropped at ingest (such URLs are invalid unencoded anyway).
R10 hardening DONE 4517256 (backend 1336 passed; RED 21 failed + timing hang on old code).
R10 re-review (opus): M1, L1, L2 ADDRESSED; no new breakage; call sites lose no legitimate data. Residual Low: U+E0100–E01EF variation selectors (Mn) and Hangul/Khmer fillers not stripped; bidi override (RLO) in website text can display as .onion.
Ruling: R11 park the residual invisible-character/bidi website-text cases (U+E0100–E01EF, U+115F/1160/17B4/17B5/3164/FFA0, U+202A–202E/2066–2069) as a follow-up — text-only, signed-in-only ransomware details, never a link (frontend safeHref UTS46-maps and rejects the URL forms), and the branch already went through its one fix wave plus R10 — cost if wrong: a signed-in user could see a website line that visually reads as a .onion name until the follow-up extends _IGNORABLE_EXTRA and rejects bidi controls (~3 lines).
FINAL STATE: HEAD 4517256. Gates: backend 1336 passed; vitest 698 passed/3 skipped; e2e chromium 26, firefox 26; lint/typecheck/format:check/build clean (frontend unchanged since 3d19dcf).
