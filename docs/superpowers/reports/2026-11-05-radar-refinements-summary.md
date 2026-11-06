# Radar refinements summary (spec A–E, plus OSV fix)

**Branch:** `feat/radar-refinements`, local only: nothing is pushed and `main` is untouched. The range is `edf2dfb..4517256` (plus this report commit).

Mid-run, the user pulled `origin/main` (fb4ade7, PR #6) into the branch. That merge, **22e44d3**, was resolved inside this track and reviewed (Approved). The diff against main is therefore `fb4ade7..HEAD`. Migration **0006** still has `down_revision = "0005"`, and main added no migrations.

**Result:**
- **Tasks:** all 10 plan tasks are done, plus Task 11, which the controller added (the OSV collector). Each passed its own spec-and-quality review, with at most one fix round per task.
- **Final review:** the whole-branch final review (opus) said "With fixes", with 0 Critical and 2 Important findings.
  - One fix wave handled the 2 Important items plus 5 minors.
  - The scoped re-review left one backend `.onion` gap open. It was the same issue as the security review's Medium.
- **Security review:** 0 High, 1 Medium and 2 Low findings. Ruling R10 fixed the Medium and both Lows in one targeted commit, **4517256**, and the scoped opus re-review marked all three ADDRESSED. One text-only Low is accepted as a follow-up (R11).

**Tests at HEAD:**
- backend: 1336 passed (`PGHOSTADDR=127.0.0.1 CVENOM_TEST_PG_PORT=5434`);
- frontend unit tests: vitest 698 passed, 3 skipped;
- e2e: 26 on chromium and 26 on firefox;
- lint, typecheck, `format:check` and build are clean, and the dist URL allow-list scan passes.

## What changed
- **A. Lane windows:**
  - Exploited covers KEV listings from the last 30 days, judged by the UTC date and shown newest listing first.
  - Likely covers CVEs published in the last 30 days with high EPSS.
  - `/api/lanes`, `/api/cves?lane=` and Situation all agree.
  - Situation is recalibrated: Severe, High, Elevated and Calm by recent KEV listings.
  - A quiet month shows "No new KEV listings in the last 30 days", with a link to History.
- **B. History:**
  - `/history` replaces `/search` (the old path redirects), with CVE and Stories tabs.
  - New: a KEV-added date range, a sort control, and `/api/stories` search. Restricted sources are filtered in SQL before LIMIT and in the count. Free-text `q` bypasses the anonymous cache.
  - Paging past the end shows the real total with a link back to page 1.
- **C. Country drawer:**
  - `GET /api/geo/{cc}` returns counts, top sources and an hourly trend. Individual events go to signed-in users only, so the anonymous cached body carries no records.
  - The drawer opens from a globe click, from the keyboard hotspot list, and from the new country chips in the CVE drawer.
  - Back and forward between drawers works, with one dialog at a time.
- **D. Richer detail:**
  - Migration 0006 adds the KEV name, action, due date, ransomware use and notes, and the NVD vector, severity, CWEs, references and last-modified fields. It also adds `story.details`.
  - The collectors fill these fields.
  - The CVE drawer has 10 sections, and empty sections are omitted. It links to NVD, CISA KEV, cve.org and CWE.
  - A richer story drawer is served by the new `/api/story`.
  - The drawer overflow is fixed: the cause was the `nowrap` reference-tag chip.
- **E. No `.onion`:**
  - `safeHref` and `validate_http_url` reject `.onion` hosts, including percent-encoded, IDNA-dot, entity and markup obfuscation, plus over-long URLs.
  - ransomware.live stories are keyed on the permalink, and `post_url` and `screenshot` are never read.
  - Migration 0006 deletes non-permalink ransomware.live stories and `.onion` stories, and nulls `.onion` geo `story_url`s. The deleted rows can't be restored.
  - Unsafe links render as "link removed" or nothing, never as URL text. An unsafe `?story=` shows "not found", with no fetch and no echo of the URL.
- **Task 11, OSV:**
  - The collector streams `modified_id.csv` and stops at the window cutoff, staying under the existing 25 MB cap. Before this, the 157 MB index failed every run.
  - It never retries after body bytes have arrived.
  - When a run is truncated it keeps a backlog, so older items are not skipped.

## Decisions that need you
1. **The merge of main lives in this branch (22e44d3).** When you open the PR, it will contain that merge commit.
2. **The MFA branch's 0007** still has to be relinked onto 0006, as planned.
3. **Ruling R11**, the follow-up for accepted residual characters in the ransomware Website text: the variation-selector supplement, the Hangul/Khmer fillers and bidi controls. It is about 3 lines, and the issue is text-only and signed-in only.
4. **Backend lint has never run.** ruff is not installed in the venv and the repo has no ruff config, so import order was checked by hand.
5. **Deferred minors, triaged as non-blocking by the final review:** these are listed in the ledger. They include story-search indexes (pg_trgm) and `ix_cve_kev_added`, the sort selector forgetting an explicit default, and the stale `live.test` name.

The full decision record, including every `Ruling:` from R1 to R11 and the Task 11 ruling, is in `2026-11-05-radar-refinements-ledger.md`. The security detail is in `2026-11-05-radar-refinements-security-review.md`.
