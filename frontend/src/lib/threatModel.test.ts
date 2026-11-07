import { describe, expect, test } from "vitest";
import { headline, ladderStages, offsetLabel, timelineRows, versionText } from "./threatModel";
import type { AffectedVersion, CveDetail, CveEvent } from "./types";

const T0 = "2026-11-03T10:00:00Z";
const plus = (h: number) => new Date(Date.parse(T0) + h * 36e5).toISOString();

describe("offsetLabel", () => {
  test.each([
    [T0, "t = 0"],
    [plus(5), "+5h"],
    [plus(-9 * 24), "−9d"],
    [plus(47), "+47h"],
    [plus(48), "+2d"],
    [plus(-47), "−47h"],
    [plus(72), "+3d"],
  ])("%s -> %s", (at, want) => {
    expect(offsetLabel(at, T0)).toBe(want);
  });
});

const ev = (kind: CveEvent["kind"], occurred_at: string, source = "NVD"): CveEvent => ({
  kind,
  occurred_at,
  source,
  detail: {},
});

describe("timelineRows", () => {
  const events = [
    ev("first_news", plus(30), "Example News"),
    ev("kev_added", plus(24 * 5), "CISA KEV"),
    ev("published", T0),
    ev("first_news", plus(10), "Other News"),
    ev("reserved", plus(-9 * 24), "CVE.org"),
  ];
  test("is chronological, keeps only the earliest first_news, and names each source", () => {
    const rows = timelineRows(events, T0);
    expect(rows.map((r) => [r.label, r.source, r.offset])).toEqual([
      ["CVE ID reserved", "CVE.org", "−9d"],
      ["Published", "NVD", "t = 0"],
      ["First news coverage", "Other News", "+10h"],
      ["Added to KEV, exploited in the wild", "CISA KEV", "+5d"],
    ]);
  });
  test("marks the key rows", () => {
    const keys = timelineRows(events, T0)
      .filter((r) => r.key)
      .map((r) => r.label);
    expect(keys).toEqual(["Published", "Added to KEV, exploited in the wild"]);
  });
  test("has no offsets without a publication time", () => {
    expect(timelineRows(events, null).every((r) => r.offset === null)).toBe(true);
  });
});

const detail = (o: Partial<CveDetail> = {}): CveDetail =>
  ({
    cve_id: "CVE-2026-1001",
    cvss: 9.8,
    epss_percentile: 0.9,
    kev: false,
    kev_added: null,
    kev_source: null,
    poc_badge: false,
    patch_available: null,
    published: T0,
    summary: "",
    recent_story_count: 0,
    product: null,
    last_seen: null,
    epss: null,
    affected: [],
    stories: [],
    geo_events: [],
    kev_name: null,
    kev_action: null,
    kev_notes: null,
    kev_due: null,
    kev_ransomware: null,
    cvss_vector: null,
    cvss_severity: null,
    cwes: [],
    references: [],
    last_modified: null,
    events: [],
    affected_versions: [],
    related: [],
    geo_top: [],
    updated_at: T0,
    ...o,
  }) satisfies CveDetail;

describe("ladderStages", () => {
  test("a KEV and ransomware record reaches disclosed, exploited and ransomware", () => {
    const s = ladderStages(
      detail({
        kev: true,
        kev_source: "cisa",
        kev_added: "2026-11-04",
        kev_ransomware: true,
        events: [ev("published", T0)],
      }),
    );
    expect(s.map((x) => x.name)).toEqual([
      "Disclosed",
      "Detectable",
      "Public exploit",
      "Exploited in the wild",
      "Ransomware use",
    ]);
    expect(s.map((x) => x.reached)).toEqual([true, false, false, true, true]);
    expect(s[0].evidence).toBe("2026-11-03 · NVD");
    expect(s[3].evidence).toBe("CISA KEV · 2026-11-04");
    expect(s[4].evidence).toBe("KEV: known");
  });
  test("uses the earliest event per kind", () => {
    const s = ladderStages(
      detail({ events: [ev("poc_published", plus(48), "GitHub"), ev("poc_published", plus(24), "Exploit-DB")] }),
    );
    expect(s[2]).toEqual({ name: "Public exploit", reached: true, evidence: "Exploit-DB · 2026-11-04" });
  });
  test("a nuclei-templates reference makes it detectable; lookalike hosts do not", () => {
    const ref = (url: string) => detail({ references: [{ url, tags: [] }] });
    const good = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1001.yaml";
    expect(ladderStages(ref(good))[1]).toEqual({ name: "Detectable", reached: true, evidence: "Nuclei template" });
    expect(ladderStages(ref("https://evil.example/github.com/projectdiscovery/nuclei-templates/x"))[1].reached).toBe(
      false,
    );
    expect(ladderStages(ref("https://github.com/other/nuclei-templates/x"))[1].reached).toBe(false);
  });
  test("a detection event makes it detectable; no data reads as absent", () => {
    expect(ladderStages(detail({ events: [ev("detection", plus(3), "Nuclei")] }))[1].reached).toBe(true);
    const none = ladderStages(detail());
    expect(none.slice(1).map((x) => x.evidence)).toEqual(["Not yet", "None found", "No reports", "Not known"]);
  });
});

describe("versionText", () => {
  const v = (o: Partial<AffectedVersion>): AffectedVersion => ({
    product: "P",
    vendor: null,
    ecosystem: null,
    introduced: null,
    fixed: null,
    last_affected: null,
    source: "OSV",
    ...o,
  });
  test.each([
    [{ introduced: "1.0", fixed: "1.4" }, "from 1.0 before 1.4", "1.4"],
    [{ fixed: "1.4" }, "before 1.4", "1.4"],
    [{ introduced: "1.0", last_affected: "1.3" }, "from 1.0 through 1.3", "No fix listed"],
    [{ introduced: "1.3", last_affected: "1.3" }, "1.3", "No fix listed"],
    [{ last_affected: "1.3" }, "through 1.3", "No fix listed"],
    [{}, "all versions", "No fix listed"],
  ])("%j", (o, affected, fixed) => {
    expect(versionText(v(o))).toEqual({ affected, fixed });
  });
});

describe("headline", () => {
  test("product plus the first sentence, decoded once", () => {
    expect(headline(detail({ product: "Acme Gateway", summary: "Auth bypass &amp; more. Second sentence." }))).toBe(
      "Acme Gateway: Auth bypass & more",
    );
  });
  test("cuts at 140 characters when there is no sentence end", () => {
    expect(headline(detail({ summary: "x".repeat(300) }))).toBe("x".repeat(140));
  });
  test("falls back to the product, then the id", () => {
    expect(headline(detail({ product: "Acme", summary: "" }))).toBe("Acme");
    expect(headline(detail())).toBe("CVE-2026-1001");
  });
});
