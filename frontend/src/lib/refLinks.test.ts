import { expect, test } from "vitest";
import { CVE_ORG, CWE_DEF, KEV_CATALOG, NVD_DETAIL, cveOrgUrl, cweUrl, kevUrl, nvdUrl } from "./refLinks";

test("CVE links are built only for well-formed ids", () => {
  expect(nvdUrl("CVE-2026-1001")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2026-1001");
  expect(kevUrl("CVE-2026-1001")).toBe(`${KEV_CATALOG}CVE-2026-1001`);
  expect(cveOrgUrl("CVE-2026-1001")).toBe(`${CVE_ORG}CVE-2026-1001`);
  for (const bad of ["x", "", "CVE-2026-1", "CVE-2026-1001/../x", "cve-2026-1001", "CVE-2026-1001&x=1"]) {
    expect(nvdUrl(bad), bad).toBeNull();
    expect(kevUrl(bad), bad).toBeNull();
    expect(cveOrgUrl(bad), bad).toBeNull();
  }
});

test("CWE links only for CWE-<digits>", () => {
  expect(cweUrl("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
  expect(CWE_DEF).toBe("https://cwe.mitre.org/data/definitions/");
  expect(NVD_DETAIL).toBe("https://nvd.nist.gov/vuln/detail/");
  for (const bad of ["NVD-CWE-Other", "NVD-CWE-noinfo", "CWE-", "CWE-1234567", "CWE-7/9", "CWE-79x", ""])
    expect(cweUrl(bad), bad).toBeNull();
});
