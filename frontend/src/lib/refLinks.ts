import { CVE_ID_RE } from "./selection";

/** Reference-link prefixes. Each is one complete string literal (see the allow-list in project.test.ts). */
export const NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/";
export const KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=";
export const CVE_ORG = "https://www.cve.org/CVERecord?id=";
export const CWE_DEF = "https://cwe.mitre.org/data/definitions/";

const build = (prefix: string, id: string): string | null => (CVE_ID_RE.test(id) ? prefix + id : null);

export const nvdUrl = (id: string): string | null => build(NVD_DETAIL, id);
export const kevUrl = (id: string): string | null => build(KEV_CATALOG, id);
export const cveOrgUrl = (id: string): string | null => build(CVE_ORG, id);

/** `CWE-79` -> its MITRE definition page; anything else (NVD-CWE-Other, ...) -> null. */
export function cweUrl(cwe: string): string | null {
  const m = /^CWE-(\d{1,6})$/.exec(cwe);
  return m ? `${CWE_DEF}${m[1]}.html` : null;
}
