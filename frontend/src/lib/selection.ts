import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { isIso3166Alpha2 } from "./iso3166";
import { safeHref } from "./text";

export type Selection =
  { kind: "cve"; id: string } | { kind: "story"; url: string | null } | { kind: "country"; cc: string };

export const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/;

/** Pure parser: validates `cve` and `story` params; anything invalid is ignored. */
export function parseSelection(sp: URLSearchParams): Selection | null {
  const cve = sp.get("cve");
  if (cve !== null && CVE_ID_RE.test(cve)) return { kind: "cve", id: cve };
  const story = sp.get("story");
  if (story !== null) {
    // safeHref is only a gate: the backend exact-matches the stored Story.url, so keep the original string (URL.href
    // would normalise case, ports and percent-encoding). An unsafe `?story=` (.onion, javascript:, malformed) still
    // opens the drawer, in its not-found state (url null).
    return { kind: "story", url: safeHref(story) !== null ? story : null };
  }
  const country = sp.get("country");
  if (country !== null && isIso3166Alpha2(country)) return { kind: "country", cc: country };
  return null;
}

/** `?country=` as a validated ISO-2 code, or null. Independent of the drawer: a CVE can be open over a country. */
export function parseCountry(sp: URLSearchParams): string | null {
  const c = sp.get("country");
  return c !== null && isIso3166Alpha2(c) ? c : null;
}

/**
 * Reads and writes the selection through `?cve=` / `?story=` (the drawer) and `?country=` (the dashboard side panel).
 * Selecting or closing a CVE or story keeps `?country=`, so opening a CVE from the country panel preserves it (R7).
 */
export function useSelection() {
  const [sp, setSp] = useSearchParams();
  const selection = useMemo(() => parseSelection(sp), [sp]);
  const country = useMemo(() => parseCountry(sp), [sp]);
  const select = useCallback(
    (s: Selection | null, opts?: { replace?: boolean }) => {
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete("cve");
          next.delete("story");
          if (s?.kind === "cve" && CVE_ID_RE.test(s.id)) next.set("cve", s.id);
          else if (s?.kind === "story") {
            // Write the original string (see parseSelection); safeHref only decides whether it is written at all.
            if (s.url !== null && safeHref(s.url) !== null) next.set("story", s.url);
          } else if (s?.kind === "country") {
            next.delete("country");
            if (isIso3166Alpha2(s.cc)) next.set("country", s.cc);
          }
          return next;
        },
        opts?.replace ? { replace: true } : undefined,
      );
    },
    [setSp],
  );
  /** Closes the drawer with `replace` history so Back does not re-open it. Keeps `?country=`. */
  const clear = useCallback(() => select(null, { replace: true }), [select]);
  /** Back to the "Top countries" list. */
  const clearCountry = useCallback(
    () =>
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete("country");
          return next;
        },
        { replace: true },
      ),
    [setSp],
  );
  return { selection, country, select, clear, clearCountry };
}
