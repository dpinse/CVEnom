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
    const url = safeHref(story);
    // An unsafe `?story=` (.onion, javascript:, malformed) still opens the drawer, in its not-found state (url null).
    return { kind: "story", url };
  }
  const country = sp.get("country");
  if (country !== null && isIso3166Alpha2(country)) return { kind: "country", cc: country };
  return null;
}

/** Reads and writes the drawer selection through `?cve=` / `?story=`. */
export function useSelection() {
  const [sp, setSp] = useSearchParams();
  const selection = useMemo(() => parseSelection(sp), [sp]);
  const select = useCallback(
    (s: Selection | null, opts?: { replace?: boolean }) => {
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.delete("cve");
          next.delete("story");
          next.delete("country");
          if (s?.kind === "cve" && CVE_ID_RE.test(s.id)) next.set("cve", s.id);
          else if (s?.kind === "story") {
            const url = s.url === null ? null : safeHref(s.url);
            if (url !== null) next.set("story", url);
          } else if (s?.kind === "country" && isIso3166Alpha2(s.cc)) next.set("country", s.cc);
          return next;
        },
        opts?.replace ? { replace: true } : undefined,
      );
    },
    [setSp],
  );
  /** Closes the drawer with `replace` history so Back does not re-open it. */
  const clear = useCallback(() => select(null, { replace: true }), [select]);
  return { selection, select, clear };
}
