import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { AddedKey } from "../lib/types";

/** Pieces shared by the Threats tabs (CVEs and News). */
export const PAGE_SIZE = 50;
export const MAX_Q = 200;
export const DEBOUNCE_MS = 300;

/** Same trim-slice-trim for the free-text query on both tabs. */
export function cleanQ(q: string | null): string | undefined {
  const tq = q?.trim().slice(0, MAX_Q).trim();
  return tq || undefined;
}

export function parsePage(raw: string | null): number {
  if (raw !== null && /^\d+$/.test(raw)) {
    const p = Number(raw);
    if (p >= 1 && p <= 10000) return p;
  }
  return 1;
}

export type Patch = Record<string, string | undefined>;

/** Writes filter params into the URL, keeping everything else (cve / story selection, tab); resets the page. */
export function useUpdateParams() {
  const [, setSp] = useSearchParams();
  return useCallback(
    (patch: Patch, push = false) => {
      setSp(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch)) {
            if (v === undefined || v === "") next.delete(k);
            else next.set(k, v);
          }
          if (!("page" in patch)) next.delete("page");
          return next;
        },
        push ? undefined : { replace: true },
      );
    },
    [setSp],
  );
}

/**
 * The free-text box: local text, debounced into the URL (replace). An external URL change (back/forward, a link)
 * wins over local text and cancels a pending write.
 */
export function useDebouncedQ(urlQ: string, write: (q: string) => void) {
  const [qText, setQText] = useState(urlQ);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancel = () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
  };
  useEffect(() => cancel, []);
  const [seenQ, setSeenQ] = useState(urlQ);
  const [lastWritten, setLastWritten] = useState(urlQ);
  const [epoch, setEpoch] = useState(0);
  const epochRef = useRef(0);
  useEffect(() => {
    epochRef.current = epoch;
    cancel(); // a stale debounce must not fire after an external URL change
  }, [epoch]);
  if (seenQ !== urlQ) {
    setSeenQ(urlQ);
    if (urlQ !== lastWritten) {
      setLastWritten(urlQ);
      setQText(urlQ);
      setEpoch((e) => e + 1);
    }
  }
  const onChange = (v: string) => {
    const value = v.slice(0, MAX_Q);
    setQText(value);
    cancel();
    const mine = epochRef.current;
    timer.current = setTimeout(() => {
      timer.current = null;
      if (mine !== epochRef.current) return;
      const written = value.trim();
      setLastWritten(written);
      write(written);
    }, DEBOUNCE_MS);
  };
  const reset = () => {
    cancel();
    setLastWritten("");
    setQText("");
  };
  return { qText, onChange, reset };
}

/** Pager state: focus + scroll the result count after a page change. */
export function usePager(update: (patch: Patch, push?: boolean) => void) {
  const countRef = useRef<HTMLParagraphElement>(null);
  const setPage = (p: number) => {
    update({ page: p <= 1 ? undefined : String(p) }, true);
    const el = countRef.current;
    if (el) {
      el.focus({ preventScroll: true });
      const reduce =
        typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      el.scrollIntoView?.({ behavior: reduce ? "auto" : "smooth", block: "start" });
    }
  };
  return { countRef, setPage };
}

export function Pager({ page, total, setPage }: { page: number; total: number; setPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return (
    <nav className="spager" id="pager" tabIndex={-1} aria-label="Pagination">
      <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>
        Previous
      </button>
      <span className="num">
        Page {page}
        {total > 0 && page <= pages ? ` of ${pages}` : ""}
      </span>
      <button type="button" disabled={page * PAGE_SIZE >= total} onClick={() => setPage(page + 1)}>
        Next
      </button>
    </nav>
  );
}

/** Keyboard route past the filters and table: moves focus to the pagination nav. */
export function SkipToPagination() {
  return (
    <a
      className="skip-pager"
      href="#pager"
      onClick={(e) => {
        e.preventDefault();
        document.getElementById("pager")?.focus();
      }}
    >
      Skip to pagination
    </a>
  );
}

const ADDED: Record<Exclude<AddedKey, "14d">, string> = {
  any: "Added any time",
  day: "Added past day",
  week: "Added past week",
  month: "Added past month",
  "90d": "Added past 90 days",
  year: "Added past year",
};
const ADDED_KEYS = [...Object.keys(ADDED), "14d"] as AddedKey[];

/** Pure: a valid `added` param or the default. `14d` is only produced by Dashboard deep links. */
export function parseAdded(raw: string | null): AddedKey {
  return raw !== null && (ADDED_KEYS as string[]).includes(raw) ? (raw as AddedKey) : "any";
}

/** The Added window select. The 14-day option exists only while the URL holds it. */
export function AddedSelect({ value, onChange }: { value: AddedKey; onChange: (v: AddedKey) => void }) {
  return (
    <label className="f-inline">
      <span className="sr-only">Added</span>
      <select value={value} onChange={(e) => onChange(e.target.value as AddedKey)}>
        {(Object.keys(ADDED) as Exclude<AddedKey, "14d">[]).map((k) => (
          <option key={k} value={k}>
            {ADDED[k]}
          </option>
        ))}
        {value === "14d" && <option value="14d">Added past 14 days</option>}
      </select>
    </label>
  );
}

/** Shown when a page past the end returns no items although results exist. */
export function OutOfRange() {
  const [sp] = useSearchParams();
  const next = new URLSearchParams(sp);
  next.delete("page");
  const qs = next.toString();
  return (
    <p className="sempty">
      No results on this page <span aria-hidden="true">·</span>{" "}
      <Link to={{ pathname: "/threats", search: qs ? `?${qs}` : "" }}>Go to page 1</Link>
    </p>
  );
}
