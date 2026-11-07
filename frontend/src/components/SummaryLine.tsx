import { Link } from "react-router-dom";
import { useSummary } from "../lib/queries";
import { RANGE_LABEL, type RangeKey } from "../lib/range";

/** Dashboard range -> Threats `added` filter, so each count equals the list its link opens (R6/R19). */
const ADDED: Record<RangeKey, string> = { "24h": "day", "7d": "week", "14d": "14d", "30d": "month" };

export function summaryHrefs(range: RangeKey) {
  const added = ADDED[range];
  return {
    kev: `/threats?status=exploited&added=${added}`,
    due: "/threats?due=7d",
    critical: `/threats?status=critical&exclude_kev=1&added=${added}`,
    exploits: `/threats?poc=1&added=${added}`,
  };
}

/** `Last 7 days` and the four counts for the range, each a link to the Threats list that shows exactly those CVEs. */
export function SummaryLine({ range }: { range: RangeKey }) {
  const q = useSummary(range);
  const d = q.data;
  const href = summaryHrefs(range);
  const n = (v: number | undefined) => (d && Number.isFinite(v) ? String(v) : "–");
  return (
    <div className="today" aria-busy={q.isPending}>
      <h1>Last {RANGE_LABEL[range]}</h1>
      <Link to={href.kev}>
        <b className={d && d.new_kev > 0 ? "hot" : undefined}>{n(d?.new_kev)}</b>
        <span>new KEV listings</span>
      </Link>
      <Link to={href.due}>
        <b>{n(d?.kev_due_soon)}</b>
        <span>KEV deadlines this week</span>
      </Link>
      <Link to={href.critical}>
        <b>{n(d?.new_critical)}</b>
        <span>new critical CVEs</span>
      </Link>
      <Link to={href.exploits}>
        <b>{n(d?.public_exploits)}</b>
        <span>public exploits published</span>
      </Link>
    </div>
  );
}
