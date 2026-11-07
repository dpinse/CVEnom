import type { CveDetail } from "../../lib/types";
import { dayOf, minuteOf } from "./format";

/** One-line verdict: exploited, deadline, public exploit, EPSS, patch, and when the data was last updated. */
export function StatusLine({ d }: { d: CveDetail }) {
  const epss = d.epss_percentile;
  return (
    <div className="panel status" data-testid="status-line">
      {d.kev ? (
        <span className="on">
          <b>Exploited</b> in the wild
        </span>
      ) : (
        <span>Not known to be exploited</span>
      )}
      {d.kev && d.kev_due ? (
        <span>
          KEV due <b className="num">{dayOf(d.kev_due) || d.kev_due}</b>
        </span>
      ) : null}
      {d.poc_badge ? (
        <span>
          <b>Public exploit</b> available
        </span>
      ) : (
        <span>No public exploit</span>
      )}
      {epss !== null && Number.isFinite(epss) ? (
        <span>
          EPSS <b className="num">p{Math.round(epss * 100)}</b> percentile
        </span>
      ) : null}
      {d.patch_available === true ? (
        <span className="ok">
          <b>Fix available</b>
        </span>
      ) : d.patch_available === false ? (
        <span className="on">
          <b>No patch</b> yet
        </span>
      ) : (
        <span>Patch status unknown</span>
      )}
      <span className="asof">Data as of {minuteOf(d.updated_at)} UTC</span>
    </div>
  );
}
