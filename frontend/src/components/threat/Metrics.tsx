import { decodeCvss } from "../../lib/cvssVector";
import type { CveDetail } from "../../lib/types";
import { severityOf } from "../LaneRow";
import { dayOf } from "./format";

const SEV_WORD = { crit: "critical", high: "high", med: "medium", low: "low" } as const;

function Cell({ label, value, note, tone }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <div className="metric">
      <span className="lbl">{label}</span>
      <span className={`val${tone ? ` ${tone}` : ""}`}>{value}</span>
      <span className="note">{note}</span>
    </div>
  );
}

export function Metrics({ d }: { d: CveDetail }) {
  const cvss = d.cvss !== null && Number.isFinite(d.cvss) ? d.cvss : null;
  const sev = severityOf(cvss);
  const version = d.cvss_vector ? decodeCvss(d.cvss_vector)?.version : undefined;
  const epss = d.epss !== null && Number.isFinite(d.epss) ? d.epss : null;
  const pct = d.epss_percentile !== null && Number.isFinite(d.epss_percentile) ? d.epss_percentile : null;
  return (
    <div className="panel metrics" data-testid="metrics">
      <Cell
        label={version ? `CVSS ${version}` : "CVSS"}
        value={cvss === null ? "n/a" : cvss.toFixed(1)}
        note={cvss === null ? "not scored" : SEV_WORD[sev]}
        tone={cvss === null ? undefined : `c-${sev}`}
      />
      <Cell
        label="EPSS"
        value={epss === null ? "n/a" : `${(epss * 100).toFixed(1)}%`}
        note={pct === null ? "no percentile" : `percentile p${Math.round(pct * 100)}`}
      />
      <Cell
        label="KEV due date"
        value={d.kev_due ? dayOf(d.kev_due) || d.kev_due : "None"}
        note={d.kev ? "US federal agencies" : "Not in KEV"}
      />
      <Cell
        label="Patch"
        value={d.patch_available === true ? "Yes" : d.patch_available === false ? "None" : "Unknown"}
        note={
          d.patch_available === true
            ? "Fixed releases out"
            : d.patch_available === false
              ? "No fixed version yet"
              : "No patch data"
        }
        tone={d.patch_available === true ? "c-low" : d.patch_available === false ? "c-crit" : undefined}
      />
    </div>
  );
}
