import { Link, useParams } from "react-router-dom";
import { CvssVector } from "../components/threat/CvssVector";
import { EvidenceLadder } from "../components/threat/EvidenceLadder";
import { Metrics } from "../components/threat/Metrics";
import { References } from "../components/threat/References";
import { StatusLine } from "../components/threat/StatusLine";
import { ThreatAside, SEEN_RANGE } from "../components/threat/ThreatAside";
import { Timeline } from "../components/threat/Timeline";
import { Weakness } from "../components/threat/Weakness";
import { WhatToDo } from "../components/threat/WhatToDo";
import { severityOf } from "../components/LaneRow";
import { ApiError } from "../lib/api";
import { useCve } from "../lib/queries";
import { CVE_ID_RE } from "../lib/selection";
import { Text } from "../lib/text";
import { headline } from "../lib/threatModel";
import type { CveDetail } from "../lib/types";
import NotFound from "./NotFound";

const SEV_NAME = { crit: "Critical", high: "High", med: "Medium", low: "Low" } as const;

function ThreatBody({ d }: { d: CveDetail }) {
  const scored = d.cvss !== null && Number.isFinite(d.cvss);
  const sev = severityOf(d.cvss);
  const cwes = (d.cwes ?? []).filter((c) => typeof c === "string");
  return (
    <>
      <nav className="crumb" aria-label="Breadcrumb">
        <Link to="/threats">Threats</Link> / <span className="mono">{d.cve_id}</span>
      </nav>
      <div className="t-head">
        <div className="idline">
          <span className="sevpill">
            <i className={`s-${scored ? sev : "none"}`} />
            <span className={scored ? `c-${sev}` : undefined}>
              {scored ? `${SEV_NAME[sev]} ${d.cvss!.toFixed(1)}` : "Not scored"}
            </span>
          </span>
          <span>{d.cve_id}</span>
          {cwes[0] ? (
            <span>
              <Text value={cwes[0]} />
            </span>
          ) : null}
        </div>
        <h1>{headline(d)}</h1>
      </div>
      <StatusLine d={d} />
      <div className="t-grid">
        <div className="t-main">
          <Metrics d={d} />
          <EvidenceLadder d={d} />
          <WhatToDo d={d} />
          <Timeline d={d} />
          <section className="blk" aria-labelledby="t-desc">
            <h2 id="t-desc">Description</h2>
            <div className="prose">
              {d.summary ? (
                <p>
                  <Text value={d.summary} />
                </p>
              ) : (
                <p className="muted">No description published yet.</p>
              )}
              <p className="muted small">Source: NVD</p>
            </div>
          </section>
          {d.cvss_vector ? <CvssVector vector={d.cvss_vector} /> : null}
          {cwes.length > 0 ? <Weakness cwes={cwes} /> : null}
          {(d.references ?? []).length > 0 ? <References refs={d.references} /> : null}
        </div>
        <ThreatAside d={d} />
      </div>
    </>
  );
}

/** The full threat page. A malformed id is the not-found view and never reaches the API. */
export default function ThreatPage() {
  const { cveId = "" } = useParams();
  const valid = CVE_ID_RE.test(cveId);
  // `enabled` keys off the id, so an invalid one makes no request.
  const q = useCve(valid ? cveId : undefined, SEEN_RANGE);
  if (!valid) return <NotFound />;
  let body;
  if (q.isError) {
    body =
      q.error instanceof ApiError && q.error.status === 404 ? (
        <div role="alert">
          <h1>Threat not found</h1>
          <p>We have no record of {cveId}.</p>
          <Link to="/threats">Back to Threats</Link>
        </div>
      ) : (
        <div role="alert">
          <h1>Couldn&apos;t load {cveId}</h1>
          <button type="button" className="btn" onClick={() => void q.refetch()}>
            Retry
          </button>
        </div>
      );
  } else if (!q.data) {
    body = <div className="t-loading" role="status" aria-busy="true" aria-label="Loading threat" />;
  } else {
    body = <ThreatBody d={q.data} />;
  }
  return <div className="page gutter threat">{body}</div>;
}
