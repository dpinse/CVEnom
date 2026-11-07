import { useParams } from "react-router-dom";
import { CVE_ID_RE } from "../lib/selection";
import NotFound from "./NotFound";

/** Minimal stand-in until the threat page lands: a bad CVE id is a not-found view without fetching anything. */
export default function ThreatPlaceholder() {
  const { cveId = "" } = useParams();
  if (!CVE_ID_RE.test(cveId)) return <NotFound />;
  return (
    <section className="page gutter">
      <h1>{cveId}</h1>
    </section>
  );
}
