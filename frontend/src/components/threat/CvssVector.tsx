import { decodeCvss } from "../../lib/cvssVector";
import { Text } from "../../lib/text";

const IMPACT_KEYS = new Set(["C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA"]);

export function CvssVector({ vector }: { vector: string }) {
  const decoded = decodeCvss(vector);
  return (
    <section className="blk" aria-labelledby="t-cvss">
      <h2 id="t-cvss">CVSS vector</h2>
      <p className="mono muted vec" data-testid="cvss-vector">
        <Text value={vector} />
      </p>
      {decoded ? (
        <div className="cvss-v">
          {decoded.metrics.map((m) => (
            <div key={m.key}>
              <span>{m.label}</span>
              <b className={IMPACT_KEYS.has(m.key) && m.value === "High" ? "c-crit" : undefined}>{m.value}</b>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
