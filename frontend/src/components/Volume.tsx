import { useVolume } from "../lib/queries";
import { DEFAULT_RANGE, RANGE_LABEL, type RangeKey } from "../lib/range";
import type { VolumeBucket, VolumeOut } from "../lib/types";

export const SEV_ORDER = ["crit", "high", "med", "low"] as const;
export type Sev = (typeof SEV_ORDER)[number];

const W = 1000;
const H = 110;
const PAD = 18;
const TOP = 4;
const NUMBER = new Intl.NumberFormat("en-US");
const SEV_LABEL: Record<Sev, string> = { crit: "Critical", high: "High", med: "Medium", low: "Low" };
const DAY = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const HOUR = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});

export interface VolumeBar {
  x: number;
  width: number;
  segs: { sev: Sev; y: number; height: number }[];
}

const count = (v: number) => (Number.isFinite(v) ? Math.max(0, v) : 0);

/**
 * Pure stacked-bar geometry. Band scale over [0, w] (inner and outer padding equal), linear y from
 * the largest stacked total up to `TOP` and down to `h - pad`. Critical sits at the top of each
 * stack; segs come back in SEV_ORDER. All-zero input gives zero heights. Never emits NaN.
 */
export function volumeBars(buckets: VolumeBucket[], w: number, h: number, pad: number): VolumeBar[] {
  const n = buckets.length;
  if (n === 0) return [];
  const padding = n < 15 ? 0.55 : 0.2;
  const step = w / (n + padding);
  const width = step * (1 - padding);
  const start = (w - step * (n - padding)) / 2;
  const totals = buckets.map((b) => SEV_ORDER.reduce((s, k) => s + count(b[k]), 0));
  const max = Math.max(...totals);
  const base = h - pad;
  const scale = max > 0 ? Math.max(0, base - TOP) / max : 0;
  return buckets.map((b, i) => {
    let y = base;
    const segs: VolumeBar["segs"] = [];
    for (const sev of [...SEV_ORDER].reverse()) {
      const height = count(b[sev]) * scale;
      y -= height;
      segs.push({ sev, y, height });
    }
    return { x: start + step * i, width, segs: segs.reverse() };
  });
}

const r2 = (v: number) => Math.round(v * 100) / 100;

interface ViewProps {
  data?: VolumeOut;
  loading?: boolean;
  error?: unknown;
  range?: RangeKey;
}

export function VolumeView({ data, loading, error, range = DEFAULT_RANGE }: ViewProps) {
  if (error || (!loading && !data)) {
    return (
      <section className="vol vol-state" role="status">
        <span className="vol-msg">CVE volume is unavailable right now.</span>
      </section>
    );
  }
  if (loading || !data) {
    return (
      <section className="vol" role="status" aria-busy="true" aria-label="Loading CVE volume">
        <span className="sr-only">Loading CVE volume</span>
        <div className="vol-skeleton" />
      </section>
    );
  }
  const unit = data.unit === "hour" ? "hour" : "day";
  const bars = volumeBars(data.buckets, W, H, PAD);
  const fmt = (start: string) => {
    const d = new Date(start);
    if (Number.isNaN(d.getTime())) return start;
    return (unit === "hour" ? HOUR : DAY).format(d);
  };
  const first = data.buckets[0];
  return (
    <section className="vol" aria-labelledby="vol-title">
      <div className="vol-head">
        <h2 id="vol-title">New CVEs per {unit}</h2>
        <span className="vol-total">
          {NUMBER.format(data.total)} in the last {RANGE_LABEL[range]}
        </span>
        <span className="vol-leg">
          {SEV_ORDER.map((s) => (
            <span key={s}>
              <i className={`vol-sw vol-${s}`} aria-hidden="true" />
              {SEV_LABEL[s]}
            </span>
          ))}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H - PAD + 2}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`New CVEs per ${unit}, stacked by severity`}
      >
        {bars.map((b, i) => (
          <g key={data.buckets[i].start}>
            <title>
              {`${fmt(data.buckets[i].start)}: ${SEV_ORDER.map((k) => `${SEV_LABEL[k]} ${NUMBER.format(count(data.buckets[i][k]))}`).join(", ")}`}
            </title>
            {b.segs.map((s) =>
              s.height > 0 ? (
                <rect
                  key={s.sev}
                  className={`vol-${s.sev}`}
                  x={r2(b.x)}
                  y={r2(s.y)}
                  width={r2(b.width)}
                  height={r2(s.height)}
                />
              ) : null,
            )}
          </g>
        ))}
      </svg>
      <div className="vol-axis" aria-hidden="true">
        <span>{unit === "hour" ? "24h ago" : first ? fmt(first.start) : ""}</span>
        <span>now</span>
      </div>
      <div className="sr-only">
        <table>
          <caption>New CVEs per {unit} by severity</caption>
          <thead>
            <tr>
              <th scope="col">Start</th>
              <th scope="col">Critical</th>
              <th scope="col">High</th>
              <th scope="col">Medium</th>
              <th scope="col">Low</th>
            </tr>
          </thead>
          <tbody>
            {data.buckets.map((b) => (
              <tr key={b.start}>
                <th scope="row">{fmt(b.start)}</th>
                <td>{b.crit}</td>
                <td>{b.high}</td>
                <td>{b.med}</td>
                <td>{b.low}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.unscored > 0 && <p className="vol-foot">{NUMBER.format(data.unscored)} unscored CVEs not shown</p>}
    </section>
  );
}

export function Volume({ range = DEFAULT_RANGE }: { range?: RangeKey }) {
  const q = useVolume(range);
  return (
    <VolumeView
      data={q.data}
      loading={q.isPending && !q.isError}
      error={q.isError ? q.error : undefined}
      range={range}
    />
  );
}
