import { useVelocity } from "../lib/queries";
import type { VelocityOut } from "../lib/types";

export const DAYS = 30;
const W = 200;
const H = 42;
const PAD = 3;
const NUMBER = new Intl.NumberFormat("en-US");

export interface SparkPath {
  line: string;
  area: string;
  end: { x: number; y: number };
}

const n = (v: number) => (Math.round(v * 100) / 100).toString();

/**
 * Pure sparkline geometry. Linear scale to max(series); a series with no range (empty, all
 * zeros, all equal) draws a flat line at the vertical middle. Never emits NaN.
 */
export function sparkPath(series: number[], w: number, h: number, pad: number): SparkPath {
  const mid = h / 2;
  if (series.length === 0) return { line: "", area: "", end: { x: w / 2, y: mid } };
  const vals = series.map((v) => (Number.isFinite(v) ? Math.max(0, v) : 0));
  const max = Math.max(...vals);
  const min = Math.min(...vals);
  const flat = max === min;
  const innerW = Math.max(0, w - 2 * pad);
  const innerH = Math.max(0, h - 2 * pad);
  const xs = vals.length === 1 ? [w / 2] : vals.map((_, i) => pad + (i / (vals.length - 1)) * innerW);
  const ys = vals.map((v) => (flat ? mid : h - pad - (v / max) * innerH));
  const pts = xs.map((x, i) => `${n(x)},${n(ys[i])}`);
  const line = `M${pts.join(" L")}`;
  const base = h - pad;
  const area = `${line} L${n(xs[xs.length - 1])},${n(base)} L${n(xs[0])},${n(base)} Z`;
  return { line, area, end: { x: xs[xs.length - 1], y: ys[ys.length - 1] } };
}

function summary(data: VelocityOut): string {
  let peak = data.series[0];
  for (const p of data.series) if (!peak || p.count >= peak.count) peak = p;
  const trend = data.rising ? "rising" : "steady";
  const pk = peak ? `, peak ${NUMBER.format(peak.count)} on ${peak.day}` : "";
  return `CVEs published per day over the last ${DAYS} days: today ${NUMBER.format(data.current)}${pk}, trend ${trend}`;
}

interface ViewProps {
  data?: VelocityOut;
  loading?: boolean;
  error?: unknown;
}

export function VelocityView({ data, loading, error }: ViewProps) {
  if (error || (!loading && !data)) {
    return (
      <div className="velocity velocity-state" role="status">
        <span className="velocity-msg">CVE velocity is unavailable right now.</span>
      </div>
    );
  }
  if (loading || !data) {
    return (
      <div className="velocity" role="status" aria-busy="true" aria-label="Loading CVE velocity">
        <span className="sr-only">Loading CVE velocity</span>
        <div className="velocity-skeleton velocity-skeleton-num" />
        <div className="velocity-skeleton velocity-skeleton-spark" />
      </div>
    );
  }
  const counts = data.series.map((p) => p.count);
  const empty = counts.every((c) => c === 0);
  const p = sparkPath(counts, W, H, PAD);
  const showDot = counts.length > 0;
  return (
    <div className="velocity">
      <div className="velocity-num">
        <div className="velocity-label">CVEs published / day</div>
        <b className="velocity-value">{NUMBER.format(data.current)}</b>
      </div>
      <div className="velocity-spark">
        <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true" focusable="false">
          {p.area && <path className="velocity-area" d={p.area} />}
          {p.line && <path className="velocity-line" d={p.line} vectorEffect="non-scaling-stroke" />}
        </svg>
        {showDot && (
          <span
            className="velocity-dot"
            aria-hidden="true"
            style={{ left: `${(p.end.x / W) * 100}%`, top: `${(p.end.y / H) * 100}%` }}
          />
        )}
      </div>
      <div className="velocity-side">
        <span className={data.rising ? "velocity-trend velocity-rising" : "velocity-trend"}>
          {data.rising ? "rising" : "steady"}
        </span>
        {empty && <span className="velocity-empty">No new CVEs in this window</span>}
      </div>
      <p className="sr-only">{summary(data)}</p>
    </div>
  );
}

export function Velocity() {
  const q = useVelocity(DAYS);
  return <VelocityView data={q.data} loading={q.isPending && !q.isError} error={q.isError ? q.error : undefined} />;
}
