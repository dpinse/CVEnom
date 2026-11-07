import { RANGES, RANGE_LABEL, useRange } from "../lib/range";

/** Dashboard-only time range (24h | 7d | 14d | 30d); the choice lives in `?range=`. */
export function RangeControl() {
  const { range, setRange } = useRange();
  return (
    <div className="seg" role="group" aria-label="Time range">
      {RANGES.map((r) => (
        <button key={r} type="button" aria-pressed={r === range} title={RANGE_LABEL[r]} onClick={() => setRange(r)}>
          {r}
        </button>
      ))}
    </div>
  );
}
