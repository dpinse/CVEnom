import { Lanes } from "../components/Lanes";
import { MapPanel } from "../components/MapPanel";
import { SummaryLine } from "../components/SummaryLine";
import { Volume } from "../components/Volume";
import { useRange } from "../lib/range";

/**
 * The radar, top to bottom: summary line, map and country panel, the four lanes, the volume chart. The range control
 * (top bar) sets one range that every block here reads. The alert bar and the drawer live in the shell.
 */
export default function Dashboard() {
  const { range } = useRange();
  return (
    <div className="dash gutter">
      <SummaryLine range={range} />
      <MapPanel range={range} />
      <Lanes range={range} />
      <Volume range={range} />
    </div>
  );
}
