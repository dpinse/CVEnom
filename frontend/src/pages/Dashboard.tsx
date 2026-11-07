import { Lanes } from "../components/Lanes";
import { LazyGlobe } from "../components/LazyGlobe";
import { Volume } from "../components/Volume";

/**
 * The radar: globe (full width), then the volume chart, then the four lanes. The alert bar and the
 * drawer live in the shell, so they are not repeated here.
 */
export default function Dashboard() {
  return (
    <div className="dash gutter">
      <h1 className="sr-only">Dashboard</h1>
      <LazyGlobe />
      <Volume />
      <Lanes />
    </div>
  );
}
