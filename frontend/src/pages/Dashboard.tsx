import { Lanes } from "../components/Lanes";
import { LazyGlobe } from "../components/LazyGlobe";
import { Velocity } from "../components/Velocity";

/**
 * The radar: globe (full width), then the velocity strip, then the four lanes. The alert bar and the
 * drawer live in the shell, so they are not repeated here.
 */
export default function Dashboard() {
  return (
    <div className="dash gutter">
      <h1 className="sr-only">Dashboard</h1>
      <LazyGlobe />
      <Velocity />
      <Lanes />
    </div>
  );
}
