import { useLiveUpdates } from "./lib/live";

export default function App() {
  useLiveUpdates(); // the one live socket for the whole app
  return (
    <main className="gutter">
      <h1
        style={{
          fontFamily: "var(--font-display)",
          fontWeight: 700,
          letterSpacing: "0.02em",
        }}
      >
        CVEnom
      </h1>
    </main>
  );
}
