/**
 * Dev-only harness: renders the real lazy <Globe> (real MapLibre, real worker, real atlas)
 * against fixture geo data with no backend. Not part of the production build.
 *
 *   dev:      npm run dev            -> localhost:5173/globe-harness.html
 *   built:    npm run build:harness && npm run preview:harness
 *                                    -> localhost:4173/globe-harness.html
 *
 * Query params: ?data=empty (no geo data), ?theme=light|dark. Task 11's Playwright Firefox
 * pixel check targets this page.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { GlobeProvider, useGlobe } from "../components/GlobeContext";
import { LazyGlobe } from "../components/LazyGlobe";
import { qk } from "../lib/queries";
import { applyTheme, type Theme } from "../lib/theme";
import type { GeoSummaryItem } from "../lib/types";

const at = "2026-11-05T09:00:00Z";
export const GEO_FIXTURE: GeoSummaryItem[] = [
  { country_code: "US", kind: "scan", magnitude: 9.4, events: 1840, last_seen: at },
  { country_code: "US", kind: "victim", magnitude: 3.1, events: 12, last_seen: at },
  { country_code: "CN", kind: "scan", magnitude: 7.2, events: 960, last_seen: at },
  { country_code: "RU", kind: "c2", magnitude: 4.4, events: 37, last_seen: at },
  { country_code: "RU", kind: "outage", magnitude: 1.4, events: 2, last_seen: at },
  { country_code: "NL", kind: "c2", magnitude: 2.6, events: 21, last_seen: at },
  { country_code: "DE", kind: "scan", magnitude: 3.3, events: 140, last_seen: at },
  { country_code: "BR", kind: "outage", magnitude: 6.2, events: 5, last_seen: at },
  { country_code: "BR", kind: "scan", magnitude: 2.2, events: 88, last_seen: at },
  { country_code: "IR", kind: "outage", magnitude: 8.0, events: 3, last_seen: at },
  { country_code: "UA", kind: "outage", magnitude: 3.5, events: 4, last_seen: at },
  { country_code: "UA", kind: "bgp", magnitude: 2.0, events: 6, last_seen: at },
  { country_code: "JP", kind: "victim", magnitude: 1.2, events: 3, last_seen: at },
  { country_code: "SG", kind: "scan", magnitude: 4.8, events: 410, last_seen: at },
  { country_code: "IN", kind: "scan", magnitude: 3.9, events: 260, last_seen: at },
  { country_code: "AU", kind: "victim", magnitude: 0.8, events: 1, last_seen: at },
  { country_code: "FJ", kind: "bgp", magnitude: 1.1, events: 2, last_seen: at },
  { country_code: "ZA", kind: "outage", magnitude: 1.0, events: 1, last_seen: at },
];

function FlyButtons() {
  const globe = useGlobe();
  return (
    <div className="harness-bar">
      {["US", "NL", "JP", "BR", "RU", "FJ"].map((c) => (
        <button key={c} type="button" className="btn" onClick={() => globe.flyTo(c)}>
          fly {c}
        </button>
      ))}
    </div>
  );
}

export default function GlobeHarness() {
  const params = new URLSearchParams(window.location.search);
  const [qc] = useState(() => {
    const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } });
    client.setQueryData(qk.geo(24), params.get("data") === "empty" ? [] : GEO_FIXTURE);
    return client;
  });
  const [theme, setTheme] = useState<Theme>(() => {
    const t: Theme = params.get("theme") === "light" ? "light" : "dark";
    applyTheme(t);
    return t;
  });
  const toggle = () => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  };
  return (
    <QueryClientProvider client={qc}>
      <GlobeProvider>
        <main className="gutter page">
          <div className="harness-bar">
            <strong>Globe harness</strong>
            <button type="button" className="btn" onClick={toggle}>
              theme: {theme}
            </button>
          </div>
          <FlyButtons />
          <LazyGlobe />
        </main>
      </GlobeProvider>
    </QueryClientProvider>
  );
}
