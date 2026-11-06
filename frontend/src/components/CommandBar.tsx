import { Link, NavLink } from "react-router-dom";
import { useLiveUpdates, type LiveStatus } from "../lib/live";
import { useSummary } from "../lib/queries";
import { situationLevel } from "../lib/situation";
import { useTheme } from "../lib/theme";
import { useNow } from "../lib/useNow";
import { UserMenu } from "./UserMenu";

const STATUS_TEXT: Record<LiveStatus, string> = {
  live: "Live updates: connected",
  reconnecting: "Live updates: reconnecting",
  offline: "Live updates: offline",
};

const hhmm = (ms: number) =>
  new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });

function Radar() {
  return (
    <svg className="mark" viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true">
      <circle cx="16" cy="16" r="13" />
      <ellipse cx="16" cy="16" rx="6" ry="13" />
      <path d="M3 16h26" />
      <path d="M16 16 L25.5 10.5" />
      <circle cx="16" cy="16" r="2.4" fill="currentColor" stroke="none" />
    </svg>
  );
}

function Situation() {
  // fixed 7-day window: the gauge is not driven by the Dashboard range control
  const summary = useSummary("7d");
  const now = useNow();
  const s = summary.data ? situationLevel(summary.data, now) : null;
  const label = s ? s.level : "Unavailable";
  return (
    <div
      className="situation"
      data-level={s?.level ?? "Unknown"}
      title="Situation level, driven by live-exploited vulnerabilities"
    >
      <div className="sgauge" role="img" aria-label={`Situation: ${label}`}>
        {[0, 1, 2, 3].map((i) => (
          <i key={i} className={s && i < s.lit ? "lit" : undefined} />
        ))}
      </div>
      <div className="stext" aria-hidden="true">
        <div className="slabel">Situation</div>
        <div className="slevel">{s ? s.level : "…"}</div>
      </div>
    </div>
  );
}

function LiveStatusReadout() {
  const { status, lastUpdated } = useLiveUpdates();
  return (
    <div className="readout">
      <span className="dot" data-status={status} aria-hidden="true" />
      <span className="sr-only">{STATUS_TEXT[status]}</span>
      {lastUpdated !== null && <span className="mono updated">{`updated ${hhmm(lastUpdated)}`}</span>}
    </div>
  );
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button type="button" className="iconbtn" aria-label="Dark theme" aria-pressed={theme === "dark"} onClick={toggle}>
      <span aria-hidden="true">◐</span>
    </button>
  );
}

export function CommandBar() {
  return (
    <header className="command gutter">
      <Link className="brand" to="/">
        <Radar />
        <span>
          <span className="name">CVEnom</span>
          <span className="kicker">vulnerability threat radar</span>
        </span>
      </Link>
      <nav className="cnav" aria-label="Primary">
        <NavLink to="/history">History</NavLink>
      </nav>
      <Situation />
      <div className="cspacer" />
      <LiveStatusReadout />
      <ThemeToggle />
      <UserMenu />
    </header>
  );
}
