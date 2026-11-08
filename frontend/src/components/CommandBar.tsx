import { Link, NavLink, useLocation } from "react-router-dom";
import { useLiveUpdates, type LiveStatus } from "../lib/live";
import { useRange } from "../lib/range";
import { useTheme } from "../lib/theme";
import { RangeControl } from "./RangeControl";
import { UserMenu } from "./UserMenu";

const STATUS_TEXT: Record<LiveStatus, string> = {
  live: "Live updates: connected",
  reconnecting: "Live updates: reconnecting",
  offline: "Live updates: offline",
};

const hhmm = (ms: number) =>
  new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });

/** The CVEnom mark: a radar scope with a sweep line. */
function Radar() {
  return (
    <svg className="mark" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <circle cx="10" cy="10" r="8.25" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="10" cy="10" r="4.25" stroke="currentColor" strokeWidth="1.5" opacity=".6" />
      <path d="M10 10 L16.5 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="10" cy="10" r="1.5" fill="currentColor" />
    </svg>
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
  const { pathname } = useLocation();
  const { range } = useRange();
  return (
    <header className="command gutter">
      <Link className="brand" to="/">
        <Radar />
        <span className="name">CVEnom</span>
      </Link>
      <nav className="cnav" aria-label="Main">
        <NavLink to={{ pathname: "/", search: `?range=${range}` }} end>
          Dashboard
        </NavLink>
        <NavLink to="/threats">Threats</NavLink>
      </nav>
      <div className="cspacer" />
      {pathname === "/" && <RangeControl />}
      <LiveStatusReadout />
      <ThemeToggle />
      <UserMenu />
    </header>
  );
}
