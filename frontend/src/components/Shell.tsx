import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { startBootstrap } from "../lib/useAuth";
import { AlertBar } from "./AlertBar";
import { CommandBar } from "./CommandBar";
import { DrawerHost } from "./DrawerHost";

const NOTICES: Record<string, string> = { "admins-only": "Admins only. You were sent back to the dashboard." };
const NOTICE_MS = 6000;

/** Layout for every route: bootstrap once, command bar, alert bar, an optional notice, the page. */
export function Shell() {
  const loc = useLocation();
  const [hiddenKey, setHiddenKey] = useState<string | null>(null);

  useEffect(() => startBootstrap(), []);

  const code = (loc.state as { notice?: string } | null)?.notice;
  const notice = code ? NOTICES[code] : undefined;
  const visible = notice !== undefined && hiddenKey !== loc.key;

  useEffect(() => {
    if (!notice) return;
    const id = setTimeout(() => setHiddenKey(loc.key), NOTICE_MS);
    return () => clearTimeout(id);
  }, [notice, loc.key]);

  return (
    <>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <CommandBar />
      <AlertBar />
      {visible && (
        <div className="notice gutter" role="status">
          <span>{notice}</span>
          <button type="button" onClick={() => setHiddenKey(loc.key)} aria-label="Dismiss notice">
            <span aria-hidden="true">×</span>
          </button>
        </div>
      )}
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <DrawerHost />
    </>
  );
}
