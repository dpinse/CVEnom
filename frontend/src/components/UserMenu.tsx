import { useEffect, useId, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { getAuth } from "../lib/auth";
import { loginPath } from "../lib/redirect";
import { Text } from "../lib/text";
import { useAuth } from "../lib/useAuth";

/** Disclosure menu (not an ARIA menu widget): a button toggles a list of links. */
export function UserMenu() {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const navigate = useNavigate();
  const loc = useLocation();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setOpen(false);
      triggerRef.current?.focus();
    };
    const onPointer = (e: Event) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onFocusIn = (e: FocusEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("focusin", onFocusIn);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("focusin", onFocusIn);
    };
  }, [open]);

  if (!user) {
    return (
      <Link className="btn signin" to={loginPath(loc.pathname + loc.search)}>
        Sign in
      </Link>
    );
  }

  const close = () => setOpen(false);
  const logout = async () => {
    close();
    await getAuth().logout();
    navigate("/");
  };

  return (
    <div className="usermenu" ref={wrapRef}>
      <button
        ref={triggerRef}
        type="button"
        className="btn user-trigger"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={() => setOpen((o) => !o)}
      >
        <Text value={user.email} className="user-email" />
        <span className="caret" aria-hidden="true">
          ▾
        </span>
      </button>
      {open && (
        <nav id={panelId} className="menu-panel" aria-label="Account">
          <Link to="/account/sessions" onClick={close}>
            Sessions
          </Link>
          <Link to="/account/password" onClick={close}>
            Change password
          </Link>
          {user.role === "admin" && (
            <>
              <hr />
              <Link to="/admin/alerts" onClick={close}>
                Alerts
              </Link>
              <Link to="/admin/invites" onClick={close}>
                Invites
              </Link>
              <Link to="/admin/users" onClick={close}>
                Users
              </Link>
              <hr />
            </>
          )}
          <button type="button" onClick={() => void logout()}>
            Log out
          </button>
        </nav>
      )}
    </div>
  );
}
