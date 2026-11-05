import { useEffect, useId, useRef, type ReactNode } from "react";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
/** Everything behind the drawer: the page, the app header (not any card <header>), the skip link, the alert bar and the notice. */
const BACKGROUND = "#main, header.command, .skip, .alertbar, .notice";

interface DrawerProps {
  /** Heading text; the dialog is labelled by it. */
  heading: ReactNode;
  onClose: () => void;
  /** Changing this (e.g. the selected id) moves focus back to the close button. */
  focusKey?: string;
  children: ReactNode;
}

/**
 * Accessible modal drawer: role=dialog, focus trap, Esc and scrim close, focus return,
 * inert background and body scroll lock while mounted. Mount it only while open.
 */
export function Drawer({ heading, onClose, focusKey, children }: DrawerProps) {
  const headId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  });

  useEffect(() => {
    const opener =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    const bg = Array.from(
      document.querySelectorAll<HTMLElement>(BACKGROUND),
    ).filter((el) => !el.contains(dialogRef.current));
    const prevInert = bg.map((el) => el.hasAttribute("inert"));
    bg.forEach((el) => el.setAttribute("inert", ""));
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const trap = (e: globalThis.KeyboardEvent) => {
      const nodes = Array.from(
        dialogRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [],
      );
      if (nodes.length === 0) {
        e.preventDefault();
        return;
      }
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      const active = document.activeElement;
      if (
        e.shiftKey &&
        (active === first ||
          active === dialogRef.current ||
          !dialogRef.current?.contains(active))
      ) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape" && !e.defaultPrevented) onCloseRef.current();
      else if (e.key === "Tab") trap(e);
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      bg.forEach((el, i) => {
        if (!prevInert[i]) el.removeAttribute("inert");
      });
      document.body.style.overflow = prevOverflow;
      const target =
        opener && opener !== document.body && opener.isConnected
          ? opener
          : document.getElementById("main");
      target?.focus();
    };
  }, []);

  useEffect(() => {
    closeRef.current?.focus();
  }, [focusKey]);

  return (
    <>
      <div
        className="scrim"
        data-testid="scrim"
        aria-hidden="true"
        onClick={onClose}
      />
      <div
        ref={dialogRef}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={headId}
      >
        <div className="dhead">
          <h2 id={headId} className="dtitle" tabIndex={-1}>
            {heading}
          </h2>
          <button
            ref={closeRef}
            type="button"
            className="close"
            aria-label="Close"
            onClick={onClose}
          >
            <span aria-hidden="true">✕</span>
          </button>
        </div>
        <div className="dbody">{children}</div>
      </div>
    </>
  );
}
