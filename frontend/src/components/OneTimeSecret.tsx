import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Text } from "../lib/text";

/**
 * A secret shown exactly once. The value is held only by the caller's component state and
 * rendered here; it is never put in the query cache, the URL, web storage or a log. Copying
 * happens only on an explicit click. When the parent drops the item (Done) or unmounts, it is gone.
 */
export function OneTimeSecret({
  title,
  label,
  value,
  expiresAt,
  onDone,
}: {
  title: ReactNode;
  label: string;
  value: string;
  expiresAt?: string;
  onDone: () => void;
}) {
  const headId = useId();
  const box = useRef<HTMLElement>(null);
  const field = useRef<HTMLInputElement>(null);
  const [note, setNote] = useState("");
  useEffect(() => {
    box.current?.focus();
  }, []);

  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(value);
      setNote("Copied to clipboard");
    } catch {
      field.current?.focus();
      field.current?.select();
      setNote("Couldn't copy automatically. The text is selected: press Ctrl+C");
    }
  };

  const expiry = expiresAt ? new Date(expiresAt) : null;
  return (
    <section ref={box} className="secret-panel" aria-labelledby={headId} tabIndex={-1}>
      <h2 id={headId}>{title}</h2>
      <p className="secret-warn">This won&apos;t be shown again</p>
      <label className="field">
        <span>{label}</span>
        <input
          ref={field}
          className="secret-field"
          type="text"
          readOnly
          value={value}
          spellCheck={false}
          autoComplete="off"
          onFocus={(e) => e.currentTarget.select()}
        />
      </label>
      {expiry !== null && Number.isFinite(expiry.getTime()) && <p className="form-hint">Expires {expiry.toLocaleString()}</p>}
      <div className="secret-actions">
        <button type="button" className="btn" onClick={() => void copy()}>
          Copy
        </button>
        <button type="button" className="btn primary" onClick={onDone}>
          Done
        </button>
      </div>
      <p className="form-hint" role="status">
        {note}
      </p>
    </section>
  );
}

export interface SecretItem {
  key: number;
  title: string;
  /** server text shown next to the title, via <Text> */
  subject?: string;
  label: string;
  value: string;
  expiresAt?: string;
}

let seq = 0;
export const secretKey = () => ++seq;

export function SecretList({ items, onDone }: { items: SecretItem[]; onDone: (key: number) => void }) {
  return (
    <>
      {items.map((s) => (
        <OneTimeSecret
          key={s.key}
          title={
            <>
              {s.title}
              {s.subject !== undefined && (
                <>
                  {": "}
                  <Text value={s.subject} />
                </>
              )}
            </>
          }
          label={s.label}
          value={s.value}
          expiresAt={s.expiresAt}
          onDone={() => onDone(s.key)}
        />
      ))}
    </>
  );
}
