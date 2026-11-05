import { useEffect, useId, useRef, type ReactNode } from "react";
import { ApiError, NetworkError, RateLimited } from "../lib/api";

/** Always-mounted assertive live region; focus moves to it each time `tick` changes with errors. */
export function ErrorSummary({
  errors,
  tick,
}: {
  errors: string[];
  tick: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (tick > 0 && errors.length > 0) ref.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- refocus on every failed submit, even with identical text
  }, [tick]);
  return (
    <div
      ref={ref}
      className="form-errors"
      tabIndex={-1}
      aria-live="assertive"
      aria-atomic="true"
    >
      {errors.map((e) => (
        <p key={e}>{e}</p>
      ))}
    </div>
  );
}

export function Field({
  label,
  type,
  value,
  onChange,
  autoComplete,
  maxLength,
  required = true,
  hint,
}: {
  label: string;
  type: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete: string;
  maxLength: number;
  required?: boolean;
  /** Helper text under the input, linked with aria-describedby. */
  hint?: string;
}) {
  const hintId = useId();
  return (
    <div className="fieldwrap">
      <label className="field">
        <span>{label}</span>
        <input
          type={type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoComplete={autoComplete}
          maxLength={maxLength}
          required={required}
          spellCheck={false}
          autoCapitalize="none"
          aria-describedby={hint ? hintId : undefined}
        />
      </label>
      {hint && (
        <small id={hintId} className="field-hint">
          {hint}
        </small>
      )}
    </div>
  );
}

export function ShowToggle({
  shown,
  onToggle,
  plural = false,
}: {
  shown: boolean;
  onToggle: () => void;
  plural?: boolean;
}) {
  return (
    <button
      type="button"
      className="btn show-toggle"
      aria-pressed={shown}
      onClick={onToggle}
    >
      {plural ? "Show passwords" : "Show password"}
    </button>
  );
}

export function AuthCard({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="page gutter">
      <div className="authcard">
        <h1>{title}</h1>
        {children}
      </div>
    </section>
  );
}

/** One user-facing message per failure class shared by every auth form. */
export function commonError(e: unknown): string {
  if (e instanceof RateLimited)
    return `Too many attempts — try again in ${e.retryAfter} seconds`;
  if (e instanceof NetworkError)
    return "Could not reach the server. Check your connection and try again.";
  if (e instanceof ApiError && e.status >= 500)
    return "Something went wrong on our side. Please try again.";
  return "Something went wrong. Please try again.";
}
