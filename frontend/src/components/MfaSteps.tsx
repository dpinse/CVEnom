import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { ApiError } from "../lib/api";
import { getAuth } from "../lib/auth";
import type { MfaEnrollStart } from "../lib/types";
import { ErrorSummary, commonError } from "./formParts";
import { QrCode } from "./QrCode";

/*
 * The second sign-in step. The MFA ticket, the enrollment secret and the recovery codes live only
 * in component state: never in the query cache, web storage, the URL or a log. Unmounting (or
 * "Start over") drops them.
 */

export const CODE_REJECTED = "That code was not accepted. Check your authenticator app and try again, or start over.";
const EXPIRED = "This sign-in has expired. Start over.";

/** Belt and braces with the server's Referrer-Policy header while a secret is on screen. */
export function useNoReferrer() {
  useEffect(() => {
    const meta = document.createElement("meta");
    meta.name = "referrer";
    meta.content = "no-referrer";
    document.head.appendChild(meta);
    return () => meta.remove();
  }, []);
}

function codeError(e: unknown): string {
  // Every failed second factor is the same 401 (wrong, replayed or expired): one message.
  if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return CODE_REJECTED;
  return commonError(e);
}

/** A one-field form for a TOTP (or recovery) code. */
export function CodeForm({
  hint,
  submitLabel = "Verify",
  onSubmit,
  onStartOver,
}: {
  hint: string;
  submitLabel?: string;
  onSubmit: (code: string) => Promise<void>;
  onStartOver?: () => void;
}) {
  const [code, setCode] = useState("");
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const busy = useRef(false);
  const hintId = useId();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy.current) return;
    const value = code.trim();
    if (value === "") {
      setErrors(["Enter the 6-digit code from your authenticator app."]);
      setTick((t) => t + 1);
      return;
    }
    busy.current = true;
    setPending(true);
    setErrors([]);
    try {
      await onSubmit(value);
      setCode("");
    } catch (err) {
      setErrors([codeError(err)]);
      setCode("");
      setTick((t) => t + 1);
    } finally {
      busy.current = false;
      setPending(false);
    }
  };

  return (
    <form className="authform" onSubmit={(e) => void submit(e)}>
      <ErrorSummary errors={errors} tick={tick} />
      <div className="fieldwrap">
        <label className="field">
          <span>Authentication code</span>
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            autoComplete="one-time-code"
            maxLength={64}
            required
            spellCheck={false}
            autoCapitalize="none"
            aria-describedby={hintId}
          />
        </label>
        <small id={hintId} className="field-hint">
          {hint}
        </small>
      </div>
      <button type="submit" className="btn primary" disabled={pending}>
        {pending ? "Checking…" : submitLabel}
      </button>
      {onStartOver && (
        <button type="button" className="btn" onClick={onStartOver}>
          Start over
        </button>
      )}
    </form>
  );
}

/** "JBSWY3DP..." as "JBSW Y3DP ..." for typing into an app by hand. */
const grouped = (s: string) => s.replace(/(.{4})/g, "$1 ").trim();

/**
 * Enrollment for an account without MFA: local QR + manual secret + a first code. On success the
 * session exists and `onEnrolled` receives the one-time recovery codes.
 */
export function EnrollStep({
  ticket,
  onEnrolled,
  onStartOver,
}: {
  ticket: string;
  onEnrolled: (recoveryCodes: string[]) => void;
  onStartOver: () => void;
}) {
  useNoReferrer();
  const [setup, setSetup] = useState<MfaEnrollStart | null>(null);
  const [error, setError] = useState<string | null>(null);
  const request = useRef<{ ticket: string; p: Promise<MfaEnrollStart> } | null>(null);

  useEffect(() => {
    // One start per ticket, even across StrictMode's re-mount: a second start would replace the
    // pending secret server-side, and the two answers could race.
    if (request.current?.ticket !== ticket) request.current = { ticket, p: getAuth().startEnrollment(ticket) };
    let live = true;
    request.current.p.then(
      (s) => {
        if (live) setSetup(s);
      },
      (e: unknown) => {
        if (live) setError(e instanceof ApiError && e.status === 401 ? EXPIRED : commonError(e));
      },
    );
    return () => {
      live = false;
    };
  }, [ticket]);

  return (
    <>
      <h2>Set up two-factor authentication</h2>
      <p className="form-notice">
        Two-factor authentication is required. Scan the QR code with an authenticator app (for example Aegis, Google
        Authenticator or 1Password), then enter the 6-digit code it shows.
      </p>
      {error && (
        <div className="form-errors" role="alert">
          <p>{error}</p>
          <button type="button" className="btn" onClick={onStartOver}>
            Start over
          </button>
        </div>
      )}
      {!setup && !error && <p role="status">Preparing…</p>}
      {setup && (
        <>
          <div className="mfa-qr">
            <QrCode value={setup.otpauth_uri} label="QR code for your authenticator app" />
          </div>
          <p className="form-hint">Can&apos;t scan it? Enter this key in the app instead (time-based, 6 digits):</p>
          <p>
            <code className="mfa-secret">{grouped(setup.secret)}</code>
          </p>
          <CodeForm
            hint="The 6-digit code your app shows for CVEnom."
            submitLabel="Verify"
            onSubmit={async (code) => {
              const { recoveryCodes } = await getAuth().finishEnrollment(ticket, code);
              setSetup(null); // the secret leaves memory as soon as it is confirmed
              onEnrolled(recoveryCodes);
            }}
            onStartOver={onStartOver}
          />
        </>
      )}
    </>
  );
}

/** The recovery codes, shown exactly once (same pattern as OneTimeSecret). */
export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  useNoReferrer();
  const headId = useId();
  const box = useRef<HTMLElement>(null);
  const [note, setNote] = useState("");
  useEffect(() => {
    box.current?.focus();
  }, []);

  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText) throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(codes.join("\n"));
      setNote("Copied to clipboard");
    } catch {
      setNote("Couldn't copy automatically. Select the codes and copy them.");
    }
  };

  return (
    <section ref={box} className="secret-panel" aria-labelledby={headId} tabIndex={-1}>
      <h2 id={headId}>Recovery codes</h2>
      <p className="secret-warn">This won&apos;t be shown again</p>
      <p className="form-hint">
        Each code signs you in once if you lose your authenticator. Keep them somewhere safe, away from your phone.
      </p>
      <ol className="recovery-codes">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ol>
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
