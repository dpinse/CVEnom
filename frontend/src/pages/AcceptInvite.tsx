import { useEffect, useRef, useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { getAuth } from "../lib/auth";
import { MAX_PASSWORD_INPUT, MIN_PASSWORD, POLICY_MESSAGE, passwordProblems } from "../lib/password";
import { AuthCard, ErrorSummary, Field, ShowToggle, commonError } from "../components/formParts";
import { EnrollStep, RecoveryCodes } from "../components/MfaSteps";
import type { MfaChallenge } from "../lib/types";

/** The account plus an MFA ticket (no session): a new account goes straight into enrollment. */
interface Accepted extends Partial<MfaChallenge> {
  id: number;
  email: string;
  role: string;
}

type After = { kind: "enroll"; ticket: string } | { kind: "codes"; codes: string[] };

const INVALID = "This link is invalid or expired";

/** The token from a `#<token>` fragment ("" when absent or malformed). */
function tokenFrom(hash: string): string {
  try {
    return decodeURIComponent(hash.replace(/^#/g, ""));
  } catch {
    return "";
  }
}

/**
 * `/invite#<token>` creates an account and continues straight into MFA enrollment (the account has no
 * session until it is done); `/reset#<token>` sets a new password (same endpoint) and leaves MFA alone.
 * The token is in the URL fragment, which browsers never send to the server, so it stays out of
 * nginx and Cloudflare access logs. The page reads it once into memory and at once replaces the
 * history entry without it. It then lives only in component state and the POST body: never in
 * storage or a request URL. The page has no external links or resources, asks browsers not to
 * send a Referer, and replaces its history entry again on success.
 */
export default function AcceptInvite({ mode }: { mode: "invite" | "reset" }) {
  const loc = useLocation();
  const [token] = useState(() => tokenFrom(loc.hash));
  const navigate = useNavigate();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>(() => (token ? [] : [INVALID]));
  const [tick, setTick] = useState(0);
  const [after, setAfter] = useState<After | null>(null);
  const busy = useRef(false);

  // Strip the fragment from the address bar and history as soon as it has been read.
  useEffect(() => {
    if (loc.hash) navigate({ pathname: loc.pathname, search: loc.search }, { replace: true });
  }, [loc.hash, loc.pathname, loc.search, navigate]);

  // Belt and braces with the server's Referrer-Policy header: no Referer from this route.
  useEffect(() => {
    const meta = document.createElement("meta");
    meta.name = "referrer";
    meta.content = "no-referrer";
    document.head.appendChild(meta);
    return () => meta.remove();
  }, []);

  const fail = (list: string[]) => {
    setErrors(list);
    setTick((t) => t + 1);
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy.current) return;
    if (!token) return fail([INVALID]);
    const problems = passwordProblems(pw, confirm);
    if (problems.length > 0) return fail(problems);
    busy.current = true;
    setPending(true);
    setErrors([]);
    try {
      const made = await api<Accepted>("/auth/invites/accept", { method: "POST", body: { token, password: pw } });
      if (mode === "reset") {
        // Every session was revoked server-side: clear this tab, then sign in again.
        const signedIn = getAuth().getSnapshot().user;
        if (signedIn && signedIn.email.toLowerCase() !== made.email.toLowerCase()) {
          // A different user (e.g. an admin) opened the link: leave their session alone.
          navigate("/", { replace: true, state: { notice: "reset-other", email: made.email } });
        } else {
          await getAuth().logout();
          navigate("/login", { replace: true, state: { notice: "password-reset" } });
        }
      } else if (typeof made.ticket === "string" && made.ticket !== "") {
        // No session yet: the new account sets up its second factor first (the ticket stays in memory).
        setAfter({ kind: "enroll", ticket: made.ticket });
      } else {
        navigate("/login", { replace: true, state: { notice: "account-created" } });
      }
      setPw("");
      setConfirm("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) fail([INVALID]);
      else if (err instanceof ApiError && err.status === 422) {
        fail([err.code === "weak_password" ? POLICY_MESSAGE : INVALID]);
      } else fail([commonError(err)]);
    } finally {
      busy.current = false;
      setPending(false);
    }
  };

  if (after?.kind === "enroll") {
    return (
      <AuthCard title="Accept invite">
        <EnrollStep
          ticket={after.ticket}
          onEnrolled={(codes) => setAfter({ kind: "codes", codes })}
          onStartOver={() => navigate("/login", { replace: true, state: { notice: "account-created" } })}
        />
      </AuthCard>
    );
  }
  if (after?.kind === "codes") {
    return (
      <AuthCard title="Two-factor is on">
        <RecoveryCodes codes={after.codes} onDone={() => navigate("/", { replace: true })} />
      </AuthCard>
    );
  }

  const type = show ? "text" : "password";
  return (
    <AuthCard title={mode === "reset" ? "Reset password" : "Accept invite"}>
      <form className="authform" onSubmit={(e) => void onSubmit(e)}>
        <ErrorSummary errors={errors} tick={tick} />
        <Field
          label="New password"
          hint={`At least ${MIN_PASSWORD} characters.`}
          type={type}
          value={pw}
          onChange={setPw}
          autoComplete="new-password"
          maxLength={MAX_PASSWORD_INPUT}
        />
        <Field
          label="Confirm password"
          type={type}
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          maxLength={MAX_PASSWORD_INPUT}
        />
        <ShowToggle shown={show} onToggle={() => setShow((s) => !s)} />
        <button type="submit" className="btn primary" disabled={pending}>
          {mode === "reset" ? "Set new password" : "Create account"}
        </button>
      </form>
    </AuthCard>
  );
}
