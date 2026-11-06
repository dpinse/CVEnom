import { useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError } from "../lib/api";
import { getAuth } from "../lib/auth";
import { safeNext } from "../lib/redirect";
import { useAuth } from "../lib/useAuth";
import { AuthCard, ErrorSummary, Field, commonError } from "../components/formParts";
import { Loading } from "../components/guards";
import { CodeForm, EnrollStep, RecoveryCodes } from "../components/MfaSteps";

const NOTICES: Record<string, string> = {
  "session-expired": "Your session expired — please sign in again",
  "account-created": "Account created — please sign in",
  "password-reset": "Password reset — please sign in",
};

/**
 * Sign-in is two steps. The password step returns a short-lived MFA ticket (never a session); the
 * ticket then goes with a TOTP or recovery code (or through enrollment) for the session. The ticket
 * lives only in this component's state.
 */
type Step =
  | { kind: "password" }
  | { kind: "code"; ticket: string }
  | { kind: "enroll"; ticket: string }
  | { kind: "codes"; codes: string[] };

export default function Login() {
  const [sp] = useSearchParams();
  const next = safeNext(sp.get("next"));
  const loc = useLocation();
  const navigate = useNavigate();
  const { user, ready } = useAuth();
  const [step, setStep] = useState<Step>({ kind: "password" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const busy = useRef(false);

  const code = (loc.state as { notice?: string } | null)?.notice;
  const notice = code ? NOTICES[code] : undefined;

  if (!ready) return <Loading />;
  // Only the password step bounces a signed-in user: the later steps navigate themselves, and the
  // one-time recovery codes must stay on screen after enrollment has signed the user in.
  if (user && !pending && step.kind === "password") return <Navigate to={next} replace />;

  const startOver = () => {
    setStep({ kind: "password" });
    setPassword("");
    setErrors([]);
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy.current) return;
    busy.current = true;
    setPending(true);
    setErrors([]);
    try {
      const c = await getAuth().login(email, password);
      setPassword(""); // not needed past the first step
      setStep(c.enroll_required ? { kind: "enroll", ticket: c.ticket } : { kind: "code", ticket: c.ticket });
    } catch (err) {
      // Identical for unknown user and wrong password: never say which.
      setErrors([err instanceof ApiError && err.status === 401 ? "Email or password is incorrect" : commonError(err)]);
      setPassword("");
      setTick((t) => t + 1);
    } finally {
      busy.current = false;
      setPending(false);
    }
  };

  if (step.kind === "code") {
    const ticket = step.ticket;
    return (
      <AuthCard title="Sign in">
        <h2>Two-factor authentication</h2>
        <CodeForm
          hint="The 6-digit code from your authenticator app, or one of your recovery codes."
          onSubmit={async (c) => {
            setPending(true);
            try {
              await getAuth().verifyMfa(ticket, c);
              navigate(next, { replace: true });
            } finally {
              setPending(false);
            }
          }}
          onStartOver={startOver}
        />
      </AuthCard>
    );
  }

  if (step.kind === "enroll") {
    return (
      <AuthCard title="Sign in">
        <EnrollStep
          ticket={step.ticket}
          onEnrolled={(codes) => setStep({ kind: "codes", codes })}
          onStartOver={startOver}
        />
      </AuthCard>
    );
  }

  if (step.kind === "codes") {
    return (
      <AuthCard title="Two-factor is on">
        <RecoveryCodes codes={step.codes} onDone={() => navigate(next, { replace: true })} />
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Sign in">
      {notice && (
        <p className="form-notice" role="status">
          {notice}
        </p>
      )}
      <form className="authform" onSubmit={(e) => void onSubmit(e)} noValidate={false}>
        <ErrorSummary errors={errors} tick={tick} />
        <Field label="Email" type="email" value={email} onChange={setEmail} autoComplete="username" maxLength={320} />
        <Field
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          maxLength={1024}
        />
        <button type="submit" className="btn primary" disabled={pending}>
          {pending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </AuthCard>
  );
}
