import { useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError } from "../lib/api";
import { getAuth } from "../lib/auth";
import { safeNext } from "../lib/redirect";
import { useAuth } from "../lib/useAuth";
import { AuthCard, ErrorSummary, Field, commonError } from "../components/formParts";
import { Loading } from "../components/guards";

const NOTICES: Record<string, string> = {
  "session-expired": "Your session expired — please sign in again",
  "account-created": "Account created — please sign in",
  "password-reset": "Password reset — please sign in",
};

export default function Login() {
  const [sp] = useSearchParams();
  const next = safeNext(sp.get("next"));
  const loc = useLocation();
  const navigate = useNavigate();
  const { user, ready } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const busy = useRef(false);

  const code = (loc.state as { notice?: string } | null)?.notice;
  const notice = code ? NOTICES[code] : undefined;

  if (!ready) return <Loading />;
  if (user && !pending) return <Navigate to={next} replace />;

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy.current) return;
    busy.current = true;
    setPending(true);
    setErrors([]);
    try {
      await getAuth().login(email, password);
      navigate(next, { replace: true });
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
