import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { getAuth } from "../lib/auth";
import { MAX_PASSWORD_INPUT, MIN_PASSWORD, POLICY_MESSAGE, passwordProblems } from "../lib/password";
import { AuthCard, ErrorSummary, Field, ShowToggle, commonError } from "../components/formParts";

interface Accepted {
  id: number;
  email: string;
  role: string;
}

/**
 * `/invite/:token` creates an account; `/reset/:token` sets a new password (same endpoint).
 * The route URL holds a secret, so this page has no external links or resources, asks browsers
 * not to send a Referer, and replaces its history entry on success. The token lives only in the
 * route param and the POST body: never in storage, never logged.
 */
export default function AcceptInvite({ mode }: { mode: "invite" | "reset" }) {
  const { token = "" } = useParams();
  const navigate = useNavigate();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const busy = useRef(false);

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
      } else {
        try {
          await getAuth().login(made.email, pw);
          navigate("/", { replace: true });
        } catch {
          navigate("/login", { replace: true, state: { notice: "account-created" } });
        }
      }
      setPw("");
      setConfirm("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) fail(["This link is invalid or expired"]);
      else if (err instanceof ApiError && err.status === 422) {
        fail([err.code === "weak_password" ? POLICY_MESSAGE : "This link is invalid or expired"]);
      }
      else fail([commonError(err)]);
    } finally {
      busy.current = false;
      setPending(false);
    }
  };

  const type = show ? "text" : "password";
  return (
    <AuthCard title={mode === "reset" ? "Reset password" : "Accept invite"}>
      <form className="authform" onSubmit={(e) => void onSubmit(e)}>
        <ErrorSummary errors={errors} tick={tick} />
        <Field label="New password" hint={`At least ${MIN_PASSWORD} characters.`} type={type} value={pw} onChange={setPw} autoComplete="new-password" maxLength={MAX_PASSWORD_INPUT} />
        <Field label="Confirm password" type={type} value={confirm} onChange={setConfirm} autoComplete="new-password" maxLength={MAX_PASSWORD_INPUT} />
        <ShowToggle shown={show} onToggle={() => setShow((s) => !s)} />
        <button type="submit" className="btn primary" disabled={pending}>
          {mode === "reset" ? "Set new password" : "Create account"}
        </button>
      </form>
    </AuthCard>
  );
}
