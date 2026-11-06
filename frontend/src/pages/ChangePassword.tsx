import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, AuthError, api, getApiClient } from "../lib/api";
import { MAX_PASSWORD_INPUT, MIN_PASSWORD, POLICY_MESSAGE, passwordProblems } from "../lib/password";
import { qk } from "../lib/queries";
import { AuthCard, ErrorSummary, Field, ShowToggle, commonError } from "../components/formParts";

export default function ChangePassword() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [current, setCurrent] = useState("");
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [show, setShow] = useState(false);
  const [pending, setPending] = useState(false);
  const [done, setDone] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const busy = useRef(false);

  const fail = (list: string[]) => {
    setDone(false);
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
    setDone(false);
    const post = () =>
      api("/auth/password", {
        method: "POST",
        body: { current_password: current, new_password: pw },
      });
    try {
      try {
        await post();
      } catch (err) {
        // invalid_credentials is a wrong current password. Any other 401 means the access token
        // lapsed (this route is exempt from automatic refresh): refresh once, retry once.
        if (!(err instanceof ApiError && err.status === 401 && err.code !== "invalid_credentials")) throw err;
        await getApiClient().refresh();
        await post();
      }
      setCurrent("");
      setPw("");
      setConfirm("");
      setDone(true);
      void qc.invalidateQueries({ queryKey: qk.sessions() });
    } catch (err) {
      if (
        err instanceof AuthError ||
        (err instanceof ApiError && err.status === 401 && err.code !== "invalid_credentials")
      ) {
        // The session could not be refreshed (or is still rejected): sign in again; Login shows the notice.
        navigate("/login", {
          replace: true,
          state: { notice: "session-expired" },
        });
      } else if (err instanceof ApiError && err.status === 401) {
        fail(["Current password is incorrect"]);
      } else if (err instanceof ApiError && err.status === 422) {
        fail([err.code === "weak_password" ? POLICY_MESSAGE : "Couldn't update password"]);
      } else fail([commonError(err)]);
    } finally {
      busy.current = false;
      setPending(false);
    }
  };

  const type = show ? "text" : "password";
  return (
    <AuthCard title="Change password">
      <p className="form-hint">Other devices will be signed out. This device stays signed in.</p>
      <form className="authform" onSubmit={(e) => void onSubmit(e)}>
        <ErrorSummary errors={errors} tick={tick} />
        {done && (
          <p className="form-notice" role="status">
            Password changed. Other devices have been signed out.
          </p>
        )}
        <Field
          label="Current password"
          type={type}
          value={current}
          onChange={setCurrent}
          autoComplete="current-password"
          maxLength={1024}
        />
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
          label="Confirm new password"
          type={type}
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          maxLength={MAX_PASSWORD_INPUT}
        />
        <ShowToggle plural shown={show} onToggle={() => setShow((s) => !s)} />
        <button type="submit" className="btn primary" disabled={pending}>
          Change password
        </button>
      </form>
    </AuthCard>
  );
}
