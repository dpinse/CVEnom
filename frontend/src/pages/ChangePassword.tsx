import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type FormEvent } from "react";
import { ApiError, api } from "../lib/api";
import { MAX_PASSWORD, POLICY_MESSAGE, passwordProblems } from "../lib/password";
import { qk } from "../lib/queries";
import { AuthCard, ErrorSummary, Field, ShowToggle, commonError } from "../components/formParts";

export default function ChangePassword() {
  const qc = useQueryClient();
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
    try {
      await api("/auth/password", { method: "POST", body: { current_password: current, new_password: pw } });
      setCurrent("");
      setPw("");
      setConfirm("");
      setDone(true);
      void qc.invalidateQueries({ queryKey: qk.sessions() });
    } catch (err) {
      // A 401 here is a wrong current password (the API client never refreshes or logs out on it).
      if (err instanceof ApiError && err.status === 401) fail(["Current password is incorrect"]);
      else if (err instanceof ApiError && err.status === 422) fail([POLICY_MESSAGE]);
      else fail([commonError(err)]);
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
        <Field label="Current password" type={type} value={current} onChange={setCurrent} autoComplete="current-password" maxLength={1024} />
        <Field label="New password" type={type} value={pw} onChange={setPw} autoComplete="new-password" maxLength={MAX_PASSWORD} />
        <Field label="Confirm new password" type={type} value={confirm} onChange={setConfirm} autoComplete="new-password" maxLength={MAX_PASSWORD} />
        <ShowToggle shown={show} onToggle={() => setShow((s) => !s)} />
        <button type="submit" className="btn primary" disabled={pending}>
          Change password
        </button>
      </form>
    </AuthCard>
  );
}
