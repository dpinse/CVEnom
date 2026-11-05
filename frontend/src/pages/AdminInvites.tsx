import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { flushSync } from "react-dom";
import { SecretList, secretKey, type SecretItem } from "../components/OneTimeSecret";
import { adminError } from "../lib/adminErrors";
import { api } from "../lib/api";
import { qk } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { Text, decodeEntities } from "../lib/text";
import type { InviteBody, InviteOut, Role, TokenIssued, UserAdmin } from "../lib/types";
import { useNow } from "../lib/useNow";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function AdminInvites() {
  const qc = useQueryClient();
  const now = useNow();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("member");
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [confirming, setConfirming] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const listHead = useRef<HTMLHeadingElement>(null);
  const confirmBtn = useRef<HTMLButtonElement>(null);
  const revokeBtns = useRef(new Map<number, HTMLButtonElement>());

  const invites = useQuery({ queryKey: qk.invites(), queryFn: ({ signal }) => api<InviteOut[]>("/auth/invites", { signal }) });
  // Only for the "created by" label; the page works without it.
  const users = useQuery({ queryKey: qk.users(), queryFn: ({ signal }) => api<UserAdmin[]>("/auth/users", { signal }) });
  const emailOf = new Map((users.data ?? []).map((u) => [u.id, u.email]));

  useEffect(() => {
    if (confirming !== null) confirmBtn.current?.focus();
  }, [confirming]);

  const create = useMutation({
    // The token is handed to local state here and never returned: it cannot reach the mutation or query cache.
    mutationFn: async (body: InviteBody) => {
      const res = await api<TokenIssued>("/auth/invites", { method: "POST", body });
      setSecrets((l) => [
        ...l,
        {
          key: secretKey(),
          title: "Invite link",
          subject: body.email,
          label: "Invite link (send it to the invitee)",
          value: `${location.origin}/invite/${res.token}`,
          expiresAt: res.expires_at,
        },
      ]);
    },
    onSuccess: async () => {
      setError(null);
      setEmail("");
      await qc.invalidateQueries({ queryKey: qk.invites() });
    },
    onError: (e) => setError(adminError(e)),
  });

  const revoke = useMutation({
    mutationFn: (i: InviteOut) => api(`/auth/invites/${i.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setError(null);
      flushSync(() => setConfirming(null));
      await qc.invalidateQueries({ queryKey: qk.invites() });
      listHead.current?.focus();
    },
    onError: (e) => {
      setConfirming(null);
      setError(adminError(e));
      void qc.invalidateQueries({ queryKey: qk.invites() });
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const addr = email.trim();
    if (addr.length === 0 || addr.length > 254 || !EMAIL_RE.test(addr)) {
      setError("Enter a valid email address");
      emailRef.current?.focus();
      return;
    }
    setError(null);
    create.mutate({ email: addr, role });
  };

  const doneSecret = (key: number) => {
    setSecrets((l) => l.filter((s) => s.key !== key));
    emailRef.current?.focus();
  };
  const cancelRevoke = (id: number) => {
    flushSync(() => setConfirming(null));
    revokeBtns.current.get(id)?.focus();
  };

  return (
    <section className="page gutter">
      <h1>Invites</h1>
      <SecretList items={secrets} onDone={doneSecret} />
      <form className="admin-form" onSubmit={submit} noValidate aria-label="Invite someone">
        <h2>Invite someone</h2>
        <label className="field">
          <span>Email</span>
          <input ref={emailRef} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" maxLength={254} spellCheck={false} />
        </label>
        <label className="field">
          <span>Role</span>
          <select className="admin-select" value={role} onChange={(e) => setRole(e.target.value === "admin" ? "admin" : "member")}>
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </label>
        <div className="form-errors" aria-live="assertive">
          {error && <p>{error}</p>}
        </div>
        <div className="admin-row">
          <button type="submit" className="btn primary" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create invite"}
          </button>
        </div>
      </form>

      <div className="admin-section">
        <h2 ref={listHead} tabIndex={-1}>
          Pending invites
        </h2>
        {invites.isPending && <p role="status">Loading invites…</p>}
        {invites.isError && <p className="form-errors">Could not load invites.</p>}
        {invites.data && invites.data.length === 0 && <p className="form-hint">No pending invites.</p>}
        {invites.data && invites.data.length > 0 && (
          <div className="stable-wrap">
            <table className="stable admin-table">
              <thead>
                <tr>
                  <th scope="col">Email</th>
                  <th scope="col">Role</th>
                  <th scope="col">Purpose</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Created by</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {invites.data.map((i) => (
                  <tr key={i.id}>
                    <td data-label="Email">
                      <Text value={i.email} />
                    </td>
                    <td data-label="Role">{i.role}</td>
                    <td data-label="Purpose">{i.purpose === "reset" ? "Password reset" : "Invite"}</td>
                    <td data-label="Expires">{relTime(i.expires_at, now) || "—"}</td>
                    <td data-label="Created by">
                      {i.created_by === null ? "—" : emailOf.has(i.created_by) ? <Text value={emailOf.get(i.created_by) ?? ""} /> : `User #${i.created_by}`}
                    </td>
                    <td>
                      {confirming === i.id ? (
                        <span className="confirm">
                          <span>Revoke this {i.purpose === "reset" ? "reset link" : "invite"}?</span>
                          <button ref={confirmBtn} type="button" className="btn danger" disabled={revoke.isPending} onClick={() => revoke.mutate(i)}>
                            Confirm revoke
                          </button>
                          <button type="button" className="btn" onClick={() => cancelRevoke(i.id)}>
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <button
                          ref={(el) => {
                            if (el) revokeBtns.current.set(i.id, el);
                            else revokeBtns.current.delete(i.id);
                          }}
                          type="button"
                          className="btn"
                          aria-label={`Revoke ${i.purpose} for ${decodeEntities(i.email)}`}
                          onClick={() => setConfirming(i.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
