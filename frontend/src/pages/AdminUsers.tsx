import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { SecretList, secretKey, type SecretItem } from "../components/OneTimeSecret";
import { adminError } from "../lib/adminErrors";
import { api } from "../lib/api";
import { qk } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { Text, decodeEntities } from "../lib/text";
import type { Role, TokenIssued, UserAdmin, UserPatch } from "../lib/types";
import { useAuth } from "../lib/useAuth";
import { useNow } from "../lib/useNow";

type Pending =
  | { user: UserAdmin; action: "role"; role: Role }
  | { user: UserAdmin; action: "active"; active: boolean }
  | { user: UserAdmin; action: "revoke" };

function confirmText(p: Pending) {
  const who = <Text value={p.user.email} as="strong" />;
  switch (p.action) {
    case "role":
      return <>Change {who} from admin to member? They lose access to the admin pages.</>;
    case "active":
      return p.active ? (
        <>Reactivate {who}? They will be able to sign in again.</>
      ) : (
        <>Deactivate {who}? Signs them out everywhere.</>
      );
    case "revoke":
      return <>Revoke all sessions for {who}? Signs them out everywhere.</>;
  }
}

export default function AdminUsers() {
  const qc = useQueryClient();
  const now = useNow();
  const { user: me } = useAuth();
  const [pending, setPending] = useState<Pending | null>(null);
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const confirmBtn = useRef<HTMLButtonElement>(null);
  const roleSelects = useRef(new Map<number, HTMLSelectElement>());
  const resetBtns = useRef(new Map<number, HTMLButtonElement>());

  const users = useQuery({ queryKey: qk.users(), queryFn: ({ signal }) => api<UserAdmin[]>("/auth/users", { signal }) });

  useEffect(() => {
    if (pending !== null) confirmBtn.current?.focus();
  }, [pending]);

  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: qk.users() }), qc.invalidateQueries({ queryKey: qk.invites() })]);
  const backToRow = (id: number) => {
    roleSelects.current.get(id)?.focus();
  };

  const patch = useMutation({
    mutationFn: (v: { user: UserAdmin; body: UserPatch }) => api(`/auth/users/${v.user.id}`, { method: "PATCH", body: v.body }),
    onSuccess: async (_d, v) => {
      setError(null);
      flushSync(() => setPending(null));
      await refresh();
      backToRow(v.user.id);
    },
    onError: (e, v) => {
      flushSync(() => setPending(null));
      setError(adminError(e));
      void refresh();
      backToRow(v.user.id);
    },
  });

  const revoke = useMutation({
    mutationFn: (u: UserAdmin) => api(`/auth/users/${u.id}/sessions/revoke`, { method: "POST" }),
    onSuccess: async (_d, u) => {
      setError(null);
      flushSync(() => setPending(null));
      await refresh();
      backToRow(u.id);
    },
    onError: (e, u) => {
      flushSync(() => setPending(null));
      setError(adminError(e));
      backToRow(u.id);
    },
  });

  const reset = useMutation({
    // The token goes straight into local state and is not returned, so it never reaches a cache.
    mutationFn: async (u: UserAdmin) => {
      const res = await api<TokenIssued>(`/auth/users/${u.id}/reset`, { method: "POST" });
      setSecrets((l) => [
        ...l,
        {
          key: secretKey(),
          title: "Password reset link",
          subject: u.email,
          label: "Reset link (send it to the user)",
          value: `${location.origin}/reset/${res.token}`,
          expiresAt: res.expires_at,
        },
      ]);
    },
    onSuccess: () => {
      setError(null);
      return qc.invalidateQueries({ queryKey: qk.invites() });
    },
    onError: (e) => setError(adminError(e)),
  });

  const busy = patch.isPending || revoke.isPending;

  const confirmNow = () => {
    if (!pending) return;
    if (pending.action === "role") patch.mutate({ user: pending.user, body: { role: pending.role } });
    else if (pending.action === "active") patch.mutate({ user: pending.user, body: { is_active: pending.active } });
    else revoke.mutate(pending.user);
  };
  const cancel = () => {
    const id = pending?.user.id;
    flushSync(() => setPending(null));
    if (id !== undefined) backToRow(id);
  };
  const changeRole = (u: UserAdmin, role: Role) => {
    if (role === u.role) return;
    if (u.role === "admin" && role === "member") setPending({ user: u, action: "role", role });
    else patch.mutate({ user: u, body: { role } });
  };
  const doneSecret = (key: number) => {
    setSecrets((l) => l.filter((s) => s.key !== key));
    const last = [...resetBtns.current.values()][0];
    last?.focus();
  };

  return (
    <section className="page gutter">
      <h1>Users</h1>
      <SecretList items={secrets} onDone={doneSecret} />
      <div className="form-errors" aria-live="assertive">
        {error && <p>{error}</p>}
      </div>
      {users.isPending && <p role="status">Loading users…</p>}
      {users.isError && <p className="form-errors">Could not load users.</p>}
      {users.data && (
        <div className="stable-wrap">
          <table className="stable admin-table">
            <thead>
              <tr>
                <th scope="col">Email</th>
                <th scope="col">Role</th>
                <th scope="col">Active</th>
                <th scope="col">Active sessions</th>
                <th scope="col">Created</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {users.data.map((u) => {
                const self = me !== null && me.id === u.id;
                const name = decodeEntities(u.email);
                const mine = pending?.user.id === u.id ? pending : null;
                return (
                  <tr key={u.id}>
                    <td data-label="Email">
                      <Text value={u.email} /> {self && <span className="badge">You</span>}
                    </td>
                    <td data-label="Role">
                      <select
                        ref={(el) => {
                          if (el) roleSelects.current.set(u.id, el);
                          else roleSelects.current.delete(u.id);
                        }}
                        className="admin-select"
                        aria-label={`Role for ${name}`}
                        value={u.role}
                        disabled={self || busy}
                        onChange={(e) => changeRole(u, e.target.value === "admin" ? "admin" : "member")}
                      >
                        <option value="member">Member</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td data-label="Active">
                      <label className="check">
                        <input
                          type="checkbox"
                          role="switch"
                          checked={u.is_active}
                          disabled={self || busy}
                          aria-label={`Active: ${name}`}
                          onChange={(e) => setPending({ user: u, action: "active", active: e.target.checked })}
                        />
                        {u.is_active ? "Active" : "Inactive"}
                      </label>
                    </td>
                    <td data-label="Active sessions">{u.active_sessions}</td>
                    <td data-label="Created">{relTime(u.created_at, now) || "—"}</td>
                    <td>
                      {mine ? (
                        <span className="confirm" role="group" aria-label="Confirm">
                          <span>{confirmText(mine)}</span>
                          <button ref={confirmBtn} type="button" className="btn danger" disabled={busy} onClick={confirmNow}>
                            Confirm
                          </button>
                          <button type="button" className="btn" onClick={cancel}>
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <span className="rule-actions">
                          <button
                            type="button"
                            className="btn"
                            disabled={self || busy}
                            aria-label={`Revoke sessions for ${name}`}
                            onClick={() => setPending({ user: u, action: "revoke" })}
                          >
                            Revoke sessions
                          </button>
                          <button
                            ref={(el) => {
                              if (el) resetBtns.current.set(u.id, el);
                              else resetBtns.current.delete(u.id);
                            }}
                            type="button"
                            className="btn"
                            disabled={self || reset.isPending}
                            aria-label={`Reset password for ${name}`}
                            onClick={() => reset.mutate(u)}
                          >
                            Reset password
                          </button>
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
