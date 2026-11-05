import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { getAuth } from "../lib/auth";
import { qk } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { Text } from "../lib/text";
import type { SessionInfo } from "../lib/types";
import { useNow } from "../lib/useNow";
import { commonError } from "../components/formParts";

export default function Sessions() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const now = useNow();
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const list = useQuery({ queryKey: qk.sessions(), queryFn: () => api<SessionInfo[]>("/auth/sessions") });

  const revoke = useMutation({
    mutationFn: async (s: SessionInfo) => {
      try {
        await api(`/auth/sessions/${encodeURIComponent(s.id)}`, { method: "DELETE" });
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 404)) throw e; // 404: already gone
      }
      return s;
    },
    onSuccess: async (s) => {
      setConfirming(null);
      setError(null);
      if (s.current) {
        await getAuth().logout();
        navigate("/login", { replace: true });
        return;
      }
      await qc.invalidateQueries({ queryKey: qk.sessions() });
    },
    onError: (e) => {
      setConfirming(null);
      setError(commonError(e));
    },
  });

  return (
    <section className="page gutter">
      <h1>Sessions</h1>
      <p className="form-hint">Devices signed in to your account. Revoke any you do not recognize.</p>
      <div className="form-errors" aria-live="assertive">
        {error && <p>{error}</p>}
      </div>
      {list.isPending && <p role="status">Loading sessions…</p>}
      {list.isError && <p className="form-errors">Could not load sessions.</p>}
      {list.data && (
        <div className="stable-wrap">
          <table className="stable sessions">
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">IP</th>
                <th scope="col">Last used</th>
                <th scope="col">Created</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((s) => (
                <tr key={s.id}>
                  <td>
                    {s.user_agent ? <Text value={s.user_agent} /> : "Unknown device"}{" "}
                    {s.current && <span className="badge">This device</span>}
                  </td>
                  <td>{s.ip ? <Text value={s.ip} /> : "—"}</td>
                  <td>{relTime(s.last_used_at, now) || "—"}</td>
                  <td>{relTime(s.created_at, now) || "—"}</td>
                  <td>
                    {confirming === s.id ? (
                      <span className="confirm">
                        <span>{s.current ? "Sign out of this device?" : "Revoke this session?"}</span>{" "}
                        <button type="button" className="btn danger" disabled={revoke.isPending} onClick={() => revoke.mutate(s)}>
                          Confirm revoke
                        </button>{" "}
                        <button type="button" className="btn" onClick={() => setConfirming(null)}>
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button type="button" className="btn" onClick={() => setConfirming(s.id)}>
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
    </section>
  );
}
