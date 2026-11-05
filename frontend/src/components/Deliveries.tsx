import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../lib/api";
import { qk } from "../lib/queries";
import { relTime } from "../lib/relTime";
import { useSelection } from "../lib/selection";
import { Text } from "../lib/text";
import type { AlertRule, DeliveriesOut } from "../lib/types";
import { useNow } from "../lib/useNow";

export const DELIVERIES_PAGE_SIZE = 50;
export const DELIVERIES_REFETCH_MS = 30_000;

export function Deliveries({ rules }: { rules: AlertRule[] }) {
  const now = useNow();
  const { select } = useSelection();
  const [status, setStatus] = useState("");
  const [rule, setRule] = useState("");
  const [page, setPage] = useState(1);

  const q = useQuery({
    queryKey: qk.deliveries({ status, rule, page }),
    queryFn: ({ signal }) => {
      const sp = new URLSearchParams({ page: String(page), page_size: String(DELIVERIES_PAGE_SIZE) });
      if (status) sp.set("status", status);
      if (rule) sp.set("rule_id", rule);
      return api<DeliveriesOut>(`/alerts/deliveries?${sp.toString()}`, { signal });
    },
    placeholderData: keepPreviousData,
    // Paused automatically while the tab is hidden (refetchIntervalInBackground defaults to false).
    refetchInterval: DELIVERIES_REFETCH_MS,
  });

  const names = new Map(rules.map((r) => [r.id, r.name]));
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / DELIVERIES_PAGE_SIZE));

  return (
    <section className="admin-section" aria-labelledby="deliveries-h">
      <h2 id="deliveries-h">Deliveries</h2>
      <div className="admin-row">
        <label className="field">
          <span>Status</span>
          <select
            className="admin-select"
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All</option>
            <option value="pending">Pending</option>
            <option value="sent">Sent</option>
            <option value="failed">Failed</option>
          </select>
        </label>
        <label className="field">
          <span>Rule</span>
          <select
            className="admin-select"
            value={rule}
            onChange={(e) => {
              setRule(e.target.value);
              setPage(1);
            }}
          >
            <option value="">All rules</option>
            {rules.map((r) => (
              <option key={r.id} value={String(r.id)}>
                <Text value={r.name} />
              </option>
            ))}
          </select>
        </label>
      </div>
      {q.isPending && <p role="status">Loading deliveries…</p>}
      {q.isError && !q.data && <p className="form-errors">Could not load deliveries.</p>}
      {q.data && q.data.items.length === 0 && <p className="form-hint">No deliveries match.</p>}
      {q.data && q.data.items.length > 0 && (
        <div className="stable-wrap" aria-busy={q.isFetching}>
          <table className="stable admin-table">
            <thead>
              <tr>
                <th scope="col">Status</th>
                <th scope="col">CVE</th>
                <th scope="col">Rule</th>
                <th scope="col">Channel</th>
                <th scope="col">Attempts</th>
                <th scope="col">Last error</th>
                <th scope="col">Created</th>
                <th scope="col">Sent</th>
                <th scope="col">Next attempt</th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((d) => (
                <tr key={d.id}>
                  <td data-label="Status">
                    <span className={`chip ${d.status}`}>{d.status}</span>
                  </td>
                  <td data-label="CVE">
                    <button type="button" className="sid" onClick={() => select({ kind: "cve", id: d.cve_id })}>
                      <Text value={d.cve_id} />
                    </button>
                  </td>
                  <td data-label="Rule">{names.has(d.rule_id) ? <Text value={names.get(d.rule_id) ?? ""} /> : `Rule #${d.rule_id}`}</td>
                  <td data-label="Channel">{d.channel}</td>
                  <td data-label="Attempts">{d.attempts}</td>
                  <td data-label="Last error">{d.last_error ? <Text value={d.last_error} /> : "—"}</td>
                  <td data-label="Created">{relTime(d.created_at, now) || "—"}</td>
                  <td data-label="Sent">{relTime(d.sent_at, now) || "—"}</td>
                  <td data-label="Next attempt">{relTime(d.next_attempt_at, now) || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.data && total > DELIVERIES_PAGE_SIZE && (
        <nav className="spager" aria-label="Deliveries pages">
          <button type="button" className="btn" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            Previous
          </button>
          <span className="num">
            Page {page} of {pages}
          </span>
          <button type="button" className="btn" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
            Next
          </button>
        </nav>
      )}
    </section>
  );
}
