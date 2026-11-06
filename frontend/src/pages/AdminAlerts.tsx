import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Deliveries } from "../components/Deliveries";
import { SecretList, type SecretItem } from "../components/OneTimeSecret";
import { RuleCreateForm, RuleEditForm } from "../components/RuleForms";
import { adminError } from "../lib/adminErrors";
import { ApiError, RateLimited, api } from "../lib/api";
import { qk } from "../lib/queries";
import { KIND_LABEL } from "../lib/ruleValidation";
import { Text, decodeEntities } from "../lib/text";
import type { AlertRule, TestSendResult } from "../lib/types";

function Condition({ rule }: { rule: AlertRule }) {
  switch (rule.kind) {
    case "kev_added":
      return <>Any CVE newly added to KEV</>;
    case "cvss_min":
      return <>CVSS ≥ {rule.threshold}</>;
    case "epss_min":
      return <>EPSS ≥ {rule.threshold}</>;
    case "keyword":
      return (
        <>
          Keyword: <Text value={rule.keyword ?? ""} />
        </>
      );
  }
}

function recipientLabel(rule: AlertRule, id: number): string {
  const r = rule.recipients.find((x) => x.id === id);
  if (!r) return `Recipient #${id}`;
  return r.channel === "email" ? r.email : (r.url_masked ?? "webhook");
}

function testError(e: unknown): string {
  if (e instanceof RateLimited) return `Too many test sends. Try again in ${e.retryAfter} seconds.`;
  if (e instanceof ApiError && e.status === 504) return "Test timed out — some recipients may still receive it";
  return adminError(e);
}

function TestSend({ rule }: { rule: AlertRule }) {
  const test = useMutation({
    mutationFn: () => api<TestSendResult[]>(`/alerts/rules/${rule.id}/test`, { method: "POST" }),
  });
  const hint = `test-hint-${rule.id}`;
  return (
    <div className="admin-section" style={{ margin: 0 }}>
      <div className="admin-row">
        <button
          type="button"
          className="btn"
          disabled={test.isPending || rule.recipients.length === 0}
          aria-describedby={hint}
          onClick={() => test.mutate()}
        >
          {test.isPending && <span className="spinner" aria-hidden="true" />}
          {test.isPending ? "Sending test…" : "Send test"}
        </button>
        <small id={hint} className="field-hint">
          Sends a clearly-labelled TEST alert to every recipient of this rule
        </small>
      </div>
      <div aria-live="polite">
        {rule.recipients.length === 0 && <p className="form-hint">This rule has no recipients</p>}
        {test.isError && <p className="form-errors">{testError(test.error)}</p>}
        {test.data && (
          <ul className="test-results" aria-label={`Test results for ${decodeEntities(rule.name)}`}>
            {test.data.map((r) => (
              <li key={r.recipient_id}>
                <span className="badge">{r.channel}</span> <Text value={recipientLabel(rule, r.recipient_id)} />{" "}
                <span className={r.ok ? "test-ok" : "test-fail"}>{r.ok ? "OK" : "Failed"}</span>
                {r.error ? (
                  <>
                    {": "}
                    <Text value={r.error} />
                  </>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default function AdminAlerts() {
  const qc = useQueryClient();
  const [secrets, setSecrets] = useState<SecretItem[]>([]);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<number | null>(null);
  const [confirming, setConfirming] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const newBtn = useRef<HTMLButtonElement>(null);
  const listHead = useRef<HTMLHeadingElement>(null);
  const confirmBtn = useRef<HTMLButtonElement>(null);
  const editBtns = useRef(new Map<number, HTMLButtonElement>());
  const delBtns = useRef(new Map<number, HTMLButtonElement>());

  const rules = useQuery({
    queryKey: qk.rules(),
    queryFn: ({ signal }) => api<AlertRule[]>("/alerts/rules", { signal }),
  });

  useEffect(() => {
    if (confirming !== null) confirmBtn.current?.focus();
  }, [confirming]);

  const refresh = () => qc.invalidateQueries({ queryKey: qk.alerts() });

  const toggle = useMutation({
    mutationFn: (v: { rule: AlertRule; enabled: boolean }) =>
      api(`/alerts/rules/${v.rule.id}`, { method: "PATCH", body: { enabled: v.enabled } }),
    onSuccess: () => {
      setError(null);
      return refresh();
    },
    onError: (e) => {
      setError(adminError(e));
      void refresh();
    },
  });

  const del = useMutation({
    mutationFn: (r: AlertRule) => api(`/alerts/rules/${r.id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setError(null);
      flushSync(() => setConfirming(null));
      await refresh();
      listHead.current?.focus();
    },
    onError: (e) => {
      setConfirming(null);
      setError(adminError(e));
      void refresh();
    },
  });

  const addSecrets = (items: SecretItem[]) => setSecrets((l) => [...l, ...items]);
  const doneSecret = (key: number) => {
    setSecrets((l) => l.filter((s) => s.key !== key));
    newBtn.current?.focus();
  };

  const closeCreate = () => {
    flushSync(() => setCreating(false));
    newBtn.current?.focus();
  };
  const closeEdit = (id: number) => {
    flushSync(() => setEditing(null));
    editBtns.current.get(id)?.focus();
  };
  const cancelDelete = (id: number) => {
    flushSync(() => setConfirming(null));
    delBtns.current.get(id)?.focus();
  };

  return (
    <section className="page gutter">
      <h1>Alert rules</h1>
      <SecretList items={secrets} onDone={doneSecret} />
      <div className="admin-section">
        <div className="admin-row">
          <h2 ref={listHead} tabIndex={-1}>
            Rules
          </h2>
          <button
            ref={newBtn}
            type="button"
            className="btn primary"
            disabled={creating}
            onClick={() => setCreating(true)}
          >
            New rule
          </button>
        </div>
        <div className="form-errors" aria-live="assertive">
          {error && <p>{error}</p>}
        </div>
        {creating && <RuleCreateForm onSecrets={addSecrets} onClose={closeCreate} />}
        {rules.isPending && <p role="status">Loading rules…</p>}
        {rules.isError && <p className="form-errors">Could not load rules.</p>}
        {rules.data && rules.data.length === 0 && <p className="form-hint">No alert rules yet.</p>}
        {rules.data && rules.data.length > 0 && (
          <ul className="rules">
            {rules.data.map((r) => (
              <li key={r.id} className="rule">
                <div className="rule-head">
                  <span className="rule-name">
                    <Text value={r.name} />
                  </span>
                  <span className="badge">{KIND_LABEL[r.kind]}</span>
                  <span className="rule-cond">
                    <Condition rule={r} />
                  </span>
                  <label className="check">
                    <input
                      type="checkbox"
                      role="switch"
                      checked={r.enabled}
                      disabled={toggle.isPending}
                      aria-label={`Enabled: ${decodeEntities(r.name)}`}
                      onChange={(e) => toggle.mutate({ rule: r, enabled: e.target.checked })}
                    />
                    Enabled
                  </label>
                  <span className="rule-meta">
                    {r.recipients.length} {r.recipients.length === 1 ? "recipient" : "recipients"}
                  </span>
                  <div className="rule-actions">
                    <button
                      ref={(el) => {
                        if (el) editBtns.current.set(r.id, el);
                        else editBtns.current.delete(r.id);
                      }}
                      type="button"
                      className="btn"
                      aria-label={`Edit ${decodeEntities(r.name)}`}
                      aria-expanded={editing === r.id}
                      onClick={() => setEditing(editing === r.id ? null : r.id)}
                    >
                      Edit
                    </button>
                    {confirming === r.id ? (
                      <span className="confirm">
                        <span>Delete this rule and its recipients?</span>
                        <button
                          ref={confirmBtn}
                          type="button"
                          className="btn danger"
                          disabled={del.isPending}
                          onClick={() => del.mutate(r)}
                        >
                          Confirm delete
                        </button>
                        <button type="button" className="btn" onClick={() => cancelDelete(r.id)}>
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        ref={(el) => {
                          if (el) delBtns.current.set(r.id, el);
                          else delBtns.current.delete(r.id);
                        }}
                        type="button"
                        className="btn danger"
                        aria-label={`Delete ${decodeEntities(r.name)}`}
                        onClick={() => setConfirming(r.id)}
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>
                {editing === r.id && <RuleEditForm rule={r} onSecrets={addSecrets} onClose={() => closeEdit(r.id)} />}
                <TestSend rule={r} />
              </li>
            ))}
          </ul>
        )}
      </div>
      <Deliveries rules={rules.data ?? []} />
    </section>
  );
}
