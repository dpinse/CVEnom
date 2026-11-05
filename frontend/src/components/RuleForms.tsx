import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState, type FormEvent } from "react";
import { api } from "../lib/api";
import { adminError } from "../lib/adminErrors";
import { qk } from "../lib/queries";
import {
  KIND_LABEL,
  MAX_RECIPIENTS,
  conditionProblem,
  nameProblem,
  newDraft,
  recipientProblem,
  toRecipientIn,
  type RecipientDraft,
} from "../lib/ruleValidation";
import { Text, decodeEntities } from "../lib/text";
import type { AlertRule, Recipient, RuleKind, RulePatch } from "../lib/types";
import { ErrorSummary, Field } from "./formParts";
import { secretKey, type SecretItem } from "./OneTimeSecret";

/** Pulls one-time webhook secrets out of a server response and drops them from what is returned. */
function takeSecrets(recipients: Recipient[], expiresAt?: string): { secrets: SecretItem[]; rest: Recipient[] } {
  const secrets: SecretItem[] = [];
  const rest = recipients.map((r) => {
    if (r.channel !== "webhook" || r.secret === undefined) return r;
    const { secret, ...clean } = r;
    secrets.push({
      key: secretKey(),
      title: "Webhook secret",
      subject: r.url_masked ?? "webhook",
      label: "Webhook signing secret",
      value: secret,
      expiresAt,
    });
    return clean;
  });
  return { secrets, rest };
}

const KINDS: RuleKind[] = ["kev_added", "cvss_min", "epss_min", "keyword"];

export function RecipientFields({
  draft,
  onChange,
  index,
}: {
  draft: RecipientDraft;
  onChange: (d: RecipientDraft) => void;
  index: number;
}) {
  const n = index + 1;
  return (
    <>
      <label className="field">
        <span>Recipient {n} type</span>
        <select
          className="admin-select"
          value={draft.channel}
          onChange={(e) => onChange({ ...draft, channel: e.target.value === "webhook" ? "webhook" : "email" })}
        >
          <option value="email">Email</option>
          <option value="webhook">Webhook</option>
        </select>
      </label>
      {draft.channel === "email" ? (
        <Field
          label={`Recipient ${n} email`}
          type="email"
          value={draft.email}
          onChange={(v) => onChange({ ...draft, email: v })}
          autoComplete="off"
          maxLength={254}
          required={false}
        />
      ) : (
        <>
          <Field
            label={`Recipient ${n} webhook URL`}
            type="url"
            value={draft.url}
            onChange={(v) => onChange({ ...draft, url: v })}
            autoComplete="off"
            maxLength={4096}
            required={false}
            hint="Must be an https:// address. The server also checks that it is a public endpoint."
          />
          <Field
            label={`Recipient ${n} webhook secret (optional)`}
            type="password"
            value={draft.secret}
            onChange={(v) => onChange({ ...draft, secret: v })}
            autoComplete="off"
            maxLength={256}
            required={false}
            hint="Leave blank to generate. 16 to 256 characters. Shown once after you save."
          />
        </>
      )}
    </>
  );
}

export function RuleCreateForm({
  onSecrets,
  onClose,
}: {
  onSecrets: (items: SecretItem[]) => void;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<RuleKind>("kev_added");
  const [threshold, setThreshold] = useState("");
  const [keyword, setKeyword] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [drafts, setDrafts] = useState<RecipientDraft[]>(() => [newDraft()]);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const inflight = useRef(false);

  const fail = (list: string[]) => {
    setErrors(list);
    setTick((t) => t + 1);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (inflight.current) return;
    const problems: string[] = [];
    const np = nameProblem(name);
    if (np) problems.push(np);
    const cond = conditionProblem(kind, threshold, keyword);
    if (cond.problem) problems.push(cond.problem);
    if (drafts.length < 1) problems.push("Add at least one recipient");
    drafts.forEach((d, i) => {
      const p = recipientProblem(d);
      if (p) problems.push(`Recipient ${i + 1}: ${p}`);
    });
    if (problems.length > 0) return fail(problems);
    inflight.current = true;
    setBusy(true);
    setErrors([]);
    try {
      // Plain request (not useMutation): a typed webhook secret must not sit in the mutation cache as `variables`.
      const body = {
        name: name.trim(),
        kind,
        ...(cond.threshold !== null ? { threshold: cond.threshold } : {}),
        ...(cond.keyword !== null ? { keyword: cond.keyword } : {}),
        enabled,
        recipients: drafts.map(toRecipientIn),
      };
      const rule = await api<AlertRule>("/alerts/rules", { method: "POST", body });
      const { secrets } = takeSecrets(rule.recipients);
      if (secrets.length > 0) onSecrets(secrets);
      await qc.invalidateQueries({ queryKey: qk.alerts() });
      onClose();
    } catch (err) {
      fail([adminError(err)]);
    } finally {
      inflight.current = false;
      setBusy(false);
    }
  };

  const setDraft = (i: number, d: RecipientDraft) => setDrafts((l) => l.map((x, j) => (j === i ? d : x)));

  return (
    <form className="admin-form" onSubmit={(e) => void submit(e)} noValidate aria-label="New alert rule">
      <h2>New alert rule</h2>
      <ErrorSummary errors={errors} tick={tick} />
      <Field label="Name" type="text" value={name} onChange={setName} autoComplete="off" maxLength={200} required={false} />
      <label className="field">
        <span>Kind</span>
        <select className="admin-select" value={kind} onChange={(e) => setKind(e.target.value as RuleKind)}>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {KIND_LABEL[k]}
            </option>
          ))}
        </select>
      </label>
      {(kind === "cvss_min" || kind === "epss_min") && (
        <Field
          label={kind === "cvss_min" ? "CVSS threshold (0 to 10)" : "EPSS threshold (0 to 1)"}
          type="text"
          value={threshold}
          onChange={setThreshold}
          autoComplete="off"
          maxLength={12}
          required={false}
        />
      )}
      {kind === "keyword" && (
        <Field label="Keyword (1 to 100 characters)" type="text" value={keyword} onChange={setKeyword} autoComplete="off" maxLength={100} required={false} />
      )}
      <label className="check">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
      </label>
      {drafts.map((d, i) => (
        <fieldset key={d.key}>
          <legend>Recipient {i + 1}</legend>
          <RecipientFields draft={d} index={i} onChange={(nd) => setDraft(i, nd)} />
          {drafts.length > 1 && (
            <button type="button" className="btn" onClick={() => setDrafts((l) => l.filter((x) => x.key !== d.key))}>
              Remove recipient {i + 1}
            </button>
          )}
        </fieldset>
      ))}
      <div className="admin-row">
        <button type="button" className="btn" disabled={drafts.length >= MAX_RECIPIENTS} onClick={() => setDrafts((l) => [...l, newDraft()])}>
          Add another recipient
        </button>
        <span className="form-hint">
          {drafts.length} of {MAX_RECIPIENTS}
        </span>
      </div>
      <div className="admin-row">
        <button type="submit" className="btn primary" disabled={busy}>
          {busy ? "Creating…" : "Create rule"}
        </button>
        <button type="button" className="btn" onClick={onClose}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function RuleEditForm({
  rule,
  onSecrets,
  onClose,
}: {
  rule: AlertRule;
  onSecrets: (items: SecretItem[]) => void;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(decodeEntities(rule.name));
  const [threshold, setThreshold] = useState(rule.threshold === null ? "" : String(rule.threshold));
  const [keyword, setKeyword] = useState(decodeEntities(rule.keyword ?? ""));
  const [enabled, setEnabled] = useState(rule.enabled);
  const [errors, setErrors] = useState<string[]>([]);
  const [tick, setTick] = useState(0);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<RecipientDraft>(() => newDraft());
  const [adding, setAdding] = useState(false);
  const [recErrors, setRecErrors] = useState<string[]>([]);
  const [recTick, setRecTick] = useState(0);
  const inflight = useRef(false);
  const addRef = useRef<HTMLButtonElement>(null);

  const fail = (list: string[]) => {
    setErrors(list);
    setTick((t) => t + 1);
  };
  const refresh = () => qc.invalidateQueries({ queryKey: qk.alerts() });

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (inflight.current) return;
    const problems: string[] = [];
    const np = nameProblem(name);
    if (np) problems.push(np);
    const cond = conditionProblem(rule.kind, threshold, keyword);
    if (cond.problem) problems.push(cond.problem);
    if (problems.length > 0) return fail(problems);
    inflight.current = true;
    setBusy(true);
    setErrors([]);
    try {
      // Only the four editable fields; `kind` is immutable and never sent.
      const patch: RulePatch = { name: name.trim(), enabled };
      if (rule.kind === "cvss_min" || rule.kind === "epss_min") patch.threshold = cond.threshold;
      if (rule.kind === "keyword") patch.keyword = cond.keyword;
      await api(`/alerts/rules/${rule.id}`, { method: "PATCH", body: patch });
      await refresh();
      onClose();
    } catch (err) {
      fail([adminError(err)]);
    } finally {
      inflight.current = false;
      setBusy(false);
    }
  };

  const addRecipient = async () => {
    if (inflight.current) return;
    const p = recipientProblem(draft);
    if (p) {
      setRecErrors([p]);
      setRecTick((t) => t + 1);
      return;
    }
    inflight.current = true;
    setAdding(true);
    setRecErrors([]);
    try {
      const rec = await api<Recipient>(`/alerts/rules/${rule.id}/recipients`, { method: "POST", body: toRecipientIn(draft) });
      onSecrets(takeSecrets([rec]).secrets);
      setDraft(newDraft());
      await refresh();
    } catch (err) {
      setRecErrors([adminError(err)]);
      setRecTick((t) => t + 1);
    } finally {
      inflight.current = false;
      setAdding(false);
    }
  };

  const removeRecipient = async (r: Recipient) => {
    if (inflight.current) return;
    inflight.current = true;
    setRecErrors([]);
    try {
      await api(`/alerts/rules/${rule.id}/recipients/${r.id}`, { method: "DELETE" });
      await refresh();
      addRef.current?.focus();
    } catch (err) {
      setRecErrors([adminError(err)]);
      setRecTick((t) => t + 1);
    } finally {
      inflight.current = false;
    }
  };

  return (
    <div className="admin-form" role="group" aria-label={`Edit rule ${decodeEntities(rule.name)}`}>
      <form className="admin-section" onSubmit={(e) => void save(e)} noValidate>
        <ErrorSummary errors={errors} tick={tick} />
        <p className="form-hint">
          Kind: <strong>{KIND_LABEL[rule.kind]}</strong> (can&apos;t be changed)
        </p>
        <Field label="Name" type="text" value={name} onChange={setName} autoComplete="off" maxLength={200} required={false} />
        {(rule.kind === "cvss_min" || rule.kind === "epss_min") && (
          <Field
            label={rule.kind === "cvss_min" ? "CVSS threshold (0 to 10)" : "EPSS threshold (0 to 1)"}
            type="text"
            value={threshold}
            onChange={setThreshold}
            autoComplete="off"
            maxLength={12}
            required={false}
          />
        )}
        {rule.kind === "keyword" && (
          <Field label="Keyword (1 to 100 characters)" type="text" value={keyword} onChange={setKeyword} autoComplete="off" maxLength={100} required={false} />
        )}
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
        </label>
        <div className="admin-row">
          <button type="submit" className="btn primary" disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </form>

      <div className="admin-section">
        <h3>Recipients</h3>
        <ErrorSummary errors={recErrors} tick={recTick} />
        <p className="form-hint">To change a recipient, remove it and add a new one.</p>
        <ul className="recips">
          {rule.recipients.map((r) => (
            <li key={r.id}>
              <span className="badge">{r.channel}</span>
              <Text value={r.channel === "email" ? r.email : (r.url_masked ?? "(webhook)")} />
              <button
                type="button"
                className="btn"
                aria-label={`Remove recipient ${decodeEntities(r.channel === "email" ? r.email : (r.url_masked ?? "webhook"))}`}
                onClick={() => void removeRecipient(r)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
        <fieldset>
          <legend>Add recipient</legend>
          <RecipientFields draft={draft} index={rule.recipients.length} onChange={setDraft} />
          <button
            ref={addRef}
            type="button"
            className="btn"
            disabled={adding || rule.recipients.length >= MAX_RECIPIENTS}
            onClick={() => void addRecipient()}
          >
            {adding ? "Adding…" : "Add recipient"}
          </button>
        </fieldset>
      </div>
    </div>
  );
}
