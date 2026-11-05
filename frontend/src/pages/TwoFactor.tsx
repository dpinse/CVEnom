import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { CodeForm, RecoveryCodes, useNoReferrer } from "../components/MfaSteps";
import { api } from "../lib/api";
import { qk } from "../lib/queries";
import type { MfaStatus } from "../lib/types";

const TOTAL = 10;
const LOW = 3;

/**
 * Account → Two-factor. Only the status (enabled, codes remaining) goes through the query cache.
 * New recovery codes come straight from a direct request into local state, never a cache, URL or
 * storage, and are dropped on "Done".
 */
export default function TwoFactor() {
  useNoReferrer();
  const qc = useQueryClient();
  const [codes, setCodes] = useState<string[] | null>(null);
  const status = useQuery({ queryKey: qk.mfa(), queryFn: ({ signal }) => api<MfaStatus>("/auth/mfa", { signal }) });

  const regenerate = async (code: string) => {
    const res = await api<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { method: "POST", body: { code } });
    setCodes(res.recovery_codes);
    await qc.invalidateQueries({ queryKey: qk.mfa() });
  };

  const s = status.data;
  return (
    <section className="page gutter">
      <h1>Two-factor authentication</h1>
      {status.isPending && <p role="status">Loading…</p>}
      {status.isError && <p className="form-errors">Could not load the two-factor status.</p>}
      {s && (
        <dl className="mfa-status">
          <dt>Status</dt>
          <dd>
            <strong>{s.enabled ? "On" : "Not set up"}</strong>
          </dd>
          <dt>Recovery codes</dt>
          <dd>
            {s.recovery_codes_remaining} of {TOTAL} recovery codes left
            {s.recovery_codes_remaining <= LOW && (
              <span className="form-notice"> — you&apos;re running low. Generate new ones below.</span>
            )}
          </dd>
        </dl>
      )}
      {codes ? (
        <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />
      ) : (
        <div className="authcard">
          <h2>New recovery codes</h2>
          <CodeForm
            hint="Enter a current code from your authenticator app. Your old recovery codes will stop working."
            submitLabel="Get new recovery codes"
            onSubmit={regenerate}
          />
        </div>
      )}
    </section>
  );
}
