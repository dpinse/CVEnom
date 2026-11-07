import { versionText } from "../../lib/threatModel";
import { Text } from "../../lib/text";
import type { CveDetail } from "../../lib/types";
import { dayOf } from "./format";

export function WhatToDo({ d }: { d: CveDetail }) {
  const versions = d.affected_versions ?? [];
  return (
    <section className="blk" aria-labelledby="t-todo">
      <h2 id="t-todo">What to do</h2>
      {d.kev_action ? (
        <div className="action" data-testid="kev-action">
          <b>
            <Text value={d.kev_action} />
          </b>
          <span className="who2">
            CISA required action.
            {d.kev_due ? ` Federal agencies must comply by ${dayOf(d.kev_due) || d.kev_due}.` : ""}
          </span>
          {d.kev_notes ? (
            <span className="who2">
              <Text value={d.kev_notes} />
            </span>
          ) : null}
        </div>
      ) : null}
      {versions.length === 0 ? (
        <p className="muted">No version data yet. See the vendor advisory.</p>
      ) : (
        <div className="tbl-wrap">
          <table className="vers">
            <thead>
              <tr>
                <th scope="col">Product</th>
                <th scope="col">Affected versions</th>
                <th scope="col">Fixed in</th>
                <th scope="col">Source</th>
              </tr>
            </thead>
            <tbody>
              {versions.map((v, i) => {
                const t = versionText(v);
                return (
                  <tr key={`${v.product}#${v.introduced}#${v.fixed}#${v.last_affected}#${i}`}>
                    <td>
                      <Text value={v.product} />
                    </td>
                    <td className="mono">
                      <Text value={t.affected} />
                    </td>
                    <td className={`mono${v.fixed ? "" : " nofix"}`}>
                      <Text value={t.fixed} />
                    </td>
                    <td className="muted">{v.source}</td>
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
