import { useEffect, useState } from "react";
import { cweName } from "../../lib/cwe";
import { cweUrl } from "../../lib/refLinks";
import { ExternalLink, Text } from "../../lib/text";

/** The CWE name arrives from a lazy chunk; until then (or when unknown) the id stands alone. */
function useCweName(id: string): string | null {
  const [found, setFound] = useState<{ id: string; name: string | null } | null>(null);
  useEffect(() => {
    let live = true;
    void cweName(id).then((name) => {
      if (live) setFound({ id, name });
    });
    return () => {
      live = false;
    };
  }, [id]);
  return found?.id === id ? found.name : null;
}

function WeaknessRow({ id }: { id: string }) {
  const name = useCweName(id);
  const url = cweUrl(id);
  return (
    <li>
      <b className="mono">
        <Text value={id} />
      </b>
      {name ? <> · {name}</> : null}
      {url ? (
        <>
          {" "}
          <ExternalLink href={url}>MITRE definition</ExternalLink>
        </>
      ) : null}
    </li>
  );
}

export function Weakness({ cwes }: { cwes: string[] }) {
  return (
    <section className="blk" aria-labelledby="t-cwe">
      <h2 id="t-cwe">Weakness</h2>
      <ul className="plain">
        {cwes.map((c, i) => (
          <WeaknessRow key={`${c}#${i}`} id={c} />
        ))}
      </ul>
      <p className="muted small">From the MITRE CWE catalog.</p>
    </section>
  );
}
