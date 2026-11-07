export interface CvssMetric {
  key: string;
  label: string;
  value: string;
}
export interface DecodedCvss {
  version: "3.0" | "3.1" | "4.0";
  metrics: CvssMetric[];
}

type Spec = readonly [key: string, label: string, values: Readonly<Record<string, string>>];

const CIA = { H: "High", L: "Low", N: "None" } as const;
const AV = { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } as const;
const LOW_HIGH = { L: "Low", H: "High" } as const;
const PR = { N: "None", L: "Low", H: "High" } as const;

const V3: readonly Spec[] = [
  ["AV", "Attack vector", AV],
  ["AC", "Complexity", LOW_HIGH],
  ["PR", "Privileges needed", PR],
  ["UI", "User interaction", { N: "None", R: "Required" }],
  ["S", "Scope", { U: "Unchanged", C: "Changed" }],
  ["C", "Confidentiality", CIA],
  ["I", "Integrity", CIA],
  ["A", "Availability", CIA],
];

const V4: readonly Spec[] = [
  ["AV", "Attack vector", AV],
  ["AC", "Complexity", LOW_HIGH],
  ["AT", "Attack requirements", { N: "None", P: "Present" }],
  ["PR", "Privileges needed", PR],
  ["UI", "User interaction", { N: "None", P: "Passive", A: "Active" }],
  ["VC", "Confidentiality", CIA],
  ["VI", "Integrity", CIA],
  ["VA", "Availability", CIA],
  ["SC", "Subsequent confidentiality", CIA],
  ["SI", "Subsequent integrity", CIA],
  ["SA", "Subsequent availability", CIA],
];

const PREFIX: Record<string, { version: DecodedCvss["version"]; specs: readonly Spec[] }> = {
  "CVSS:3.0": { version: "3.0", specs: V3 },
  "CVSS:3.1": { version: "3.1", specs: V3 },
  "CVSS:4.0": { version: "4.0", specs: V4 },
};

/**
 * Decodes the base metrics of a CVSS 3.x / 4.0 vector into labelled values, in the order of the spec tables.
 * Threat, environmental and supplemental metrics are ignored. Anything unrecognised or incomplete gives null.
 */
export function decodeCvss(vector: string): DecodedCvss | null {
  if (typeof vector !== "string") return null;
  const parts = vector.trim().split("/");
  const head = PREFIX[parts[0]];
  if (!head) return null;
  const given = new Map<string, string>();
  for (const p of parts.slice(1)) {
    const i = p.indexOf(":");
    if (i <= 0) return null;
    const k = p.slice(0, i);
    if (given.has(k)) return null;
    given.set(k, p.slice(i + 1));
  }
  const metrics: CvssMetric[] = [];
  for (const [key, label, values] of head.specs) {
    const raw = given.get(key);
    if (raw === undefined || !Object.hasOwn(values, raw)) return null;
    metrics.push({ key, label, value: values[raw] });
  }
  // Base keys with an unknown value were rejected above; a key outside the base set is a threat/supplemental metric.
  return { version: head.version, metrics };
}
