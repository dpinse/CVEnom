import type { RecipientIn, RuleKind } from "./types";

export const MAX_RECIPIENTS = 20;
export const KIND_LABEL: Record<RuleKind, string> = {
  kev_added: "New KEV",
  cvss_min: "CVSS minimum",
  epss_min: "EPSS minimum",
  keyword: "Keyword",
};

export function hasControl(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

export interface RecipientDraft {
  key: number;
  channel: "email" | "webhook";
  email: string;
  url: string;
  secret: string;
}

let nextKey = 1;
export function newDraft(channel: "email" | "webhook" = "email"): RecipientDraft {
  return { key: nextKey++, channel, email: "", url: "", secret: "" };
}

/** Client mirror of the server checks. The server validates again (and resolves DNS). */
export function recipientProblem(d: RecipientDraft): string | null {
  if (d.channel === "email") {
    const e = d.email.trim();
    if (e.length === 0 || e.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
      return "Enter a valid recipient email address";
    }
    return null;
  }
  const raw = d.url.trim();
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return "Webhook address must be a valid https URL";
  }
  if (raw.length > 4096 || u.protocol !== "https:") return "Webhook address must use https";
  if (u.username !== "" || u.password !== "") return "Webhook address must not contain a username or password";
  const s = d.secret;
  if (s !== "" && (s.length < 16 || s.length > 256))
    return "Webhook secret must be 16 to 256 characters (or leave blank to generate one)";
  return null;
}

export function toRecipientIn(d: RecipientDraft): RecipientIn {
  if (d.channel === "email") return { channel: "email", email: d.email.trim() };
  return d.secret === ""
    ? { channel: "webhook", url: d.url.trim() }
    : { channel: "webhook", url: d.url.trim(), secret: d.secret };
}

export function parseNumber(raw: string): number | null {
  const t = raw.trim();
  if (!/^-?(\d+\.?\d*|\.\d+)$/.test(t)) return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

/** Validates the kind-specific field. Returns the value to send and any problem. */
export function conditionProblem(
  kind: RuleKind,
  thresholdRaw: string,
  keywordRaw: string,
): { threshold: number | null; keyword: string | null; problem: string | null } {
  if (kind === "kev_added") return { threshold: null, keyword: null, problem: null };
  if (kind === "keyword") {
    const k = keywordRaw.trim();
    if (k.length < 1 || k.length > 100 || hasControl(k)) {
      return {
        threshold: null,
        keyword: null,
        problem: "Keyword must be 1 to 100 characters with no control characters",
      };
    }
    return { threshold: null, keyword: k, problem: null };
  }
  const hi = kind === "cvss_min" ? 10 : 1;
  const n = parseNumber(thresholdRaw);
  if (n === null || n < 0 || n > hi) {
    return {
      threshold: null,
      keyword: null,
      problem: `${kind === "cvss_min" ? "CVSS" : "EPSS"} threshold must be a number between 0 and ${hi}`,
    };
  }
  return { threshold: n, keyword: null, problem: null };
}

export function nameProblem(name: string): string | null {
  const n = name.trim();
  if (n.length < 1 || n.length > 200 || hasControl(n))
    return "Name must be 1 to 200 characters with no control characters";
  return null;
}
