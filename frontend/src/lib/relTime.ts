const RTF = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** Relative time ("5 minutes ago") of an ISO timestamp against `now`. Empty string if unparseable. */
export function relTime(iso: string | null | undefined, now: Date | number = Date.now()): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  const sec = Math.round((t - (typeof now === "number" ? now : now.getTime())) / 1000);
  const abs = Math.abs(sec);
  if (abs < 60) return "just now";
  if (abs < 3600) return RTF.format(Math.trunc(sec / 60), "minute");
  if (abs < 86400) return RTF.format(Math.trunc(sec / 3600), "hour");
  if (abs < 30 * 86400) return RTF.format(Math.trunc(sec / 86400), "day");
  if (abs < 365 * 86400) return RTF.format(Math.trunc(sec / (30 * 86400)), "month");
  return RTF.format(Math.trunc(sec / (365 * 86400)), "year");
}
