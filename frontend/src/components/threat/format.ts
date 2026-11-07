/** "YYYY-MM-DD" (UTC) of an ISO timestamp or date string; "" when unparseable. */
export function dayOf(iso: string | null | undefined): string {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 10) : "";
}

/** "YYYY-MM-DD HH:MM" (UTC, no zone suffix). */
export function minuteOf(iso: string | null | undefined): string {
  const t = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(t) ? new Date(t).toISOString().slice(0, 16).replace("T", " ") : "";
}
