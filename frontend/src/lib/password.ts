export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;
/** Input maxLength: matches the backend body limit so pasted passwords are never silently truncated. */
export const MAX_PASSWORD_INPUT = 1024;
/** Mirrors the server policy; shown for a 422 weak_password. */
export const POLICY_MESSAGE = `Password must be ${MIN_PASSWORD} to ${MAX_PASSWORD} characters and not only whitespace`;

/** Client-side policy check (the server stays authoritative). Empty array means OK. */
export function passwordProblems(pw: string, confirm: string): string[] {
  const out: string[] = [];
  if (pw.length < MIN_PASSWORD) out.push(`Password must be at least ${MIN_PASSWORD} characters`);
  else if (pw.length > MAX_PASSWORD) out.push(`Password must be at most ${MAX_PASSWORD} characters`);
  else if (pw.trim() === "") out.push("Password cannot be only whitespace");
  if (pw !== confirm) out.push("Passwords do not match");
  return out;
}
