/**
 * Validate a post-login `next` target. Only same-app relative paths pass: it must start with
 * a single "/", never "//" or "/\" (protocol-relative), and may contain no backslash or
 * control characters (browsers strip tab and newline, which could collapse a slash-tab-slash prefix).
 * A scheme can never survive because the value must begin with "/". Anything else is "/".
 */
export function safeNext(raw: string | null | undefined): string {
  if (typeof raw !== "string" || raw === "") return "/";
  if (raw[0] !== "/" || raw[1] === "/" || raw[1] === "\\") return "/";
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(raw)) return "/";
  return raw;
}

/** `/login?next=<encoded path>`; the bare `/login` when there is nothing worth returning to. */
export function loginPath(next: string): string {
  const n = safeNext(next);
  return n === "/" ? "/login" : `/login?next=${encodeURIComponent(n)}`;
}
