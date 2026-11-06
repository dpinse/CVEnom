const MAX_NEXT = 2048;

/**
 * Validate a post-login `next` target. Only same-app relative paths pass: it must start with
 * a single "/", never "//" or "/\" (protocol-relative), and may contain no backslash or
 * control characters (browsers strip tab and newline, which could collapse a slash-tab-slash prefix).
 * The path part (before ? or #) must also have no empty segment ("//"), no ".." segment, no
 * whitespace, and no percent-encoded slash or backslash. Input over 2048 chars is refused.
 * A scheme can never survive because the value must begin with "/". Anything else is "/".
 */
export function safeNext(raw: string | null | undefined): string {
  if (typeof raw !== "string" || raw === "" || raw.length > MAX_NEXT) return "/";
  if (raw[0] !== "/" || raw[1] === "/" || raw[1] === "\\") return "/";
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(raw)) return "/";
  const path = raw.split(/[?#]/, 1)[0];
  if (/\s/.test(path) || path.includes("//") || /%2f|%5c/i.test(path)) return "/";
  // Browsers resolve %2e as ".", so "%2e%2e" is the same traversal as "..".
  if (path.split("/").some((seg) => /^(\.|%2e){2}$/i.test(seg))) return "/";
  return raw;
}

/** `/login?next=<encoded path>`; the bare `/login` when there is nothing worth returning to. */
export function loginPath(next: string): string {
  const n = safeNext(next);
  return n === "/" ? "/login" : `/login?next=${encodeURIComponent(n)}`;
}
