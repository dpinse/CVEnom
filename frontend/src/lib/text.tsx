import type { ReactNode } from "react";

const MAX_CODE_POINT = 0x10ffff;

/**
 * Decode HTML entities exactly once, with no DOM involved.
 *
 * Handles `&amp; &lt; &gt; &quot;` plus numeric `&#NNN;` and `&#xHH;` (which covers
 * `&#39;` and `&#x27;`). One regex pass with one replace callback means decoded output
 * is never re-scanned, so `&amp;lt;` becomes `&lt;`, not `<`. Invalid code points
 * (0, surrogates, above 0x10FFFF) and unknown entities are left as literal text.
 * Non-string input yields "".
 */
export function decodeEntities(s: string): string {
  if (typeof s !== "string") return "";
  return s.replace(/&(?:(amp|lt|gt|quot)|#(\d+)|#[xX]([0-9a-fA-F]+));/g, (match, named, dec, hex) => {
    if (named) return { amp: "&", lt: "<", gt: ">", quot: '"' }[named as "amp" | "lt" | "gt" | "quot"];
    const cp = dec !== undefined ? Number.parseInt(dec, 10) : Number.parseInt(hex, 16);
    if (!Number.isFinite(cp) || cp === 0 || cp > MAX_CODE_POINT || (cp >= 0xd800 && cp <= 0xdfff)) return match;
    return String.fromCodePoint(cp);
  });
}

type TextProps = { value: string; className?: string; as?: "span" | "div" | "p" | "strong" | "em" | "code" };

/** Renders the entity-decoded string as a React text node (React escapes on output). */
export function Text({ value, className, as: As }: TextProps) {
  const decoded = decodeEntities(value);
  if (As || className) {
    const Tag = As ?? "span";
    return <Tag className={className}>{decoded}</Tag>;
  }
  return <>{decoded}</>;
}

function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true;
  }
  return false;
}

/**
 * Returns the normalized URL only for http(s), otherwise null.
 *
 * Surrounding whitespace is trimmed (a stray leading space from stored data is harmless
 * once trimmed); any control character or whitespace left inside is rejected. Parsed
 * without a base so relative and protocol-relative inputs fail to parse.
 */
export function safeHref(u: string): string | null {
  if (typeof u !== "string") return null;
  const t = u.trim();
  if (t === "" || /\s/.test(t) || hasControlChar(t)) return null;
  let url: URL;
  try {
    url = new URL(t);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  return isOnionHost(url.hostname) ? null : url.href;
}

/**
 * True for `onion` or any `*.onion` host. `URL.hostname` is already WHATWG-normalised
 * (percent-decoded, NFKC, IDNA dots U+3002/FF0E/FF61 mapped to ".", lower-cased), which mirrors
 * the backend's validate_http_url; trailing dots are stripped here.
 */
function isOnionHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.+$/, "");
  return h === "onion" || h.endsWith(".onion");
}

/** An external link: an anchor only when the URL passes safeHref, else plain text. */
export function ExternalLink({
  href,
  children,
  className,
}: {
  href: string;
  children: ReactNode;
  className?: string;
}) {
  const safe = safeHref(href);
  if (safe === null) return <span className={className}>{children}</span>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer" className={className}>
      {children}
    </a>
  );
}
