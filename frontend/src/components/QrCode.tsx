import { useMemo } from "react";
import { encode } from "uqr";

const QUIET_ZONE = 4; // modules of white border, per ISO/IEC 18004

/**
 * One SVG path covering every dark module, inside a 4-module quiet zone. uqr only computes the
 * module matrix in memory: nothing is fetched, no markup string is injected (no innerHTML), and no
 * style attribute is emitted, so the strict CSP (style-src 'self') is unaffected.
 */
export function qrPath(value: string): { size: number; d: string } {
  const qr = encode(value, { ecc: "M", border: QUIET_ZONE });
  let d = "";
  qr.data.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (dark) d += `M${x} ${y}h1v1h-1z`;
    }),
  );
  return { size: qr.size, d };
}

/**
 * A QR code rendered locally. `value` (here an otpauth:// URI carrying the TOTP secret) never
 * leaves memory as text: it is only turned into module geometry.
 */
export function QrCode({ value, label }: { value: string; label: string }) {
  const { size, d } = useMemo(() => qrPath(value), [value]);
  return (
    <svg
      className="qr-code"
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      width={size * 6}
      height={size * 6}
      shapeRendering="crispEdges"
    >
      {/* Fixed black on white whatever the theme: scanners need the contrast. */}
      <rect width={size} height={size} fill="#ffffff" />
      <path d={d} fill="#000000" />
    </svg>
  );
}
