import { RANSOMWARE_LIVE_SOURCE, RANSOMWARE_LIVE_URL } from "../lib/credits";
import { ExternalLink } from "../lib/text";

export const isRansomwareSource = (source: unknown): boolean => source === RANSOMWARE_LIVE_SOURCE;

/** Small attribution shown wherever a story from ransomware.live is rendered. */
export function RansomwareCredit({ className }: { className?: string }) {
  return (
    <span className={`credit${className ? ` ${className}` : ""}`} data-testid="ransomware-credit">
      Ransomware data: <ExternalLink href={RANSOMWARE_LIVE_URL}>ransomware.live</ExternalLink>
    </span>
  );
}
