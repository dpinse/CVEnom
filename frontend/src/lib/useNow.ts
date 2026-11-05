import { useEffect, useState } from "react";

/** A Date that refreshes on an interval so "within 24h" windows roll over in a long-lived tab. */
export function useNow(everyMs = 60_000): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), everyMs);
    return () => clearInterval(id);
  }, [everyMs]);
  return now;
}
