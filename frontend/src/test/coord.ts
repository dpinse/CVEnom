import type { ChannelLike, LocksLike } from "../lib/api";

/** In-memory BroadcastChannel hub: a message reaches every channel except the sender. */
export function makeHub() {
  const chans: (ChannelLike & { closed: boolean })[] = [];
  return {
    channel(): ChannelLike {
      const c: ChannelLike & { closed: boolean } = {
        onmessage: null,
        closed: false,
        postMessage(m: unknown) {
          const data = JSON.parse(JSON.stringify(m));
          for (const o of chans) {
            if (o === c || o.closed) continue;
            void Promise.resolve().then(() => o.onmessage?.({ data }));
          }
        },
        close() {
          c.closed = true;
        },
      };
      chans.push(c);
      return c;
    },
  };
}

/** FIFO mutex standing in for navigator.locks shared by several "tabs". */
export function makeLocks(): LocksLike & { calls: string[] } {
  let tail: Promise<unknown> = Promise.resolve();
  const calls: string[] = [];
  return {
    calls,
    request<T>(name: string, cb: () => Promise<T>): Promise<T> {
      calls.push(name);
      const run = tail.then(cb, cb);
      tail = run.catch(() => undefined);
      return run;
    },
  };
}
