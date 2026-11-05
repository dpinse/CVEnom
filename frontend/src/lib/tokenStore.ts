import type { Me } from "./types";

export interface AuthSnapshot {
  user: Me | null;
  authenticated: boolean;
  /** true once bootstrap() has finished (success or guest) */
  ready: boolean;
}

/**
 * In-memory session state. The access token lives only in this closure: never in
 * localStorage, sessionStorage, cookies or URLs.
 */
export function createTokenStore() {
  let token: string | null = null;
  let user: Me | null = null;
  let ready = false;
  let snapshot: AuthSnapshot = { user, authenticated: false, ready };
  const listeners = new Set<() => void>();

  const publish = () => {
    snapshot = { user, authenticated: token !== null, ready };
    for (const fn of [...listeners]) fn();
  };

  return {
    getToken: () => token,
    getUser: () => user,
    getSnapshot: () => snapshot,
    setToken(t: string | null) {
      if (t === token) return;
      token = t;
      publish();
    },
    setUser(u: Me | null) {
      user = u;
      publish();
    },
    setReady(r: boolean) {
      if (r === ready) return;
      ready = r;
      publish();
    },
    clear() {
      token = null;
      user = null;
      publish();
    },
    subscribe(fn: () => void) {
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
      };
    },
  };
}

export type TokenStore = ReturnType<typeof createTokenStore>;
