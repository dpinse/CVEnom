import { AuthError, authStore, getApiClient, type ApiClient } from "./api";
import type { TokenStore } from "./tokenStore";
import type { Me, TokenResponse } from "./types";

export interface AuthDeps {
  client: ApiClient;
  store: TokenStore;
}

/** Session state lives in memory only (see tokenStore); nothing here touches web storage. */
export function createAuth({ client, store }: AuthDeps) {
  return {
    /** For the WebSocket auth message (never put a token in a URL). */
    getToken: () => store.getToken(),
    getSnapshot: store.getSnapshot,
    subscribe: store.subscribe,

    async login(email: string, password: string): Promise<Me> {
      const t = await client.api<TokenResponse>("/auth/login", { method: "POST", body: { email, password } });
      client.adopt(t.access_token, t.expires_in);
      let me: Me;
      try {
        me = await client.api<Me>("/auth/me");
      } catch (e) {
        // A session exists server-side: end it (best effort) before dropping local state.
        try {
          await client.api("/auth/logout", { method: "POST" });
        } catch {
          // ignore
        }
        client.clear();
        throw e;
      }
      store.setUser(me);
      client.announce({ type: "login", sub: String(me.id), access_token: t.access_token, expires_in: t.expires_in });
      return me;
    },

    /** Best-effort server logout; local state is always cleared and other tabs are told. */
    async logout(): Promise<void> {
      const id = store.getUser()?.id;
      try {
        await client.api("/auth/logout", { method: "POST" });
      } catch {
        // the session may already be gone, or the network down: still log out locally
      }
      client.clear();
      client.announce({ type: "logout", sub: id === undefined ? null : String(id) });
    },

    /** App start: one silent refresh. Any failure leaves the user a guest; never throws. */
    async bootstrap(): Promise<void> {
      try {
        await client.refresh();
        store.setUser(await client.api<Me>("/auth/me"));
      } catch (e) {
        if (!(e instanceof AuthError)) client.clear();
      } finally {
        store.setReady(true);
      }
    },
  };
}

export type Auth = ReturnType<typeof createAuth>;

let shared: Auth | null = null;
/** The app-wide auth store. */
export function getAuth(): Auth {
  return (shared ??= createAuth({ client: getApiClient(), store: authStore }));
}
