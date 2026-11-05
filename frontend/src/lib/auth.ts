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
      try {
        const me = await client.api<Me>("/auth/me");
        store.setUser(me);
        return me;
      } catch (e) {
        client.clear();
        throw e;
      }
    },

    /** Best-effort server logout; local state is always cleared. */
    async logout(): Promise<void> {
      try {
        await client.api("/auth/logout", { method: "POST" });
      } catch {
        // the session may already be gone, or the network down: still log out locally
      }
      client.clear();
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
