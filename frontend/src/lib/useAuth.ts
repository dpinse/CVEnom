import { useSyncExternalStore } from "react";
import { authStore } from "./api";
import { getAuth } from "./auth";
import type { Me } from "./types";

/** `ready` is false until the one startup bootstrap has settled (guests included). */
export function useAuth(): { user: Me | null; ready: boolean } {
  const s = useSyncExternalStore(authStore.subscribe, authStore.getSnapshot);
  return { user: s.user, ready: s.ready };
}

let started = false;
/** Run the startup refresh exactly once per page load (StrictMode double-mounts are harmless). */
export function startBootstrap(): void {
  if (started || authStore.getSnapshot().ready) return;
  started = true;
  void getAuth().bootstrap();
}
export function __resetBootstrapForTests(): void {
  started = false;
}
