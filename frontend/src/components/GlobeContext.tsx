import { createContext, useContext, useMemo, useRef, type ReactNode } from "react";

/** The globe handle shared with the rest of the app (the drawer flies to a CVE's country). */
export interface GlobeApi {
  /** Ease the camera to a country (ISO-2) and pause auto-rotate. No-op until the globe has loaded. */
  flyTo(iso2: string): void;
}

type FlyTo = (iso2: string) => void;

interface Registry {
  api: GlobeApi;
  /** Install the live implementation; returns an unregister that only clears its own entry. */
  register(fn: FlyTo): () => void;
}

const noop: Registry = { api: { flyTo: () => {} }, register: () => () => {} };

const GlobeCtx = createContext<Registry>(noop);

/**
 * Holds the globe handle. The (lazy) <Globe> registers its flyTo once MapLibre has loaded;
 * until then, and with no globe mounted at all, flyTo does nothing.
 */
export function GlobeProvider({ children }: { children: ReactNode }) {
  const impl = useRef<FlyTo | null>(null);
  const value = useMemo<Registry>(
    () => ({
      api: { flyTo: (iso2) => impl.current?.(iso2) },
      register: (fn) => {
        impl.current = fn;
        return () => {
          if (impl.current === fn) impl.current = null;
        };
      },
    }),
    [],
  );
  return <GlobeCtx.Provider value={value}>{children}</GlobeCtx.Provider>;
}

/** The globe handle; safe to call anywhere (a no-op outside a provider or before load). */
export function useGlobe(): GlobeApi {
  return useContext(GlobeCtx).api;
}

/** For <Globe> only: the function that installs its flyTo implementation. */
export function useGlobeRegistration(): Registry["register"] {
  return useContext(GlobeCtx).register;
}
