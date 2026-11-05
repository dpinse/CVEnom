import { useCallback, useState } from "react";

export type Theme = "light" | "dark";
export const THEME_KEY = "cvenom-theme";

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

function system(): Theme {
  try {
    return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}

export const initialTheme = (): Theme => stored() ?? system();

export function applyTheme(t: Theme): void {
  document.documentElement.setAttribute("data-theme", t);
}

/** Apply the stored choice before first paint (called from main.tsx). */
export function initTheme(): void {
  const t = stored();
  if (t) applyTheme(t);
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(() => {
    const t = initialTheme();
    applyTheme(t);
    return t;
  });
  const toggle = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // storage blocked: the choice still applies for this page view
    }
    setTheme(next);
  }, [theme]);
  return { theme, toggle };
}
