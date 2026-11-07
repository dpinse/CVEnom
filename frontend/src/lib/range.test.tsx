import { act, cleanup, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, useLocation, useNavigationType } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { useRange } from "./range";

beforeEach(() => localStorage.clear());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function setup(path: string) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <MemoryRouter initialEntries={[path]}>{children}</MemoryRouter>
  );
  return renderHook(() => ({ r: useRange(), loc: useLocation(), nav: useNavigationType() }), { wrapper });
}

describe("useRange", () => {
  test("URL wins over storage", () => {
    localStorage.setItem("cvenom.range", "30d");
    expect(setup("/?range=14d").result.current.r.range).toBe("14d");
  });
  test("storage is used when the URL has none", () => {
    localStorage.setItem("cvenom.range", "30d");
    expect(setup("/").result.current.r.range).toBe("30d");
  });
  test("an invalid URL range falls through to storage", () => {
    localStorage.setItem("cvenom.range", "30d");
    expect(setup("/?range=90d").result.current.r.range).toBe("30d");
  });
  test("defaults to 7d", () => {
    expect(setup("/").result.current.r.range).toBe("7d");
  });
  test("throwing storage gives 7d, and setRange still updates the URL", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    const { result } = setup("/");
    expect(result.current.r.range).toBe("7d");
    act(() => result.current.r.setRange("24h"));
    expect(result.current.loc.search).toBe("?range=24h");
    expect(result.current.r.range).toBe("24h");
  });
  test("setRange replaces the entry, keeps other params and writes storage", () => {
    const { result } = setup("/?cve=CVE-2026-0001");
    act(() => result.current.r.setRange("14d"));
    expect(result.current.nav).toBe("REPLACE");
    expect(result.current.loc.search).toBe("?cve=CVE-2026-0001&range=14d");
    expect(localStorage.getItem("cvenom.range")).toBe("14d");
  });
});
