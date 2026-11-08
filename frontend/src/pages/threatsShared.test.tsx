import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, test } from "vitest";
import { useUpdateParams } from "./threatsShared";

const wrapper = ({ children }: { children: ReactNode }) => (
  <MemoryRouter initialEntries={["/threats?cve=CVE-2026-0001&page=3"]}>{children}</MemoryRouter>
);

describe("useUpdateParams", () => {
  test("two writes before a re-render both land (react-router's prev is the last render's params)", () => {
    const { result } = renderHook(() => ({ write: useUpdateParams(), loc: useLocation() }), { wrapper });
    act(() => {
      result.current.write({ added: "month" });
      result.current.write({ status: "exploited" });
    });
    const sp = new URLSearchParams(result.current.loc.search);
    expect(sp.get("added")).toBe("month");
    expect(sp.get("status")).toBe("exploited");
    expect(sp.get("cve")).toBe("CVE-2026-0001");
    expect(sp.has("page")).toBe(false);
  });

  test("a write after a re-render starts from the URL, keeping earlier writes", () => {
    const { result } = renderHook(() => ({ write: useUpdateParams(), loc: useLocation() }), { wrapper });
    act(() => result.current.write({ sev: "high,crit" }));
    act(() => result.current.write({ sort: "priority", sev: undefined }));
    const sp = new URLSearchParams(result.current.loc.search);
    expect(sp.get("sort")).toBe("priority");
    expect(sp.has("sev")).toBe(false);
    expect(sp.get("cve")).toBe("CVE-2026-0001");
  });
});
