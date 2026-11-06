import { act, renderHook } from "@testing-library/react";
import { createElement, type ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { expect, test } from "vitest";
import { isIso3166Alpha2 } from "./iso3166";
import { parseSelection, useSelection } from "./selection";

const sp = (q: string) => new URLSearchParams(q);

test("?country= parses only for assigned upper-case ISO alpha-2 codes", () => {
  expect(parseSelection(sp("country=DE"))).toEqual({ kind: "country", cc: "DE" });
  expect(parseSelection(sp("country=XK"))).toEqual({ kind: "country", cc: "XK" });
  for (const bad of ["de", "QQ", "DEU", "", "D", "D1"]) expect(parseSelection(sp(`country=${bad}`)), bad).toBeNull();
});

test("iso3166 set", () => {
  expect(isIso3166Alpha2("US")).toBe(true);
  expect(isIso3166Alpha2("XK")).toBe(true);
  expect(isIso3166Alpha2("AA")).toBe(false);
  expect(isIso3166Alpha2("us")).toBe(false);
});

// I1: the backend exact-matches the stored Story.url, so the drawer must keep the original string, never URL.href.
const NON_CANONICAL = [
  "https://Example.com",
  "https://news.example/Sicherheitslücke-1.html",
  "https://example.com:443/a",
  "https://example.com/a{b}",
];

test("a safe but non-canonical ?story= parses to the original string, not its normalised href", () => {
  for (const raw of NON_CANONICAL) {
    expect(parseSelection(new URLSearchParams({ story: raw })), raw).toEqual({ kind: "story", url: raw });
  }
  for (const bad of ["javascript:alert(1)", "http://abcdef.onion/x", "data:text/html,x"])
    expect(parseSelection(new URLSearchParams({ story: bad })), bad).toEqual({ kind: "story", url: null });
});

test("select() writes a safe non-canonical story url unchanged; an unsafe one is never written", () => {
  const wrapper = ({ children }: { children: ReactNode }) => createElement(MemoryRouter, null, children);
  const { result } = renderHook(() => useSelection(), { wrapper });
  for (const raw of NON_CANONICAL) {
    act(() => result.current.select({ kind: "story", url: raw }));
    expect(result.current.selection, raw).toEqual({ kind: "story", url: raw });
  }
  act(() => result.current.select({ kind: "story", url: "javascript:alert(1)" }));
  expect(result.current.selection).toBeNull();
});

test("select() clears cve, story and country before setting one", () => {
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(
      MemoryRouter,
      { initialEntries: ["/?cve=CVE-2026-1001&country=DE&story=https%3A%2F%2Fx.test%2Fa&keep=1"] },
      children,
    );
  const { result } = renderHook(() => useSelection(), { wrapper });
  expect(result.current.selection).toEqual({ kind: "cve", id: "CVE-2026-1001" });
  act(() => result.current.select({ kind: "country", cc: "FR" }));
  expect(result.current.selection).toEqual({ kind: "country", cc: "FR" });
  act(() => result.current.select({ kind: "cve", id: "CVE-2026-2002" }));
  expect(result.current.selection).toEqual({ kind: "cve", id: "CVE-2026-2002" });
  act(() => result.current.select({ kind: "country", cc: "ZZ" }));
  expect(result.current.selection).toBeNull();
  act(() => result.current.clear());
  expect(result.current.selection).toBeNull();
});
