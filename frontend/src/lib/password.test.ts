import { describe, expect, test } from "vitest";
import { passwordProblems } from "./password";

describe("passwordProblems", () => {
  test("accepts a 12-char matching password", () => {
    expect(passwordProblems("abcdefghijkl", "abcdefghijkl")).toEqual([]);
  });
  test("rejects under 12 chars", () => {
    expect(passwordProblems("short", "short").join(" ")).toMatch(/at least 12/);
  });
  test("rejects over 256 chars", () => {
    const p = "a".repeat(257);
    expect(passwordProblems(p, p).join(" ")).toMatch(/256/);
    expect(passwordProblems("a".repeat(256), "a".repeat(256))).toEqual([]);
  });
  test("rejects all-whitespace", () => {
    const p = " ".repeat(14);
    expect(passwordProblems(p, p).join(" ")).toMatch(/whitespace/);
  });
  test("rejects mismatched confirmation", () => {
    expect(passwordProblems("abcdefghijkl", "abcdefghijkm")).toEqual(["Passwords do not match"]);
  });
  test("reports several problems at once", () => {
    expect(passwordProblems("a", "b").length).toBe(2);
  });
});
