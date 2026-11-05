import { describe, expect, test } from "vitest";
import { loginPath, safeNext } from "./redirect";

describe("safeNext (open-redirect guard)", () => {
  test.each([
    "//evil.com",
    "/\\evil.com",
    "https://evil.com",
    "http://evil.com/x",
    "javascript:alert(1)",
    "data:text/html,x",
    "evil.com",
    "",
    "/\t/evil.com",
    "/\n/evil.com",
    "/a\\b",
  ])("rejects %j", (raw) => {
    expect(safeNext(raw)).toBe("/");
  });
  test("rejects null and undefined", () => {
    expect(safeNext(null)).toBe("/");
    expect(safeNext(undefined)).toBe("/");
  });
  test.each(["/", "/search?q=a", "/admin/users", "/account/password#x"])("keeps %s", (p) => {
    expect(safeNext(p)).toBe(p);
  });
  test("loginPath encodes next", () => {
    expect(loginPath("/search?q=a b")).toBe("/login?next=%2Fsearch%3Fq%3Da%20b");
    expect(loginPath("//evil")).toBe("/login");
    expect(loginPath("/")).toBe("/login");
  });
});
