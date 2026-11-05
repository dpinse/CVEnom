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
    "/%2F%2Fevil.com",
    "/%5Cevil.com",
    "/..//evil",
    "/ /evil",
    "/" + "a".repeat(5000),
  ])("rejects %j", (raw) => {
    expect(safeNext(raw)).toBe("/");
  });
  test("caps input at 2048 chars", () => {
    expect(safeNext("/" + "a".repeat(2047))).toHaveLength(2048);
    expect(safeNext("/" + "a".repeat(2048))).toBe("/");
  });
  test("rejects null and undefined", () => {
    expect(safeNext(null)).toBe("/");
    expect(safeNext(undefined)).toBe("/");
  });
  test.each(["/", "/search?q=a", "/admin/users", "/account/password#x", "/search?q=a%2Fb&x=//y"])("keeps %s", (p) => {
    expect(safeNext(p)).toBe(p);
  });
  test("loginPath encodes next", () => {
    expect(loginPath("/search?q=a b")).toBe("/login?next=%2Fsearch%3Fq%3Da%20b");
    expect(loginPath("//evil")).toBe("/login");
    expect(loginPath("/")).toBe("/login");
  });
});
