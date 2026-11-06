import { describe, expect, it } from "vitest";
import { cweName } from "./cwe";

describe("cweName", () => {
  it("resolves a bundled CWE id to its MITRE name", async () => {
    const name = await cweName("CWE-79");
    expect(name).toEqual(expect.any(String));
    expect(name?.startsWith("Improper Neutralization")).toBe(true);
  });

  it("returns null for non-CWE ids and unknown numbers", async () => {
    expect(await cweName("NVD-CWE-Other")).toBeNull();
    expect(await cweName("NVD-CWE-noinfo")).toBeNull();
    expect(await cweName("CWE-99999999")).toBeNull();
    expect(await cweName("CWE-")).toBeNull();
    expect(await cweName("cwe-79")).toBeNull();
    expect(await cweName("79")).toBeNull();
  });
});
