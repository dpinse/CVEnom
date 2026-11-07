import { describe, expect, test } from "vitest";
import { decodeCvss } from "./cvssVector";

const V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";

describe("decodeCvss", () => {
  test("decodes a 3.1 vector into eight labelled metrics", () => {
    const d = decodeCvss(V31)!;
    expect(d.version).toBe("3.1");
    expect(d.metrics).toHaveLength(8);
    expect(d.metrics.find((m) => m.key === "AV")).toEqual({ key: "AV", label: "Attack vector", value: "Network" });
    expect(d.metrics.find((m) => m.key === "S")?.value).toBe("Unchanged");
  });
  test("decodes 3.0 and records the version", () => {
    expect(decodeCvss("CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:H")?.version).toBe("3.0");
  });
  test("decodes a full 4.0 vector into eleven metrics", () => {
    const d = decodeCvss(V40)!;
    expect(d.version).toBe("4.0");
    expect(d.metrics).toHaveLength(11);
    expect(d.metrics.find((m) => m.key === "AT")?.value).toBe("None");
    expect(d.metrics.find((m) => m.key === "SC")?.label).toBe("Subsequent confidentiality");
  });
  test("ignores threat and supplemental metrics", () => {
    expect(decodeCvss(`${V40}/E:A/S:P/U:Red`)?.metrics).toHaveLength(11);
  });
  test.each([
    ["unknown value", "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["garbage", "garbage"],
    ["missing S", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"],
    ["unknown prefix", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["3.x key in a 4.0 vector", "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
    ["duplicate key", `${V31}/AV:L`],
    ["empty", ""],
  ])("%s gives null", (_name, v) => {
    expect(decodeCvss(v)).toBeNull();
  });
});
