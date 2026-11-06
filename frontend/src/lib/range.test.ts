import { describe, expect, test } from "vitest";
import { DEFAULT_RANGE, RANGES, RANGE_LABEL, parseRange } from "./range";

describe("parseRange", () => {
  test.each([
    ["7d", "7d"],
    ["24h", "24h"],
    ["90d", null],
    ["", null],
    [null, null],
    ["7D", null],
  ])("%j -> %j", (input, out) => {
    expect(parseRange(input)).toBe(out);
  });
  test("default is 7d and every range is labelled", () => {
    expect(DEFAULT_RANGE).toBe("7d");
    for (const r of RANGES) expect(RANGE_LABEL[r]).toBeTruthy();
  });
});
