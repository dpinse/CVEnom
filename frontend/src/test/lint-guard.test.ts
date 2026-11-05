import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

const eslint = new ESLint({ cwd: process.cwd() });

async function lint(code: string) {
  const [res] = await eslint.lintText(code, { filePath: "src/guard-fixture.tsx" });
  return res.messages.filter((m) => m.severity === 2);
}

describe("ESLint XSS guards", () => {
  it("flags dangerouslySetInnerHTML", async () => {
    const msgs = await lint('export const A = () => <div dangerouslySetInnerHTML={{ __html: "x" }} />;\n');
    expect(msgs.map((m) => m.ruleId)).toContain("react/no-danger");
  });
  it("flags innerHTML assignment", async () => {
    const msgs = await lint('export function f(el: HTMLElement) { el.innerHTML = "x"; }\n');
    expect(msgs.map((m) => m.ruleId)).toContain("no-restricted-syntax");
  });
  it("flags outerHTML assignment", async () => {
    const msgs = await lint('export function f(el: HTMLElement) { el.outerHTML = "x"; }\n');
    expect(msgs.map((m) => m.ruleId)).toContain("no-restricted-syntax");
  });
  it("flags insertAdjacentHTML", async () => {
    const msgs = await lint('export function f(el: HTMLElement) { el.insertAdjacentHTML("beforeend", "x"); }\n');
    expect(msgs.map((m) => m.ruleId)).toContain("no-restricted-syntax");
  });
  it("accepts clean code", async () => {
    const msgs = await lint('export const A = () => <div>hi</div>;\n');
    expect(msgs).toEqual([]);
  });
});
