import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";

// No per-file afterEach(cleanup) here on purpose: setup.ts must provide it globally (M6).
describe("global RTL cleanup", () => {
  test("renders something", () => {
    render(<p>left over?</p>);
    expect(screen.getByText("left over?")).toBeInTheDocument();
  });
  test("the previous test's tree was unmounted", () => {
    expect(screen.queryByText("left over?")).toBeNull();
    expect(document.body.innerHTML).toBe("");
  });
});
