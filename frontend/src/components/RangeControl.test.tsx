import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, expect, test } from "vitest";
import { RangeControl } from "./RangeControl";

beforeEach(() => localStorage.clear());
afterEach(cleanup);

function Loc() {
  return <output data-testid="loc">{useLocation().search}</output>;
}

test("one button is pressed and clicking 14d sets ?range=14d", () => {
  render(
    <MemoryRouter initialEntries={["/"]}>
      <RangeControl />
      <Loc />
    </MemoryRouter>,
  );
  const group = screen.getByRole("group", { name: "Time range" });
  expect(group.querySelectorAll('[aria-pressed="true"]')).toHaveLength(1);
  expect(screen.getByRole("button", { name: "7d" })).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: "14d" }));
  expect(screen.getByTestId("loc")).toHaveTextContent("?range=14d");
  expect(screen.getByRole("button", { name: "14d" })).toHaveAttribute("aria-pressed", "true");
});
