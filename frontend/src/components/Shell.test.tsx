import { QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import { guest, handlers, setupMsw } from "../test/shell";
import { Shell } from "./Shell";

vi.mock("../lib/live", () => ({ useLiveUpdates: () => ({ status: "live", lastUpdated: null }) }));

setupMsw();
afterEach(cleanup);

function at(state: unknown) {
  handlers();
  guest();
  return render(
    <QueryClientProvider client={createQueryClient()}>
      <MemoryRouter initialEntries={[{ pathname: "/", state }]}>
        <Routes>
          <Route element={<Shell />}>
            <Route index element={<p>home</p>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Shell notices", () => {
  test("reset-other names the account, rendered as text", () => {
    at({ notice: "reset-other", email: "<b>x</b>@example.com" });
    expect(screen.getByRole("status")).toHaveTextContent("Password reset for <b>x</b>@example.com");
    expect(document.querySelector(".notice b")).toBeNull();
  });
  test("no notice without state", () => {
    at(undefined);
    expect(document.querySelector(".notice")).toBeNull();
  });
});
