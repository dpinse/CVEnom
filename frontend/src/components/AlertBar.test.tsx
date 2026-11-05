import { cleanup, fireEvent, screen } from "@testing-library/react";
import { useLocation } from "react-router-dom";
import { afterEach, describe, expect, test } from "vitest";
import { handlers, item, lanes, renderAt, setupMsw } from "../test/shell";
import { AlertBar } from "./AlertBar";

setupMsw({ ready: true });
afterEach(cleanup);

const today = () => new Date().toISOString().slice(0, 10);
const yesterday = () => new Date(Date.now() - 86_400_000).toISOString().slice(0, 10);

function Where() {
  const l = useLocation();
  return <output data-testid="loc">{l.pathname + l.search}</output>;
}
const view = () =>
  renderAt(
    <>
      <AlertBar />
      <Where />
    </>,
    "/search",
  );

describe("AlertBar", () => {
  test("shows the newest in-window KEV with a decoded snippet", async () => {
    handlers({
      lanes: lanes([item({ cve_id: "CVE-2026-1111", kev_added: yesterday(), summary: "Old one" })], {
        FRESH: [item({ cve_id: "CVE-2026-2222", kev_added: today(), summary: "Fish &amp; chips overflow" })],
      }),
    });
    view();
    expect(await screen.findByText("CVE-2026-2222 added to KEV")).toBeInTheDocument();
    expect(screen.getByText("Fish & chips overflow")).toBeInTheDocument();
    expect(screen.queryByText(/CVE-2026-1111/)).toBeNull();
  });

  test("hidden when nothing is within 24h", async () => {
    handlers({ lanes: lanes([item({ kev_added: "2020-01-01" })]) });
    view();
    await screen.findByTestId("loc");
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText(/added to KEV/)).toBeNull();
  });

  test("an entity-encoded script tag renders literally, never as markup", async () => {
    handlers({ lanes: lanes([item({ kev_added: today(), summary: "&lt;script&gt;alert(1)&lt;/script&gt;" })]) });
    const { container } = view();
    expect(await screen.findByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(container.querySelector("script")).toBeNull();
  });

  test("clicking selects the CVE through the ?cve= search param", async () => {
    handlers({ lanes: lanes([item({ cve_id: "CVE-2026-3333", kev_added: today() })]) });
    view();
    fireEvent.click(await screen.findByRole("button", { name: /CVE-2026-3333 added to KEV/ }));
    expect(screen.getByTestId("loc")).toHaveTextContent("/search?cve=CVE-2026-3333");
  });

  test("dismiss hides it and persists the id in sessionStorage", async () => {
    handlers({ lanes: lanes([item({ cve_id: "CVE-2026-4444", kev_added: today() })]) });
    const first = view();
    fireEvent.click(await screen.findByRole("button", { name: "Dismiss alert" }));
    expect(screen.queryByText(/CVE-2026-4444 added to KEV/)).toBeNull();
    expect(sessionStorage.getItem("cvenom-alert-dismissed")).toBe("CVE-2026-4444");
    first.unmount();
    view();
    await screen.findByTestId("loc");
    await new Promise((r) => setTimeout(r, 50));
    expect(screen.queryByText(/CVE-2026-4444 added to KEV/)).toBeNull();
  });

  test("a different, newer CVE shows again after a dismissal", async () => {
    sessionStorage.setItem("cvenom-alert-dismissed", "CVE-OLD");
    handlers({ lanes: lanes([item({ cve_id: "CVE-2026-5555", kev_added: today() })]) });
    view();
    expect(await screen.findByText("CVE-2026-5555 added to KEV")).toBeInTheDocument();
  });
});
