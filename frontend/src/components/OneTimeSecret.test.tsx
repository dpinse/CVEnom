import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";
import { OneTimeSecret } from "./OneTimeSecret";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const SECRET = "tok-SECRET-0123456789abcdef";
const panel = (onDone = () => undefined) =>
  render(
    <OneTimeSecret title="Secret" label="The value" value={SECRET} expiresAt="2026-11-08T00:00:00Z" onDone={onDone} />,
  );

describe("OneTimeSecret", () => {
  test("shows a read-only monospace field, the warning, and the expiry", () => {
    panel();
    const field = screen.getByLabelText("The value") as HTMLInputElement;
    expect(field).toHaveValue(SECRET);
    expect(field).toHaveAttribute("readonly");
    expect(field.className).toContain("secret-field");
    expect(screen.getByText("This won't be shown again")).toBeInTheDocument();
    expect(screen.getByText(/Expires/)).toBeInTheDocument();
  });

  test("never copies on its own; Copy click uses the clipboard", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
    panel();
    expect(writeText).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(SECRET));
    expect(await screen.findByText("Copied to clipboard")).toBeInTheDocument();
  });

  test("falls back to selecting the text when the clipboard is unavailable or rejects", async () => {
    vi.stubGlobal("navigator", { ...navigator, clipboard: undefined });
    panel();
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(await screen.findByText(/press Ctrl\+C/i)).toBeInTheDocument();
    expect(screen.getByLabelText("The value")).toHaveFocus();
    cleanup();
    vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText: () => Promise.reject(new Error("denied")) } });
    panel();
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(await screen.findByText(/press Ctrl\+C/i)).toBeInTheDocument();
  });

  test("Done calls back", () => {
    const done = vi.fn();
    panel(done);
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(done).toHaveBeenCalledOnce();
  });
});
