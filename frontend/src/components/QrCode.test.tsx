import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test } from "vitest";
import { QrCode, qrPath } from "./QrCode";

afterEach(cleanup);

const URI = "otpauth://totp/CVEnom:a%40b.co?secret=JBSWY3DPEHPK3PXP&issuer=CVEnom&algorithm=SHA1&digits=6&period=30";

describe("QrCode", () => {
  test("renders an accessible inline SVG with no network, style attributes or scripts", () => {
    render(<QrCode value={URI} label="QR code for your authenticator app" />);
    const svg = screen.getByRole("img", { name: "QR code for your authenticator app" });
    expect(svg.tagName.toLowerCase()).toBe("svg");
    const html = svg.outerHTML;
    expect(html).not.toMatch(/style=|<image|<script|href=|https?:\/\/(?!www\.w3\.org)/);
    // the secret-bearing URI is never rendered as text or an attribute
    expect(html).not.toContain("JBSWY3DPEHPK3PXP");
    expect(svg.querySelectorAll("path")).toHaveLength(1);
  });

  test("the module path is deterministic and has a quiet zone", () => {
    const a = qrPath(URI);
    expect(a).toEqual(qrPath(URI));
    expect(a.size).toBeGreaterThanOrEqual(21 + 8);
    expect(a.d).toMatch(/^M4 4h1v1h-1z/); // the top-left finder starts inside the 4-module quiet zone
    expect(qrPath(URI + "x").d).not.toBe(a.d);
  });
});
