import { fireEvent, screen } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes, useLocation, useNavigationType } from "react-router-dom";
import type { ReactElement } from "react";
import { member, renderAt, server } from "./shell";

/** Shows where the router currently is (path + search) and any notice state. */
export function Where() {
  const l = useLocation();
  const navType = useNavigationType();
  return (
    <div>
      <p data-testid="at">{l.pathname + l.search}</p>
      <p data-testid="navtype">{navType}</p>
      <p data-testid="state">{JSON.stringify(l.state)}</p>
    </div>
  );
}

export function renderRoute(routePath: string, element: ReactElement, at: string) {
  return renderAt(
    <Routes>
      <Route path={routePath} element={element} />
      <Route path="*" element={<Where />} />
    </Routes>,
    at,
  );
}

export const at = () => screen.getByTestId("at").textContent;
export const fill = (label: RegExp | string, value: string) =>
  fireEvent.change(screen.getByLabelText(label, { selector: "input" }), { target: { value } });

export const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
export const OTPAUTH = `otpauth://totp/CVEnom:member%40example.com?secret=${SECRET}&issuer=CVEnom&algorithm=SHA1&digits=6&period=30`;
export const CODES = Array.from({ length: 10 }, (_, i) => `rc${i}a-bbbb-cccc-dddd`);
const TOKEN = { access_token: "tok", token_type: "bearer", expires_in: 900 };

/** Step one answers with an MFA challenge; verify / enroll then issue the session. */
export function loginOk(opts: { enroll?: boolean } = {}) {
  server.use(
    http.post("http://localhost/api/auth/login", () =>
      HttpResponse.json({ ticket: "tk-1", enroll_required: opts.enroll ?? false, expires_in: 300 }),
    ),
    http.post("http://localhost/api/auth/mfa/verify", () => HttpResponse.json(TOKEN)),
    http.post("http://localhost/api/auth/mfa/enroll/start", () =>
      HttpResponse.json({ secret: SECRET, otpauth_uri: OTPAUTH }),
    ),
    http.post("http://localhost/api/auth/mfa/enroll/finish", () =>
      HttpResponse.json({ ...TOKEN, recovery_codes: CODES }),
    ),
    http.get("http://localhost/api/auth/me", () => HttpResponse.json(member)),
  );
}

/** Enter a second-factor code and submit it. */
export async function passCode(code = "123456") {
  const input = await screen.findByLabelText(/authentication code/i, { selector: "input" });
  fireEvent.change(input, { target: { value: code } });
  fireEvent.click(screen.getByRole("button", { name: "Verify" }));
}
