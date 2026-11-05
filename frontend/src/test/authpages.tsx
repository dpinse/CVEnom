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

export function loginOk() {
  server.use(
    http.post("http://localhost/api/auth/login", () =>
      HttpResponse.json({ access_token: "tok", token_type: "bearer", expires_in: 900 }),
    ),
    http.get("http://localhost/api/auth/me", () => HttpResponse.json(member)),
  );
}
