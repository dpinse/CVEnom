import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PublicOrUser, RequireAdmin, RequireUser } from "./components/guards";
import { Shell } from "./components/Shell";
import AcceptInvite from "./pages/AcceptInvite";
import AdminAlerts from "./pages/AdminAlerts";
import AdminInvites from "./pages/AdminInvites";
import AdminUsers from "./pages/AdminUsers";
import ChangePassword from "./pages/ChangePassword";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import ThreatPlaceholder from "./pages/ThreatPlaceholder";
import Sessions from "./pages/Sessions";
import Threats from "./pages/Threats";
import TwoFactor from "./pages/TwoFactor";

const sevForMinCvss = (n: number) => (n >= 9 ? "crit" : n >= 7 ? "high,crit" : null);

/** Maps legacy /history and /search params onto Threats: q kept, kev -> status, min_cvss -> sev, tab; rest dropped. */
export function legacyThreatsSearch(search: string): string {
  const sp = new URLSearchParams(search);
  const out = new URLSearchParams();
  const q = sp.get("q");
  if (q !== null) out.set("q", q);
  if (sp.get("kev") === "true") out.set("status", "exploited");
  const raw = sp.get("min_cvss");
  const sev = raw !== null && raw.trim() !== "" && Number.isFinite(Number(raw)) ? sevForMinCvss(Number(raw)) : null;
  if (sev) out.set("sev", sev);
  if (sp.get("tab") === "stories") out.set("tab", "news");
  const s = out.toString();
  return s ? `?${s}` : "";
}

function LegacyThreatsRedirect() {
  const loc = useLocation();
  return <Navigate to={{ pathname: "/threats", search: legacyThreatsSearch(loc.search) }} replace />;
}

/** Declarative route table; the caller supplies the router (BrowserRouter in the app, MemoryRouter in tests). */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route element={<PublicOrUser />}>
          <Route index element={<Dashboard />} />
          <Route path="threats" element={<Threats />} />
          <Route path="threats/:cveId" element={<ThreatPlaceholder />} />
          <Route path="history" element={<LegacyThreatsRedirect />} />
          <Route path="search" element={<LegacyThreatsRedirect />} />
        </Route>
        <Route path="login" element={<Login />} />
        {/* The secret is in the fragment (#<token>), never the path: see AcceptInvite. */}
        <Route path="invite" element={<AcceptInvite mode="invite" />} />
        <Route path="reset" element={<AcceptInvite mode="reset" />} />
        <Route element={<RequireUser />}>
          <Route path="account/sessions" element={<Sessions />} />
          <Route path="account/password" element={<ChangePassword />} />
          <Route path="account/two-factor" element={<TwoFactor />} />
        </Route>
        <Route element={<RequireAdmin />}>
          <Route path="admin/alerts" element={<AdminAlerts />} />
          <Route path="admin/invites" element={<AdminInvites />} />
          <Route path="admin/users" element={<AdminUsers />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
