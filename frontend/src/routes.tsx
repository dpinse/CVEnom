import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { PublicOrUser, RequireAdmin, RequireUser } from "./components/guards";
import { Shell } from "./components/Shell";
import AcceptInvite from "./pages/AcceptInvite";
import AdminAlerts from "./pages/AdminAlerts";
import AdminInvites from "./pages/AdminInvites";
import AdminUsers from "./pages/AdminUsers";
import ChangePassword from "./pages/ChangePassword";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Login from "./pages/Login";
import NotFound from "./pages/NotFound";
import Sessions from "./pages/Sessions";
import TwoFactor from "./pages/TwoFactor";

/** The old /search URL keeps working: same query string, new path. */
function SearchRedirect() {
  const loc = useLocation();
  return <Navigate to={{ pathname: "/history", search: loc.search }} replace />;
}

/** Declarative route table; the caller supplies the router (BrowserRouter in the app, MemoryRouter in tests). */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route element={<PublicOrUser />}>
          <Route index element={<Dashboard />} />
          <Route path="history" element={<History />} />
          <Route path="search" element={<SearchRedirect />} />
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
