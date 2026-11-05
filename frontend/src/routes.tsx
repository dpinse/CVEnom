import { Route, Routes } from "react-router-dom";
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
import Search from "./pages/Search";
import Sessions from "./pages/Sessions";

/** Declarative route table; the caller supplies the router (BrowserRouter in the app, MemoryRouter in tests). */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route element={<PublicOrUser />}>
          <Route index element={<Dashboard />} />
          <Route path="search" element={<Search />} />
        </Route>
        <Route path="login" element={<Login />} />
        {/* The secret is in the fragment (#<token>), never the path: see AcceptInvite. */}
        <Route path="invite" element={<AcceptInvite mode="invite" />} />
        <Route path="reset" element={<AcceptInvite mode="reset" />} />
        <Route element={<RequireUser />}>
          <Route path="account/sessions" element={<Sessions />} />
          <Route path="account/password" element={<ChangePassword />} />
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
