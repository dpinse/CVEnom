import { Navigate, Outlet, useLocation } from "react-router-dom";
import { loginPath } from "../lib/redirect";
import { useHealth } from "../lib/queries";
import { useAuth } from "../lib/useAuth";

export function Loading() {
  return (
    <p className="shell-loading gutter" role="status">
      Loading…
    </p>
  );
}

function useHere() {
  const l = useLocation();
  return l.pathname + l.search;
}

/** Signed-in users only. Waits for bootstrap so a refresh never flashes a redirect. */
export function RequireUser() {
  const { user, ready } = useAuth();
  const here = useHere();
  if (!ready) return <Loading />;
  if (!user) return <Navigate to={loginPath(here)} replace />;
  return <Outlet />;
}

/** Admins only. A member goes home with a notice (shown by the shell), not an error page. */
export function RequireAdmin() {
  const { user, ready } = useAuth();
  const here = useHere();
  if (!ready) return <Loading />;
  if (!user) return <Navigate to={loginPath(here)} replace />;
  if (user.role !== "admin") return <Navigate to="/" replace state={{ notice: "admins-only" }} />;
  return <Outlet />;
}

/** Dashboard and search: open to guests only when the server is public. */
export function PublicOrUser() {
  const { user, ready } = useAuth();
  const health = useHealth();
  const here = useHere();
  if (!ready) return <Loading />;
  if (user) return <Outlet />;
  if (health.isPending) return <Loading />;
  // An unreachable /health is treated as private: never expose the app on a guess.
  if (health.data?.public_read === true) return <Outlet />;
  return <Navigate to={loginPath(here)} replace />;
}
