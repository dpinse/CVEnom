import { ApiError, RateLimited } from "./api";
import { commonError } from "../components/formParts";

/** One user-facing sentence per admin API failure. Never echoes server text. */
export function adminError(e: unknown): string {
  if (e instanceof RateLimited) return `Too many requests — try again in ${e.retryAfter} seconds`;
  if (e instanceof ApiError) {
    switch (e.code) {
      case "unsafe_webhook_url":
        return "That webhook address isn't allowed (must be a public https endpoint)";
      case "too_many_recipients":
        return "A rule can have at most 20 recipients";
      case "cannot_modify_self":
        return "You can't change your own role or status here";
      case "last_admin":
        return "At least one active admin is required";
      case "user_inactive":
        return "Reactivate the user before resetting their password";
    }
    if (e.status === 504) return "Test timed out — some recipients may still receive it";
    if (e.status === 422) return "The server rejected those values. Check them and try again.";
    if (e.status === 403) return "You don't have permission to do that.";
    if (e.status === 404) return "That item no longer exists. The list has been refreshed.";
  }
  return commonError(e);
}
