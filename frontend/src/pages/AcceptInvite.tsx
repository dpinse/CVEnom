/** Owned by Task 9. `/invite/:token` creates an account; `/reset/:token` sets a new password. */
export default function AcceptInvite({ mode }: { mode: "invite" | "reset" }) {
  return (
    <section className="page gutter">
      <h1>{mode === "reset" ? "Reset password" : "Accept invite"}</h1>
      <p>Owned by Task 9.</p>
    </section>
  );
}
