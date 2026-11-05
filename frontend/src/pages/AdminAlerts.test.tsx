import { QueryClient } from "@tanstack/react-query";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { HttpResponse, http } from "msw";
import { Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createQueryClient } from "../lib/queries";
import { Where } from "../test/authpages";
import { admin, renderAt, server, setupMsw, signIn } from "../test/shell";
import type { AlertRule, Delivery } from "../lib/types";
import AdminAlerts from "./AdminAlerts";

setupMsw();
afterEach(cleanup);

const SECRET = "WHSEC-0123456789abcdefXYZ";
const U = "http://localhost/api/alerts";

const mkRule = (o: Partial<AlertRule> = {}): AlertRule => ({
  id: 1,
  name: "Critical CVSS",
  kind: "cvss_min",
  threshold: 9,
  keyword: null,
  enabled: true,
  created_at: "2026-11-01T00:00:00Z",
  recipients: [
    { id: 10, channel: "email", email: "ops@example.com" },
    { id: 11, channel: "webhook", url_masked: "https://hooks.example.com/…" },
  ],
  ...o,
});
const mkDelivery = (o: Partial<Delivery> = {}): Delivery => ({
  id: 1,
  rule_id: 1,
  recipient_id: 10,
  channel: "email",
  cve_id: "CVE-2026-1111",
  status: "sent",
  attempts: 1,
  last_error: null,
  created_at: "2026-11-05T00:00:00Z",
  sent_at: "2026-11-05T00:01:00Z",
  next_attempt_at: null,
  ...o,
});

let rules: AlertRule[] = [];
let deliveries: Delivery[] = [];
let deliveryTotal = 0;
const bodies: { method: string; url: string; body: unknown }[] = [];
const deliveryQueries: URLSearchParams[] = [];

function mock() {
  bodies.length = 0;
  deliveryQueries.length = 0;
  server.use(
    http.get(`${U}/rules`, () => HttpResponse.json(rules)),
    http.get(`${U}/deliveries`, ({ request }) => {
      deliveryQueries.push(new URL(request.url).searchParams);
      return HttpResponse.json({ items: deliveries, page: 1, page_size: 50, total: deliveryTotal });
    }),
  );
}
async function record(request: Request) {
  const text = await request.text();
  bodies.push({ method: request.method, url: new URL(request.url).pathname, body: text ? JSON.parse(text) : undefined });
}

function Page() {
  return (
    <>
      <AdminAlerts />
      <Where />
    </>
  );
}
function open(qc: QueryClient = createQueryClient()) {
  renderAt(
    <Routes>
      <Route path="/admin/alerts" element={<Page />} />
    </Routes>,
    "/admin/alerts",
    qc,
  );
  return qc;
}
const setField = (label: RegExp | string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const cacheDump = (qc: QueryClient) =>
  JSON.stringify([
    qc.getQueryCache().getAll().map((q) => ({ k: q.queryKey, d: q.state.data, e: String(q.state.error) })),
    qc.getMutationCache().getAll().map((m) => ({ v: m.state.variables, d: m.state.data })),
  ]);

beforeEach(() => {
  signIn(admin);
  rules = [mkRule()];
  deliveries = [];
  deliveryTotal = 0;
});

async function openCreate() {
  fireEvent.click(await screen.findByRole("button", { name: "New rule" }));
  await screen.findByRole("form", { name: "New alert rule" });
}
const submitCreate = () => fireEvent.click(screen.getByRole("button", { name: "Create rule" }));

describe("create rule: client validation", () => {
  test("an http:// webhook is blocked on the client", async () => {
    mock();
    server.use(http.post(`${U}/rules`, async ({ request }) => (await record(request), HttpResponse.json(mkRule(), { status: 201 }))));
    open();
    await openCreate();
    setField("Name", "Hook rule");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "http://hooks.example.com/x");
    submitCreate();
    expect(await screen.findByText(/must use https/i)).toBeInTheDocument();
    expect(screen.getByText(/server also checks/i)).toBeInTheDocument();
    expect(bodies).toEqual([]);
  });

  test("a webhook with userinfo or a too-short secret is blocked", async () => {
    mock();
    open();
    await openCreate();
    setField("Name", "Hook rule");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "https://user:pw@hooks.example.com/x");
    submitCreate();
    expect(await screen.findByText(/username or password/i)).toBeInTheDocument();
    setField("Recipient 1 webhook URL", "https://hooks.example.com/x");
    setField(/Recipient 1 webhook secret/, "short");
    submitCreate();
    expect((await screen.findAllByText(/16 to 256 characters/i)).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Leave blank to generate/i).length).toBeGreaterThan(0);
    expect(bodies).toEqual([]);
  });

  test.each([
    ["cvss_min", /CVSS threshold/, "10.5"],
    ["cvss_min", /CVSS threshold/, "-1"],
    ["cvss_min", /CVSS threshold/, "abc"],
    ["cvss_min", /CVSS threshold/, ""],
    ["epss_min", /EPSS threshold/, "1.5"],
    ["epss_min", /EPSS threshold/, "NaN"],
    ["epss_min", /EPSS threshold/, "Infinity"],
  ])("an out-of-range %s threshold %j is blocked", async (kind, label, value) => {
    mock();
    open();
    await openCreate();
    setField("Name", "Threshold rule");
    setField("Kind", kind);
    setField(label, value);
    setField("Recipient 1 email", "a@example.com");
    submitCreate();
    expect(await screen.findByText(/threshold must be a number between 0 and/i)).toBeInTheDocument();
    expect(bodies).toEqual([]);
  });

  test("only the field for the chosen kind is shown; keyword is validated", async () => {
    mock();
    open();
    await openCreate();
    expect(screen.queryByLabelText(/threshold/i)).toBeNull();
    expect(screen.queryByLabelText(/keyword/i)).toBeNull();
    setField("Kind", "keyword");
    expect(screen.getByLabelText(/Keyword \(1 to 100/)).toBeInTheDocument();
    setField("Name", "Keyword rule");
    setField("Recipient 1 email", "a@example.com");
    submitCreate();
    expect(await screen.findByText(/Keyword must be 1 to 100/)).toBeInTheDocument();
  });

  test("recipients are capped at 20", async () => {
    mock();
    open();
    await openCreate();
    for (let i = 0; i < 19; i++) fireEvent.click(screen.getByRole("button", { name: "Add another recipient" }));
    expect(screen.getByRole("button", { name: "Add another recipient" })).toBeDisabled();
    expect(screen.getByText("20 of 20")).toBeInTheDocument();
  });
});

describe("create rule: secret shown once", () => {
  test("panel appears once; after Done the secret is in neither DOM, query cache, mutation cache nor storage", async () => {
    mock();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    let posted: unknown;
    server.use(
      http.post(`${U}/rules`, async ({ request }) => {
        await record(request);
        posted = bodies[0].body;
        rules = [mkRule({ id: 2, name: "Hook rule", kind: "keyword", threshold: null, keyword: "openssl" })];
        return HttpResponse.json(
          mkRule({
            id: 2,
            name: "Hook rule",
            kind: "keyword",
            threshold: null,
            keyword: "openssl",
            recipients: [{ id: 20, channel: "webhook", url_masked: "https://hooks.example.com/…", secret: SECRET }],
          }),
          { status: 201 },
        );
      }),
    );
    const qc = open();
    await openCreate();
    setField("Name", "Hook rule");
    setField("Kind", "keyword");
    setField(/Keyword \(1 to 100/, "openssl");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "https://hooks.example.com/abc");
    submitCreate();

    const panel = await screen.findByRole("region", { name: /Webhook secret/ });
    expect(within(panel).getByText("This won't be shown again")).toBeInTheDocument();
    expect(within(panel).getByDisplayValue(SECRET)).toHaveAttribute("readonly");
    expect(screen.getAllByRole("region", { name: /Webhook secret/ })).toHaveLength(1);
    expect(posted).toEqual({
      name: "Hook rule",
      kind: "keyword",
      keyword: "openssl",
      enabled: true,
      recipients: [{ channel: "webhook", url: "https://hooks.example.com/abc" }],
    });
    // not in the cache even while the panel is open
    expect(cacheDump(qc)).not.toContain(SECRET);
    await screen.findByRole("switch", { name: "Enabled: Hook rule" });

    fireEvent.click(within(panel).getByRole("button", { name: "Done" }));
    expect(screen.queryByDisplayValue(SECRET)).toBeNull();
    expect(document.body.textContent).not.toContain(SECRET);
    expect(document.body.innerHTML).not.toContain(SECRET);
    expect(cacheDump(qc)).not.toContain(SECRET);
    expect(JSON.stringify([localStorage, sessionStorage, location.href])).not.toContain(SECRET);
    for (const call of setItem.mock.calls) expect(call.join("|")).not.toContain(SECRET);
    expect(screen.queryByRole("region", { name: /Webhook secret/ })).toBeNull();
    setItem.mockRestore();
  });

  test("a secret typed by the user is also kept out of the caches", async () => {
    mock();
    server.use(
      http.post(`${U}/rules`, async ({ request }) => {
        await record(request);
        return HttpResponse.json(
          mkRule({ id: 3, recipients: [{ id: 30, channel: "webhook", url_masked: "https://h.example.com/…", secret: SECRET }] }),
          { status: 201 },
        );
      }),
    );
    const qc = open();
    await openCreate();
    setField("Name", "Mine");
    setField("Kind", "kev_added");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "https://h.example.com/x");
    setField(/Recipient 1 webhook secret/, SECRET);
    submitCreate();
    await screen.findByRole("region", { name: /Webhook secret/ });
    expect(cacheDump(qc)).not.toContain(SECRET);
  });
});

describe("rule list", () => {
  test("shows name, kind badge, condition, toggle, recipient count, and renders hostile text as text", async () => {
    rules = [mkRule({ name: "<img src=x onerror=alert(1)>" }), mkRule({ id: 2, name: "KEV", kind: "kev_added", threshold: null, recipients: [] })];
    mock();
    open();
    expect((await screen.findAllByText("<img src=x onerror=alert(1)>")).length).toBeGreaterThan(0);
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("CVSS minimum")).toBeInTheDocument();
    expect(screen.getByText(/CVSS ≥ 9/)).toBeInTheDocument();
    expect(screen.getByText("2 recipients")).toBeInTheDocument();
    expect(screen.getByText("0 recipients")).toBeInTheDocument();
    expect(screen.getAllByRole("switch")).toHaveLength(2);
  });

  test("delete asks for confirmation in-page (no window.confirm) and then deletes", async () => {
    mock();
    const confirm = vi.spyOn(window, "confirm");
    server.use(
      http.delete(`${U}/rules/1`, async ({ request }) => {
        await record(request);
        rules = [];
        return new HttpResponse(null, { status: 204 });
      }),
    );
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Delete Critical CVSS" }));
    expect(bodies).toEqual([]);
    expect(screen.getByText(/Delete this rule/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(bodies).toEqual([]);
    fireEvent.click(screen.getByRole("button", { name: "Delete Critical CVSS" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm delete" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0].method).toBe("DELETE");
    await waitFor(() => expect(screen.queryByText("Critical CVSS")).toBeNull());
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  test("the enabled toggle sends only {enabled}", async () => {
    mock();
    server.use(http.patch(`${U}/rules/1`, async ({ request }) => (await record(request), HttpResponse.json(mkRule({ enabled: false })))));
    open();
    fireEvent.click(await screen.findByRole("switch", { name: "Enabled: Critical CVSS" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0].body).toEqual({ enabled: false });
  });
});

describe("edit rule", () => {
  test("PATCH sends only editable fields; kind is read-only", async () => {
    mock();
    server.use(http.patch(`${U}/rules/1`, async ({ request }) => (await record(request), HttpResponse.json(mkRule()))));
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit Critical CVSS" }));
    expect(screen.getByText(/can't be changed/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Kind")).toBeNull();
    setField("Name", "Renamed");
    setField(/CVSS threshold/, "7.5");
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0].body).toEqual({ name: "Renamed", enabled: true, threshold: 7.5 });
    expect(Object.keys(bodies[0].body as object).sort()).toEqual(["enabled", "name", "threshold"]);
  });

  test("an out-of-range threshold is blocked when editing", async () => {
    mock();
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit Critical CVSS" }));
    setField(/CVSS threshold/, "11");
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText(/between 0 and 10/)).toBeInTheDocument();
    expect(bodies).toEqual([]);
  });

  test("recipients: shows masked URL as returned; Remove sends DELETE; Add sends POST and surfaces a one-time secret", async () => {
    mock();
    server.use(
      http.delete(`${U}/rules/1/recipients/10`, async ({ request }) => (await record(request), new HttpResponse(null, { status: 204 }))),
      http.post(`${U}/rules/1/recipients`, async ({ request }) => {
        await record(request);
        return HttpResponse.json({ id: 40, channel: "webhook", url_masked: "https://new.example.com/…", secret: SECRET }, { status: 201 });
      }),
    );
    const qc = open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit Critical CVSS" }));
    const group = screen.getByRole("group", { name: /Edit rule/ });
    expect(within(group).getByText("https://hooks.example.com/…")).toBeInTheDocument();
    fireEvent.click(within(group).getByRole("button", { name: "Remove recipient ops@example.com" }));
    expect(bodies.some((b) => b.method === "DELETE")).toBe(false);
    fireEvent.click(within(group).getByRole("button", { name: "Confirm remove" }));
    await waitFor(() => expect(bodies.some((b) => b.method === "DELETE")).toBe(true));

    setField(/Recipient 3 type/, "webhook");
    setField(/Recipient 3 webhook URL/, "https://new.example.com/hook");
    fireEvent.click(screen.getByRole("button", { name: "Add recipient" }));
    await screen.findByRole("region", { name: /Webhook secret/ });
    expect(bodies.find((b) => b.method === "POST")?.body).toEqual({ channel: "webhook", url: "https://new.example.com/hook" });
    expect(cacheDump(qc)).not.toContain(SECRET);
  });

  test("unsafe_webhook_url and too_many_recipients map to their own messages; other 422 is generic", async () => {
    mock();
    let code: string | null = "unsafe_webhook_url";
    server.use(
      http.post(`${U}/rules/1/recipients`, () =>
        code ? HttpResponse.json({ error: code }, { status: 422 }) : HttpResponse.json({ detail: [] }, { status: 422 }),
      ),
    );
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Edit Critical CVSS" }));
    setField(/Recipient 3 type/, "webhook");
    setField(/Recipient 3 webhook URL/, "https://10.0.0.1/x");
    const add = () => fireEvent.click(screen.getByRole("button", { name: "Add recipient" }));
    add();
    expect(await screen.findByText("That webhook address isn't allowed (must be a public https endpoint)")).toBeInTheDocument();
    code = "too_many_recipients";
    add();
    expect(await screen.findByText("A rule can have at most 20 recipients")).toBeInTheDocument();
    code = null;
    add();
    expect(await screen.findByText(/server rejected those values/i)).toBeInTheDocument();
  });

  test("unsafe_webhook_url on create keeps the form and shows the mapped message", async () => {
    mock();
    server.use(http.post(`${U}/rules`, () => HttpResponse.json({ error: "unsafe_webhook_url" }, { status: 422 })));
    open();
    await openCreate();
    setField("Name", "X");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "https://169.254.169.254/x");
    submitCreate();
    expect(await screen.findByText("That webhook address isn't allowed (must be a public https endpoint)")).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "New alert rule" })).toBeInTheDocument();
  });
});

describe("hardening", () => {
  test("editing with only Enabled toggled leaves an entity-looking name untouched", async () => {
    rules = [mkRule({ name: "R&amp;D", kind: "keyword", threshold: null, keyword: "a&amp;b" })];
    mock();
    server.use(http.patch(`${U}/rules/1`, async ({ request }) => (await record(request), HttpResponse.json(rules[0]))));
    open();
    fireEvent.click(await screen.findByRole("button", { name: /^Edit/ }));
    expect(screen.getByLabelText("Name")).toHaveValue("R&amp;D");
    fireEvent.click(within(screen.getByRole("group", { name: /Edit rule/ })).getByLabelText("Enabled"));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0].body).toEqual({ enabled: false });
  });

  test("webhook secret input resists password managers", async () => {
    mock();
    open();
    await openCreate();
    setField("Recipient 1 type", "webhook");
    const input = screen.getByLabelText(/webhook secret/i);
    expect(input).toHaveAttribute("autocomplete", "new-password");
    expect(input.getAttribute("name")).toBe("webhook-secret-1");
  });

  test("a rule with no recipients says so and cannot be test-sent", async () => {
    rules = [mkRule({ recipients: [] })];
    mock();
    open();
    expect(await screen.findByText("This rule has no recipients")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send test" })).toBeDisabled();
  });

  test("deliveries refetch every 30 seconds", async () => {
    deliveries = [mkDelivery()];
    deliveryTotal = 1;
    mock();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      open();
      await screen.findByRole("table");
      const n = deliveryQueries.length;
      await vi.advanceTimersByTimeAsync(29_000);
      expect(deliveryQueries.length).toBe(n);
      await vi.advanceTimersByTimeAsync(2_000);
      await waitFor(() => expect(deliveryQueries.length).toBeGreaterThan(n));
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("test send", () => {
  test("shows one row per recipient with error text, disables while running", async () => {
    mock();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.post(`${U}/rules/1/test`, async () => {
        await gate;
        return HttpResponse.json([
          { recipient_id: 10, channel: "email", ok: true, error: null },
          { recipient_id: 11, channel: "webhook", ok: false, error: "<b>HTTP 500</b>" },
        ]);
      }),
    );
    open();
    expect(await screen.findByText("Sends a clearly-labelled TEST alert to every recipient of this rule")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    const running = await screen.findByRole("button", { name: /Sending test/ });
    expect(running).toBeDisabled();
    release();
    const list = await screen.findByRole("list", { name: /Test results/ });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("ops@example.com");
    expect(rows[0]).toHaveTextContent("OK");
    expect(rows[1]).toHaveTextContent("Failed");
    expect(rows[1]).toHaveTextContent("<b>HTTP 500</b>");
    expect(list.querySelector("b")).toBeNull();
    expect(screen.getByRole("button", { name: "Send test" })).toBeEnabled();
  });

  test("429 shows the retry time; 504 shows the timeout message", async () => {
    mock();
    let mode: 429 | 504 = 429;
    server.use(
      http.post(`${U}/rules/1/test`, () =>
        mode === 429
          ? HttpResponse.json({ error: "rate_limited" }, { status: 429, headers: { "Retry-After": "42" } })
          : HttpResponse.json({ error: "timeout" }, { status: 504 }),
      ),
    );
    open();
    fireEvent.click(await screen.findByRole("button", { name: "Send test" }));
    expect(await screen.findByText(/try again in 42 seconds/i)).toBeInTheDocument();
    mode = 504;
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    expect(await screen.findByText("Test timed out — some recipients may still receive it")).toBeInTheDocument();
  });
});

describe("deliveries", () => {
  test("renders rows with chips, rule name, last_error as text, and filters by status and rule", async () => {
    deliveries = [
      mkDelivery({ id: 1 }),
      mkDelivery({ id: 2, status: "failed", attempts: 3, last_error: "<i>boom</i>", cve_id: "CVE-2026-2222", rule_id: 99 }),
    ];
    deliveryTotal = 2;
    mock();
    open();
    const table = await screen.findByRole("table");
    expect(within(table).getByText("sent")).toHaveClass("chip");
    expect(within(table).getByText("failed")).toHaveClass("chip");
    expect(within(table).getByText("<i>boom</i>")).toBeInTheDocument();
    expect(table.querySelector("i")).toBeNull();
    expect(within(table).getByText("Critical CVSS")).toBeInTheDocument();
    expect(within(table).getByText("Rule #99")).toBeInTheDocument();
    await waitFor(() => expect(deliveryQueries.length).toBeGreaterThan(0));
    expect(deliveryQueries[0].get("page_size")).toBe("50");

    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "failed" } });
    await waitFor(() => expect(deliveryQueries.some((q) => q.get("status") === "failed")).toBe(true));
    fireEvent.change(screen.getByLabelText("Rule"), { target: { value: "1" } });
    await waitFor(() => expect(deliveryQueries.some((q) => q.get("status") === "failed" && q.get("rule_id") === "1")).toBe(true));
  });

  test("paginates at 50 per page", async () => {
    deliveries = [mkDelivery()];
    deliveryTotal = 120;
    mock();
    open();
    expect(await screen.findByText("Page 1 of 3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(deliveryQueries.some((q) => q.get("page") === "2")).toBe(true));
    expect(await screen.findByText("Page 2 of 3")).toBeInTheDocument();
  });

  test("clicking a CVE id sets ?cve=", async () => {
    deliveries = [mkDelivery()];
    deliveryTotal = 1;
    mock();
    open();
    fireEvent.click(await screen.findByRole("button", { name: "CVE-2026-1111" }));
    await waitFor(() => expect(screen.getByTestId("at")).toHaveTextContent("/admin/alerts?cve=CVE-2026-1111"));
  });
});

describe("leaving the page", () => {
  test("an undismissed secret is discarded when the page unmounts", async () => {
    mock();
    server.use(
      http.post(`${U}/rules`, () =>
        HttpResponse.json(mkRule({ id: 5, recipients: [{ id: 50, channel: "webhook", url_masked: "https://h.example.com/…", secret: SECRET }] }), { status: 201 }),
      ),
    );
    const qc = open();
    await openCreate();
    setField("Name", "Gone");
    setField("Kind", "kev_added");
    setField("Recipient 1 type", "webhook");
    setField("Recipient 1 webhook URL", "https://h.example.com/x");
    submitCreate();
    await screen.findByDisplayValue(SECRET);
    cleanup();
    expect(document.body.textContent).not.toContain(SECRET);
    expect(cacheDump(qc)).not.toContain(SECRET);
  });
});
