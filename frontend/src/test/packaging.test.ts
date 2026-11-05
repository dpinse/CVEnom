import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { cspFor } from "../../e2e/nginxHeaders.ts";

const root = resolve(__dirname, "../..");
const read = (f: string) => readFileSync(join(root, f), "utf8");

/** The nginx.conf is the single source of the response headers; the CSP e2e parses the same lines. */
describe("nginx.conf", () => {
  const conf = existsSync(join(root, "nginx.conf")) ? read("nginx.conf") : "";
  const API_CSP = "default-src 'none'; frame-ancestors 'none'";
  const csp = conf ? cspFor(conf, "/") : "";
  const directives = new Map(
    csp
      .split(";")
      .map((d) => d.trim())
      .filter(Boolean)
      .map((d) => [d.split(" ")[0], d] as const),
  );

  it("exists and hides the version", () => {
    expect(conf).toContain("server_tokens off;");
    expect(conf).toMatch(/listen 8080;/);
  });
  it("CSP is strict: no inline/eval/blob/wildcard, no remote origin", () => {
    expect(csp).not.toBe("");
    for (const bad of ["unsafe-inline", "unsafe-eval", "blob:", "*", "http:", "https:", "ws:", "wss:"]) {
      expect(csp, bad).not.toContain(bad);
    }
    expect(directives.get("default-src")).toBe("default-src 'none'");
    expect(directives.get("script-src")).toBe("script-src 'self'");
    expect(directives.get("style-src")).toBe("style-src 'self'");
    expect(directives.get("connect-src")).toBe("connect-src 'self'");
    expect(directives.get("worker-src")).toBe("worker-src 'self'");
    expect(directives.get("frame-ancestors")).toBe("frame-ancestors 'none'");
    expect(directives.get("base-uri")).toBe("base-uri 'none'");
    expect(directives.has("upgrade-insecure-requests")).toBe(true);
    expect(csp).not.toContain("unsafe-");
  });
  it("CSP is ONE server-level add_header whose value is a map on the normalised $uri", () => {
    expect(conf.match(/add_header\s+Content-Security-Policy\s/g)).toHaveLength(1);
    expect(conf).toContain("add_header Content-Security-Policy $csp always;");
    // $uri, not $request_uri: the same normalised path nginx matches locations against.
    expect(conf).toMatch(/^map \$uri \$csp \{$/m);
    expect(conf).not.toMatch(/map \$request_uri/);
  });
  it("/api/ responses get exactly the api's strict policy; nothing else does", () => {
    for (const uri of ["/api/", "/api/health", "/api/auth/refresh", "/api/ws/live"])
      expect(cspFor(conf, uri), uri).toBe(API_CSP);
    for (const uri of [
      "/",
      "/index.html",
      "/assets/index-abc.js",
      "/healthz",
      "/login",
      "/apix",
      "/api",
      "/x/api/",
      "/API/x",
    ]) {
      expect(cspFor(conf, uri), uri).toBe(csp);
    }
    expect(csp).not.toBe(API_CSP);
  });
  it("sends the other security headers with `always`", () => {
    for (const h of [
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "Permissions-Policy",
      "Cross-Origin-Opener-Policy",
      "Cross-Origin-Resource-Policy",
      "X-Frame-Options",
    ]) {
      expect(conf, h).toMatch(new RegExp(`add_header ${h} .* always;`));
    }
    expect(conf).toContain('add_header Referrer-Policy "no-referrer" always;');
    expect(conf).toContain('add_header X-Content-Type-Options "nosniff" always;');
  });
  it("SPA fallback, cache policy and health endpoint", () => {
    expect(conf).toContain("try_files $uri /index.html;");
    expect(conf).toContain("public, max-age=31536000, immutable");
    expect(conf).toMatch(/map "\$status:\$uri" \$cache_control \{[\s\S]*\/api\/\s+"";/);
    expect(conf).toContain('"no-store"');
    expect(conf).toMatch(/location = \/healthz[\s\S]*?access_log off;[\s\S]*?return 200/);
  });
  it("proxies /api and the websocket with the trust headers and limits", () => {
    expect(conf).toMatch(/location \/api\/ \{/);
    expect(conf).toMatch(/location = \/api\/ws\/live \{/);
    expect(conf).toContain("set $api_upstream api:8000;");
    expect(conf).toContain("proxy_pass http://$api_upstream;");
    expect(conf).toContain("proxy_set_header X-Forwarded-For $xff_to_api;");
    expect(conf).toContain("$realip_remote_addr");
    expect(conf).toContain("proxy_set_header Host $http_host;");
    expect(conf).toContain('proxy_set_header CF-Connecting-IP "";');
    expect(conf).toContain("proxy_set_header Upgrade $http_upgrade;");
    expect(conf).toContain("proxy_read_timeout 75s;");
    expect(conf).toContain("proxy_buffering off;");
    expect(conf).toContain("client_max_body_size 64k;");
    expect(conf).toContain("set_real_ip_from 172.28.0.1;");
    expect(conf).toContain("real_ip_recursive on;");
    expect(conf).toMatch(/limit_req zone=\w+ burst=40/);
    // limit_req covers /api/ and the websocket only, never static files
    const serverLevel = conf.slice(0, conf.indexOf("\n  location "));
    expect(serverLevel).not.toContain("limit_req zone=");
    expect(conf.match(/limit_req zone=/g)).toHaveLength(2);
    // the api's own copies of these five headers are hidden in both proxied locations
    for (const h of [
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "X-Frame-Options",
    ]) {
      expect(conf.match(new RegExp(`proxy_hide_header ${h};`, "g")), h).toHaveLength(2);
    }
    expect(conf).not.toMatch(/proxy_hide_header (Permissions-Policy|Cache-Control|Cross-Origin)/);
    // X-Forwarded-Proto passes through only from the trusted gateway and only as exactly http/https
    expect(conf).toContain('"172.28.0.1:http"');
    expect(conf).toContain('"172.28.0.1:https"');
    expect(conf).toMatch(/default\s+\$scheme;/);
    expect(conf.match(/proxy_set_header X-Forwarded-Proto \$xfp_to_api;/g)).toHaveLength(2);
    expect(conf).not.toContain("interest-cohort");
  });
  it("add_header appears only at server level (nginx does not inherit it into a location that has its own)", () => {
    const afterFirstLocation = conf.slice(conf.indexOf("\n  location "));
    expect(afterFirstLocation).not.toContain("add_header");
    expect(conf).toContain("add_header Cache-Control $cache_control always;");
  });
});

describe("frontend/Dockerfile", () => {
  const df = existsSync(join(root, "Dockerfile")) ? read("Dockerfile") : "";
  it("is a pinned multi-stage build that runs unprivileged", () => {
    const froms = [...df.matchAll(/^FROM\s+(\S+)/gim)].map((m) => m[1]);
    expect(froms).toHaveLength(2);
    expect(froms[0]).toMatch(/^node:26\.\d+\.\d+-slim$/);
    expect(froms[1]).toMatch(/^nginxinc\/nginx-unprivileged:\d+\.\d+\.\d+-alpine-slim$/);
    expect(df).toMatch(/npm ci/);
    expect(df).toMatch(/npm run build/);
    expect(df).toMatch(/^USER 101$/m);
    expect(df).toMatch(/HEALTHCHECK[\s\S]*\/healthz/);
  });
  it("copies only dist and nginx.conf into the runtime stage, with no source maps", () => {
    const runtime = df.split(/^FROM /m)[2] ?? "";
    const copies = [...runtime.matchAll(/^COPY\s+(.+)$/gm)].map((m) => m[1]);
    expect(copies.length).toBeGreaterThan(0);
    expect(copies.join("\n")).not.toMatch(/\.map|src|node_modules/);
    expect(df).not.toMatch(/--sourcemap/);
    expect(read("vite.config.ts")).toContain("sourcemap: false");
  });
  it(".dockerignore keeps build junk and secrets out of the context", () => {
    const di = existsSync(join(root, ".dockerignore")) ? read(".dockerignore") : "";
    for (const p of ["node_modules", "dist", "test-results", "playwright-report", ".env"]) expect(di).toContain(p);
  });
});

describe("index.html is CSP-clean", () => {
  const html = read("index.html");
  it("has no inline script, inline style or style attribute", () => {
    expect(html).not.toMatch(/<style/i);
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).not.toMatch(/<script(?![^>]*\ssrc=)[^>]*>/i);
    expect(html).not.toMatch(/\son\w+=/i);
  });
});
