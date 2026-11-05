// Tiny static server for the CSP e2e: serves the production dist/ with EXACTLY the response
// headers declared in nginx.conf (parsed from its server-level `add_header` lines, so the test
// cannot drift from the deployed config), plus nginx's SPA fallback and a handshake-only
// WebSocket endpoint at /api/ws/live (so a same-origin ws:// connection is really attempted
// and the browser's connect-src decision is exercised). The /api HTTP calls are mocked by the
// spec with page.route.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";

const here = import.meta.dirname;
const DIST = resolve(here, "../dist");
const CONF = resolve(here, "../nginx.conf");
const PORT = Number(process.env.CSP_PORT ?? 4174);

/** Every server-level `add_header NAME "value" always;` whose value is a literal (not a $variable). */
export function parseHeaders(conf) {
  const out = [];
  for (const m of conf.matchAll(/^\s*add_header\s+([A-Za-z-]+)\s+"([^"]*)"\s+always;/gm)) out.push([m[1], m[2]]);
  return out;
}
const HEADERS = parseHeaders(readFileSync(CONF, "utf8"));
if (!HEADERS.some(([k]) => k === "Content-Security-Policy")) throw new Error("no CSP found in nginx.conf");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
};

function send(res, status, type, body, extra = {}) {
  for (const [k, v] of HEADERS) res.setHeader(k, v);
  res.writeHead(status, { "Content-Type": type, ...extra });
  res.end(body);
}

const server = createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/healthz") return send(res, 200, "text/plain", "ok\n", { "Cache-Control": "no-store" });
  let file = normalize(join(DIST, path));
  if (!file.startsWith(DIST)) return send(res, 403, "text/plain", "forbidden");
  const isAsset = path.startsWith("/assets/");
  if (!existsSync(file) || statSync(file).isDirectory()) {
    if (isAsset) return send(res, 404, "text/plain", "not found", { "Cache-Control": "no-store" });
    file = join(DIST, "index.html"); // try_files $uri /index.html
  }
  const cache = isAsset ? "public, max-age=31536000, immutable" : "no-store";
  send(res, 200, MIME[extname(file)] ?? "application/octet-stream", readFileSync(file), { "Cache-Control": cache });
});

server.on("upgrade", (req, socket) => {
  if (new URL(req.url, "http://x").pathname !== "/api/ws/live") return socket.destroy();
  const accept = createHash("sha1")
    .update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest("base64");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  socket.on("error", () => {});
});

// Playwright starts this after the first webServer has built dist/; wait for it.
const wait = setInterval(() => {
  if (existsSync(join(DIST, "index.html"))) {
    clearInterval(wait);
    server.listen(PORT, "127.0.0.1", () => console.log(`csp server on ${PORT}`));
  }
}, 250);
