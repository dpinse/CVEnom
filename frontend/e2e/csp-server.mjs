// Tiny static server for the CSP e2e: serves the production dist/ with EXACTLY the response
// headers declared in nginx.conf (parsed from its server-level `add_header` lines and the
// `map $uri` blocks they use, by nginxHeaders.ts, so the test cannot drift from the deployed
// config), plus nginx's SPA fallback and a handshake-only WebSocket endpoint at /api/ws/live (so a
// same-origin ws:// connection is really attempted and the browser's connect-src decision is
// exercised). The page's /api HTTP calls are mocked by the specs with page.route; a direct /api/
// request reaching this server gets a 502, like nginx with no upstream, with the /api/ headers.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { parseNginxHeaders } from "./nginxHeaders.ts";

const here = import.meta.dirname;
const DIST = resolve(here, "../dist");
const CONF = resolve(here, "../nginx.conf");
const PORT = Number(process.env.CSP_PORT ?? 4174);

const headersFor = parseNginxHeaders(readFileSync(CONF, "utf8"));
if (headersFor("/").filter(([k]) => k === "Content-Security-Policy").length !== 1) {
  throw new Error("expected exactly one Content-Security-Policy in nginx.conf");
}

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

/** `uri` is nginx's $uri for the response: the normalised, decoded path after any try_files rewrite. */
function send(res, uri, status, type, body, extra = {}) {
  for (const [k, v] of headersFor(uri)) res.setHeader(k, v);
  res.writeHead(status, { "Content-Type": type, ...extra });
  res.end(body);
}

const server = createServer((req, res) => {
  // URL parsing resolves dot segments; decoding then mirrors nginx's percent-decoded $uri.
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path === "/healthz") return send(res, path, 200, "text/plain", "ok\n", { "Cache-Control": "no-store" });
  // location /api/ with no upstream: nginx's own 502 page. The cache map sends no Cache-Control for /api/.
  if (path.startsWith("/api/")) return send(res, path, 502, "text/html", "<html><body>502 Bad Gateway</body></html>\n");
  let file = normalize(join(DIST, path));
  if (!file.startsWith(DIST)) return send(res, path, 403, "text/plain", "forbidden");
  const isAsset = path.startsWith("/assets/");
  let uri = path;
  if (!existsSync(file) || statSync(file).isDirectory()) {
    if (isAsset) return send(res, path, 404, "text/plain", "not found", { "Cache-Control": "no-store" });
    file = join(DIST, "index.html"); // try_files $uri /index.html
    uri = "/index.html";
  }
  const cache = isAsset ? "public, max-age=31536000, immutable" : "no-store";
  send(res, uri, 200, MIME[extname(file)] ?? "application/octet-stream", readFileSync(file), {
    "Cache-Control": cache,
  });
});

server.on("upgrade", (req, socket) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (path !== "/api/ws/live") return socket.destroy();
  const accept = createHash("sha1")
    .update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest("base64");
  const headers = headersFor(path)
    .map(([k, v]) => `${k}: ${v}\r\n`)
    .join("");
  socket.write(
    `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${headers}\r\n`,
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
