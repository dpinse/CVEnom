// The response headers nginx.conf declares, parsed from the file itself so the CSP e2e server
// (csp-server.mjs, which imports this through Node's type stripping), the e2e spec and the
// packaging unit test cannot drift from the deployed config. Handles exactly the two shapes the
// config uses at server level:
//   add_header NAME "literal" always;
//   add_header NAME $var always;   where `map $uri $var { ... }` (exact keys, ~regex keys, default)
// Any other variable header (Cache-Control is keyed on "$status:$uri") is left to the caller.

type UriMap = { exact: Map<string, string>; regex: [RegExp, string][]; fallback: string };
export type Header = [name: string, value: string];

/** Every `map $uri $name { ... }` block, by variable name. */
export function parseUriMaps(conf: string): Map<string, UriMap> {
  const maps = new Map<string, UriMap>();
  for (const block of conf.matchAll(/^map\s+\$uri\s+\$(\w+)\s*\{([^}]*)\}/gm)) {
    const map: UriMap = { exact: new Map(), regex: [], fallback: "" };
    let hasDefault = false;
    for (const [, key, value] of block[2].matchAll(/^\s*(\S+)\s+"([^"]*)";/gm)) {
      if (key === "default") {
        map.fallback = value;
        hasDefault = true;
      } else if (key.startsWith("~*")) map.regex.push([new RegExp(key.slice(2), "i"), value]);
      else if (key.startsWith("~")) map.regex.push([new RegExp(key.slice(1)), value]);
      else map.exact.set(key, value);
    }
    if (!hasDefault) throw new Error(`map $${block[1]} has no default`);
    maps.set(block[1], map);
  }
  return maps;
}

/** nginx's map lookup order: exact keys, then regexes in order of appearance, then default. */
export function lookup(map: UriMap, uri: string): string {
  const exact = map.exact.get(uri);
  if (exact !== undefined) return exact;
  for (const [re, value] of map.regex) if (re.test(uri)) return value;
  return map.fallback;
}

/** Returns `headersFor(uri)`: the server-level headers nginx sends for a request whose $uri is `uri`. */
export function parseNginxHeaders(conf: string): (uri: string) => Header[] {
  const maps = parseUriMaps(conf);
  const literal: Header[] = [];
  const mapped: [string, UriMap][] = [];
  for (const [, name, value, variable] of conf.matchAll(
    /^\s*add_header\s+([A-Za-z-]+)\s+(?:"([^"]*)"|\$(\w+))\s+always;/gm,
  )) {
    if (value !== undefined) literal.push([name, value]);
    else if (maps.has(variable)) mapped.push([name, maps.get(variable)!]);
  }
  return (uri) => [...literal, ...mapped.map(([name, map]): Header => [name, lookup(map, uri)])];
}

/** The CSP nginx sends for `uri`; throws unless exactly one CSP add_header is declared. */
export function cspFor(conf: string, uri: string): string {
  const csp = parseNginxHeaders(conf)(uri).filter(([name]) => name === "Content-Security-Policy");
  if (csp.length !== 1) throw new Error(`expected exactly one Content-Security-Policy add_header, found ${csp.length}`);
  return csp[0][1];
}
