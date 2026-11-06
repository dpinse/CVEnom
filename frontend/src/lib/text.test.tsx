import { render } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { ExternalLink, Text, decodeEntities, safeHref } from "./text";

test("decodes once, never twice", () => {
  expect(decodeEntities("5 &lt; 6 &amp;&amp; x")).toBe("5 < 6 && x");
  expect(decodeEntities("&amp;lt;script&amp;gt;")).toBe("&lt;script&gt;");
});
test("entity-encoded tags render literally, not as elements", () => {
  const { container } = render(<Text value="&lt;img src=x onerror=alert(1)&gt;" />);
  expect(container.querySelector("img")).toBeNull();
  expect(container.textContent).toBe("<img src=x onerror=alert(1)>");
});
test("safeHref allows only http(s)", () => {
  expect(safeHref("https://x.org/a")).toBe("https://x.org/a");
  for (const bad of ["javascript:alert(1)", "data:text/html,x", "JaVaScRiPt:x", "//evil", "", "ftp://x"])
    expect(safeHref(bad)).toBeNull();
});

test("safeHref rejects .onion hosts", () => {
  for (const bad of [
    "http://abcdef.onion/",
    "https://ABC.ONION/x",
    "http://abc.onion.:80/",
    "http://a.b.onion",
    "http://onion/",
    "http://x%2Eonion/",
    "http://x。onion/",
    "http://x．onion/",
    "http://x｡onion/",
    "http://abc.onion../",
  ])
    expect(safeHref(bad), bad).toBeNull();
  expect(safeHref("https://onion.example.com/")).toBe("https://onion.example.com/");
  expect(safeHref("https://example.com/x.onion")).toBe("https://example.com/x.onion");
  expect(safeHref("https://notonion.com/")).toBe("https://notonion.com/");
  expect(safeHref("https://x.onions.com/")).toBe("https://x.onions.com/");
  expect(safeHref("https://example.com/?u=a.onion")).toBe("https://example.com/?u=a.onion");
});

describe("decodeEntities edge cases", () => {
  test("all supported named and numeric forms", () => {
    expect(decodeEntities("&amp; &lt; &gt; &quot; &#39; &#x27; &#65; &#x41; &#X41;")).toBe(`& < > " ' ' A A A`);
  });
  test("unknown entities and bare ampersands are left as-is", () => {
    expect(decodeEntities("&nbsp; &apos; & &amp &#;")).toBe("&nbsp; &apos; & &amp &#;");
  });
  test("invalid numeric code points stay literal", () => {
    for (const bad of [
      "&#0;",
      "&#x0;",
      "&#1114112;",
      "&#x110000;",
      "&#xD800;",
      "&#55357;",
      "&#xDFFF;",
      "&#99999999999999999999;",
    ])
      expect(decodeEntities(bad)).toBe(bad);
  });
  test("valid astral code point decodes", () => {
    expect(decodeEntities("&#x1F600;")).toBe("\u{1F600}");
  });
  test("no double decode through numeric entities", () => {
    expect(decodeEntities("&#38;lt;")).toBe("&lt;");
    expect(decodeEntities("&#x26;amp;")).toBe("&amp;");
  });
  test("non-string input returns empty string", () => {
    for (const v of [null, undefined, 5, {}, ["a"]]) expect(decodeEntities(v as unknown as string)).toBe("");
  });
});

describe("<Text>", () => {
  test("renders decoded string as a text node", () => {
    const { container } = render(<Text value="a &amp; b" />);
    expect(container.textContent).toBe("a & b");
    expect(container.children).toHaveLength(0);
  });
  test("optional element and className", () => {
    const { container } = render(<Text value="x &lt;b&gt;" as="span" className="c" />);
    const el = container.querySelector("span.c");
    expect(el?.textContent).toBe("x <b>");
    expect(container.querySelector("b")).toBeNull();
  });
  test("non-string value renders nothing", () => {
    const { container } = render(<Text value={null as unknown as string} />);
    expect(container.textContent).toBe("");
  });
});

describe("safeHref edge cases", () => {
  test("rejects control characters, inner whitespace, relative and protocol-relative", () => {
    for (const bad of [
      "https://x\n.org",
      "https://x .org",
      "https://x\t.org",
      "\u0000https://x",
      "https://x\u0000",
      "//evil",
      "/relative",
      "x.org/a",
      "mailto:a@b.c",
      "vbscript:x",
      "https://\u2028x",
    ])
      expect(safeHref(bad)).toBeNull();
  });
  test("surrounding whitespace is trimmed (documented), result is normalized", () => {
    expect(safeHref(" https://x")).toBe("https://x/");
    expect(safeHref("https://x.org/a?b=1 ")).toBe("https://x.org/a?b=1");
    expect(safeHref("HTTP://X.ORG")).toBe("http://x.org/");
  });
  test("non-string input is null", () => {
    expect(safeHref(undefined as unknown as string)).toBeNull();
  });
});

describe("<ExternalLink>", () => {
  test("safe URL renders anchor with exact rel and target", () => {
    const { container } = render(<ExternalLink href="https://x.org/a">story</ExternalLink>);
    const a = container.querySelector("a");
    expect(a).not.toBeNull();
    expect(a?.getAttribute("href")).toBe("https://x.org/a");
    expect(a?.getAttribute("target")).toBe("_blank");
    expect(a?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(a?.textContent).toBe("story");
  });
  test("javascript: URL renders no anchor, only plain text in a span", () => {
    const { container } = render(<ExternalLink href="javascript:alert(1)">story</ExternalLink>);
    expect(container.querySelector("a")).toBeNull();
    expect(container.querySelector("span")?.textContent).toBe("story");
  });
});
