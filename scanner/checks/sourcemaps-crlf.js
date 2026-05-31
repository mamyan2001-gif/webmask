import { fetchTarget } from "../utils/http.js";

export async function checkSourceMaps(targetUrl, body) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const html = body || "";

  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)].map((m) => m[1]);
  const checked = new Set();

  for (const src of scripts.slice(0, 12)) {
    let scriptUrl;
    try {
      scriptUrl = new URL(src, origin).href;
    } catch {
      continue;
    }
    const mapUrl = `${scriptUrl}.map`;
    if (checked.has(mapUrl)) continue;
    checked.add(mapUrl);

    try {
      const { res, body: mapBody } = await fetchTarget(mapUrl, { followRedirects: false, timeout: 6000 });
      if (res.status < 200 || res.status >= 300) continue;
      if (!/"sources"|"mappings"|"file"\s*:/i.test(mapBody)) continue;

      findings.push({
        id: `sourcemap-${scriptUrl.split("/").pop()?.replace(/\W/g, "-")}`,
        severity: "medium",
        category: "source-maps",
        title: "JavaScript source map exposed",
        description: "Source maps reveal unminified source code and may expose secrets or business logic.",
        evidence: `${mapUrl} → HTTP ${res.status}`,
        remediation: "Do not deploy source maps to production, or restrict access to authenticated admins.",
      });
    } catch {
      /* skip */
    }
  }

  // sourceMappingURL in inline responses
  const inlineMaps = [...html.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/gi)];
  for (const match of inlineMaps.slice(0, 3)) {
    findings.push({
      id: "sourcemap-inline-reference",
      severity: "low",
      category: "source-maps",
      title: "sourceMappingURL reference in page",
      description: "Page references a source map — verify it is not publicly accessible.",
      evidence: match[1].slice(0, 120),
      remediation: "Remove sourceMappingURL comments from production bundles.",
    });
  }

  return findings;
}

export async function checkCrlfInjection(targetUrl) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const payload = encodeURIComponent("webmask\r\nSet-Cookie:crlfprobe=1");

  const probes = [
    `${origin}/?url=${payload}`,
    `${origin}/%0d%0aSet-Cookie:crlfprobe=1`,
  ];

  for (const probeUrl of probes) {
    try {
      const { res } = await fetchTarget(probeUrl, { followRedirects: false, timeout: 6000 });
      const setCookies = res.headers.getSetCookie?.() || [];
      const rawSetCookie = res.headers.get("set-cookie") || "";
      const location = res.headers.get("location") || "";

      if (
        setCookies.some((c) => /crlfprobe/i.test(c)) ||
        /crlfprobe/i.test(rawSetCookie) ||
        /%0d%0a|\r\n/.test(location)
      ) {
        findings.push({
          id: "crlf-header-injection",
          severity: "high",
          category: "crlf",
          title: "CRLF injection in HTTP response headers",
          description: "Carriage-return/line-feed characters in input influenced response headers.",
          evidence: `${probeUrl} → injected header detected`,
          remediation: "Sanitize and encode all user input used in redirects and header values.",
        });
        return findings;
      }
    } catch {
      /* skip */
    }
  }

  return findings;
}
