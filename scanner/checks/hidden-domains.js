import { getApexDomain, extractHostnamesFromText, hostnameFromUrl, isUnderApex } from "../utils/domain.js";

function extractCspHosts(value) {
  const hosts = new Set();
  if (!value) return hosts;
  for (const token of value.split(/\s+/)) {
    if (!token || token === "'self'" || token === "'none'" || token.startsWith("'")) continue;
    const host = hostnameFromUrl(token.startsWith("http") ? token : `https://${token}`);
    if (host) hosts.add(host);
  }
  return hosts;
}

function extractLinkHosts(html) {
  const hosts = new Set();
  const tags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of tags) {
    const href = tag.match(/\bhref=["']([^"']+)["']/i)?.[1];
    const rel = tag.match(/\brel=["']([^"']+)["']/i)?.[1]?.toLowerCase() || "";
    if (!href) continue;
    if (!/(preconnect|dns-prefetch|alternate|canonical|stylesheet|icon)/.test(rel) && !href.startsWith("http")) {
      continue;
    }
    const host = hostnameFromUrl(href);
    if (host) hosts.add(host);
  }
  return hosts;
}

function extractScriptAndAnchorHosts(html) {
  const hosts = new Set();
  const attrs = html.match(/\b(?:src|href|action)=["']([^"']+)["']/gi) || [];
  for (const attr of attrs) {
    const url = attr.match(/=["']([^"']+)["']/i)?.[1];
    const host = hostnameFromUrl(url);
    if (host) hosts.add(host);
  }
  return hosts;
}

export function checkHiddenDomains(targetUrl, html, headers) {
  const findings = [];
  const targetHost = new URL(targetUrl).hostname.toLowerCase();
  const apex = getApexDomain(targetHost);
  const discovered = new Map();

  function add(host, source, kind) {
    const key = `${host}|${source}`;
    if (host === targetHost) return;
    if (!discovered.has(key)) {
      discovered.set(key, { host, source, kind });
    }
  }

  for (const host of extractHostnamesFromText(html, apex)) {
    const kind = isUnderApex(host, apex) ? "sibling-subdomain" : "external";
    add(host, "page-content", kind);
  }

  for (const host of extractLinkHosts(html)) {
    const kind = isUnderApex(host, apex) ? "sibling-subdomain" : "external";
    add(host, "link-tags", kind);
  }

  for (const host of extractScriptAndAnchorHosts(html)) {
    const kind = isUnderApex(host, apex) ? "sibling-subdomain" : "external";
    add(host, "script-or-anchor", kind);
  }

  const csp = headers.get("content-security-policy") || headers.get("content-security-policy-report-only");
  if (csp) {
    for (const host of extractCspHosts(csp)) {
      const kind = isUnderApex(host, apex) ? "sibling-subdomain" : "external";
      add(host, "content-security-policy", kind);
    }
  }

  const entries = [...discovered.values()].sort((a, b) => a.host.localeCompare(b.host));
  const siblings = entries.filter((e) => e.kind === "sibling-subdomain");
  const external = entries.filter((e) => e.kind === "external");

  if (entries.length === 0) {
    findings.push({
      id: "hidden-domains-none",
      severity: "info",
      category: "hidden-domains",
      title: "No hidden domains referenced",
      description: "HTML, headers, and linked resources did not reveal additional domains beyond the target.",
      evidence: `Target: ${targetHost}`,
      remediation: "No action required.",
    });
    return { findings, hiddenDomains: [] };
  }

  findings.push({
    id: "hidden-domains-discovered",
    severity: "info",
    category: "hidden-domains",
    title: `${entries.length} referenced domain(s) found`,
    description: "Domains referenced in page markup, assets, or CSP beyond the primary target URL.",
    evidence: entries.map((e) => `${e.host} [${e.source}]`).slice(0, 20).join(", "),
    remediation: "Verify all referenced domains are intentional and use HTTPS with proper security controls.",
  });

  if (siblings.length > 0 && siblings.length <= 8) {
    findings.push({
      id: "hidden-domains-siblings",
      severity: "info",
      category: "hidden-domains",
      title: `${siblings.length} sibling subdomain(s) referenced in page`,
      description: "Related subdomains appear in HTML, scripts, or CSP.",
      evidence: siblings.map((e) => e.host).join(", "),
      remediation: "Ensure sibling subdomains are hardened and not exposing admin or staging environments.",
    });
  }

  if (external.length > 0) {
    findings.push({
      id: "hidden-domains-external",
      severity: "info",
      category: "hidden-domains",
      title: `${external.length} third-party domain(s) referenced`,
      description: "External domains loaded or referenced by the target page.",
      evidence: external.map((e) => e.host).slice(0, 15).join(", "),
      remediation: "Review third-party dependencies for supply-chain and data leakage risks.",
    });
  }

  return { findings, hiddenDomains: entries };
}
