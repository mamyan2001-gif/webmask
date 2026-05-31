import { fetchTarget } from "../utils/http.js";

export function checkTransportSecurity(targetUrl, body, headers) {
  const findings = [];
  const url = new URL(targetUrl);
  const html = body || "";
  const isHttps = url.protocol === "https:";

  if (isHttps) {
    const wsLinks = [...html.matchAll(/\bws:\/\//gi)];
    if (wsLinks.length > 0) {
      findings.push({
        id: "transport-insecure-websocket",
        severity: "medium",
        category: "transport",
        title: "Insecure WebSocket (ws://) on HTTPS page",
        description: "Page references unencrypted WebSocket connections.",
        evidence: `${wsLinks.length} ws:// reference(s) found`,
        remediation: "Use wss:// for all WebSocket connections on HTTPS sites.",
      });
    }
  }

  const encoding = headers.get("content-encoding") || "";
  const hasCompression = /gzip|deflate|br/i.test(encoding);
  const hasSensitivePatterns = /(?:password|session|token|api[_-]?key|secret)/i.test(html.slice(0, 5000));

  if (isHttps && hasCompression && hasSensitivePatterns) {
    findings.push({
      id: "transport-breach-risk",
      severity: "low",
      category: "transport",
      title: "BREACH attack surface (compression + secrets)",
      description: "HTTPS response is compressed and contains sensitive keywords — theoretical BREACH risk if secrets are reflected.",
      evidence: `Content-Encoding: ${encoding}`,
      remediation: "Disable compression on responses containing secrets; use CSRF tokens with random padding.",
    });
  }

  const clearSiteData = headers.get("clear-site-data");
  if (clearSiteData) {
    findings.push({
      id: "transport-clear-site-data",
      severity: "info",
      category: "transport",
      title: "Clear-Site-Data header present",
      description: "Server can instruct browsers to clear site data on logout or security events.",
      evidence: clearSiteData.slice(0, 120),
      remediation: "Use on logout endpoints to clear cookies and storage.",
    });
  }

  const crossOriginEmbedder = headers.get("cross-origin-embedder-policy");
  if (crossOriginEmbedder) {
    findings.push({
      id: "transport-coep",
      severity: "info",
      category: "transport",
      title: "Cross-Origin-Embedder-Policy configured",
      description: "COEP controls cross-origin resource embedding.",
      evidence: `COEP: ${crossOriginEmbedder}`,
      remediation: "Ensure cross-origin resources send appropriate CORP/CORS headers.",
    });
  }

  return findings;
}

export async function checkWebDav(targetUrl) {
  const findings = [];
  const origin = new URL(targetUrl).origin;

  try {
    const { res } = await fetchTarget(origin, { method: "OPTIONS", followRedirects: false, timeout: 8000 });
    const allow = res.headers.get("allow") || "";
    const dav = res.headers.get("dav") || "";

    if (/PROPFIND|MKCOL|COPY|MOVE|LOCK/i.test(allow)) {
      findings.push({
        id: "webdav-methods-allowed",
        severity: "medium",
        category: "webdav",
        title: "WebDAV methods enabled",
        description: "Server advertises WebDAV methods which may allow unauthorized file operations.",
        evidence: `Allow: ${allow.slice(0, 120)}`,
        remediation: "Disable WebDAV if not required; restrict to authenticated users.",
      });
    }

    if (dav) {
      findings.push({
        id: "webdav-header",
        severity: "info",
        category: "webdav",
        title: "DAV header present",
        description: "WebDAV support is advertised by the server.",
        evidence: `DAV: ${dav}`,
        remediation: "Verify WebDAV is intentionally enabled and access-controlled.",
      });
    }
  } catch {
    /* skip */
  }

  try {
    const { res } = await fetchTarget(origin, { method: "PROPFIND", followRedirects: false, timeout: 8000 });
    if (res.status !== 405 && res.status !== 501 && res.status !== 403) {
      findings.push({
        id: "webdav-propfind",
        severity: "high",
        category: "webdav",
        title: "PROPFIND method accepted",
        description: "PROPFIND returned a non-rejection status — directory listing via WebDAV may be possible.",
        evidence: `PROPFIND → HTTP ${res.status}`,
        remediation: "Disable PROPFIND at the web server unless WebDAV is required.",
      });
    }
  } catch {
    /* skip */
  }

  return findings;
}

export async function checkGraphql(targetUrl) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

  const introspectionQuery = JSON.stringify({
    query: "{ __schema { queryType { name } } }",
  });

  for (const path of endpoints) {
    const url = `${origin}${path}`;
    try {
      const { res, body } = await fetchTarget(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: introspectionQuery,
        followRedirects: false,
        timeout: 8000,
      });

      if (res.status < 200 || res.status >= 300) continue;
      if (!/"__schema"|"queryType"|IntrospectionQuery/i.test(body)) continue;
      if (/"errors"\s*:\s*\[\s*\{[^}]*authentication/i.test(body)) continue;

      findings.push({
        id: `graphql-introspection-${path.replace(/\W/g, "-")}`,
        severity: "medium",
        category: "graphql",
        title: "GraphQL introspection enabled",
        description: "GraphQL schema introspection is accessible without authentication.",
        evidence: `${path} → HTTP ${res.status}, introspection response received`,
        remediation: "Disable introspection in production or require authentication.",
      });
      break;
    } catch {
      /* skip */
    }
  }

  return findings;
}

export async function checkCrossDomainPolicy(targetUrl) {
  const findings = [];
  const origin = new URL(targetUrl).origin;

  for (const spec of [
    { path: "/crossdomain.xml", title: "Permissive Flash crossdomain policy", pattern: /allow-access-from domain="\*"/i },
    { path: "/clientaccesspolicy.xml", title: "Permissive Silverlight cross-domain policy", pattern: /Domain.*Resource="/i },
  ]) {
    try {
      const { res, body } = await fetchTarget(`${origin}${spec.path}`, { followRedirects: false, timeout: 6000 });
      if (res.status < 200 || res.status >= 300) continue;
      if (spec.pattern.test(body) && (/domain="\*"/i.test(body) || /Domain\s+URI="/i.test(body))) {
        findings.push({
          id: `crossdomain-${spec.path.replace(/\W/g, "-")}`,
          severity: "medium",
          category: "cross-domain",
          title: spec.title,
          description: "Legacy cross-domain policy allows any origin.",
          evidence: `${spec.path} → HTTP ${res.status}`,
          remediation: "Restrict crossdomain policies to specific trusted domains.",
        });
      }
    } catch {
      /* skip */
    }
  }

  return findings;
}
