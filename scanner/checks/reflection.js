import { fetchTarget } from "../utils/http.js";

const REFLECTION_PARAMS = ["q", "search", "query", "s", "name", "test", "keyword", "input"];

const DANGEROUS_CONTEXTS = [
  { id: "script", pattern: (c, canary) => new RegExp(`<script[^>]*>[^<]*${escapeRegex(canary)}`, "i").test(c) },
  { id: "attribute-unquoted", pattern: (c, canary) => new RegExp(`=\\s*${escapeRegex(canary)}[\\s>\\/]`, "i").test(c) },
  { id: "event-handler", pattern: (c, canary) => new RegExp(`on\\w+\\s*=\\s*["']?[^"'>]*${escapeRegex(canary)}`, "i").test(c) },
  { id: "raw-html", pattern: (c, canary) => new RegExp(`<[^>]*${escapeRegex(canary)}[^>]*>`, "i").test(c) },
];

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isEncoded(canary, fragment) {
  return (
    fragment.includes(encodeURIComponent(canary)) ||
    fragment.includes(canary.replace(/</g, "&lt;").replace(/>/g, "&gt;"))
  );
}

export async function checkInputReflection(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  const origin = url.origin;
  const canary = `sfcan${Date.now().toString(36)}`;

  for (const param of REFLECTION_PARAMS) {
    const probeUrl = `${origin}/?${param}=${encodeURIComponent(`${canary}-${param}`)}`;
    try {
      const { res, body } = await fetchTarget(probeUrl, { followRedirects: true, timeout: 8000 });
      if (res.status >= 500 || !body) continue;

      const needle = `${canary}-${param}`;
      if (!body.includes(needle)) continue;
      if (isEncoded(needle, body)) {
        findings.push({
          id: `reflection-encoded-${param}`,
          severity: "info",
          category: "reflection",
          title: `Input reflected safely (${param})`,
          description: "Parameter value appears in the response in encoded form.",
          evidence: `Param ${param} reflected with encoding`,
          remediation: "Continue encoding output contextually; verify server-side validation.",
        });
        continue;
      }

      const context = DANGEROUS_CONTEXTS.find((ctx) => ctx.pattern(body, needle));
      if (context) {
        findings.push({
          id: `reflection-dangerous-${param}-${context.id}`,
          severity: "high",
          category: "reflection",
          title: "Unencoded input reflected in dangerous context",
          description: `Parameter "${param}" is reflected without encoding in a ${context.id} context — potential XSS.`,
          evidence: `${probeUrl} → reflected in ${context.id}`,
          remediation: "HTML-encode all user input in output; use Content-Security-Policy as defense in depth.",
        });
        break;
      }

      findings.push({
        id: `reflection-plain-${param}`,
        severity: "low",
        category: "reflection",
        title: `Input reflected in response (${param})`,
        description: "Parameter value appears unencoded in the page — review surrounding HTML context.",
        evidence: `Param ${param} reflected in response body`,
        remediation: "Ensure contextual output encoding for all reflected user input.",
      });
    } catch {
      /* skip */
    }
  }

  if (findings.length === 0) {
    findings.push({
      id: "reflection-none",
      severity: "info",
      category: "reflection",
      title: "No input reflection detected",
      description: "Common query parameters were not reflected in the homepage response.",
      evidence: `Tested params: ${REFLECTION_PARAMS.join(", ")}`,
      remediation: "No action required for homepage; test authenticated pages separately.",
    });
  }

  return findings;
}
