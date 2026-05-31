export function checkClickjacking(headers) {
  const findings = [];
  const xfo = headers.get("x-frame-options")?.toLowerCase() || "";
  const csp = headers.get("content-security-policy") || "";
  const frameAncestors = extractFrameAncestors(csp);

  const hasXfo = xfo === "deny" || xfo === "sameorigin";
  const hasCspFrame = frameAncestors.some(
    (v) => v === "'none'" || v === "'self'" || v === "none",
  );

  if (hasXfo || hasCspFrame) {
    findings.push({
      id: "clickjacking-protected",
      severity: "info",
      category: "clickjacking",
      title: "Clickjacking protections present",
      description: "The response restricts framing via X-Frame-Options or CSP frame-ancestors.",
      evidence: [
        xfo ? `X-Frame-Options: ${xfo}` : null,
        frameAncestors.length ? `frame-ancestors: ${frameAncestors.join(" ")}` : null,
      ].filter(Boolean).join("; "),
      remediation: "Review policy covers all sensitive pages, not only the homepage.",
    });
    return findings;
  }

  if (frameAncestors.includes("*")) {
    findings.push({
      id: "clickjacking-allows-all",
      severity: "high",
      category: "clickjacking",
      title: "CSP frame-ancestors allows all origins",
      description: "Any site can embed this page in an iframe.",
      evidence: `frame-ancestors: ${frameAncestors.join(" ")}`,
      remediation: "Set frame-ancestors 'none' or 'self' for sensitive pages.",
    });
    return findings;
  }

  findings.push({
    id: "clickjacking-unprotected",
    severity: "medium",
    category: "clickjacking",
    title: "Missing clickjacking protection",
    description: "No X-Frame-Options or restrictive CSP frame-ancestors was found — page may be embeddable in iframes.",
    evidence: "X-Frame-Options and frame-ancestors not configured",
    remediation: "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none'.",
  });

  return findings;
}

function extractFrameAncestors(csp) {
  if (!csp) return [];
  const directives = csp.split(";").map((d) => d.trim());
  for (const directive of directives) {
    if (/^frame-ancestors\b/i.test(directive)) {
      return directive.split(/\s+/).slice(1);
    }
  }
  return [];
}
