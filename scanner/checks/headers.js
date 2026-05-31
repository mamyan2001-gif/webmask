const SECURITY_HEADERS = [
  {
    name: "Strict-Transport-Security",
    severity: "medium",
    title: "Missing HSTS header",
    description: "HTTP Strict Transport Security helps prevent downgrade and cookie hijacking attacks.",
    remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
  },
  {
    name: "Content-Security-Policy",
    severity: "medium",
    title: "Missing Content-Security-Policy",
    description: "CSP reduces XSS and data injection risks by restricting resource sources.",
    remediation: "Define a Content-Security-Policy appropriate for your application.",
  },
  {
    name: "X-Frame-Options",
    severity: "medium",
    title: "Missing X-Frame-Options",
    description: "Without this header, the site may be embedded in iframes (clickjacking risk).",
    remediation: "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.",
  },
  {
    name: "X-Content-Type-Options",
    severity: "low",
    title: "Missing X-Content-Type-Options",
    description: "Browsers may MIME-sniff responses without nosniff.",
    remediation: "Add X-Content-Type-Options: nosniff",
  },
  {
    name: "Referrer-Policy",
    severity: "low",
    title: "Missing Referrer-Policy",
    description: "Referrer information may leak to third parties.",
    remediation: "Add Referrer-Policy: strict-origin-when-cross-origin or stricter.",
  },
  {
    name: "Permissions-Policy",
    severity: "low",
    title: "Missing Permissions-Policy",
    description: "Browser features (camera, geolocation, etc.) are not restricted by policy.",
    remediation: "Add Permissions-Policy to disable unused browser features.",
  },
  {
    name: "Cross-Origin-Opener-Policy",
    severity: "low",
    title: "Missing Cross-Origin-Opener-Policy",
    description: "Without COOP, cross-origin documents may retain references to your window (XS-Leaks).",
    remediation: "Add Cross-Origin-Opener-Policy: same-origin for sensitive applications.",
  },
  {
    name: "Cross-Origin-Resource-Policy",
    severity: "low",
    title: "Missing Cross-Origin-Resource-Policy",
    description: "Resources may be loaded cross-origin without explicit policy.",
    remediation: "Add Cross-Origin-Resource-Policy: same-origin or cross-origin as appropriate.",
  },
];

export function checkSecurityHeaders(headers, isHttps) {
  const findings = [];
  const lower = {};
  headers.forEach((v, k) => {
    lower[k.toLowerCase()] = v;
  });

  for (const spec of SECURITY_HEADERS) {
    const key = spec.name.toLowerCase();
    if (!lower[key]) {
      if (spec.name === "Strict-Transport-Security" && !isHttps) continue;
      findings.push({
        id: `header-missing-${key}`,
        severity: spec.severity,
        category: "headers",
        title: spec.title,
        description: spec.description,
        evidence: `Header ${spec.name} not present in response`,
        remediation: spec.remediation,
      });
    } else {
      findings.push({
        id: `header-present-${key}`,
        severity: "info",
        category: "headers",
        title: `${spec.name} configured`,
        description: "Security header is present.",
        evidence: `${spec.name}: ${lower[key].slice(0, 120)}`,
        remediation: "Review value for best-practice configuration.",
      });
    }
  }

  return findings;
}

export function checkDisclosureHeaders(headers) {
  const findings = [];
  const lower = {};
  headers.forEach((v, k) => {
    lower[k.toLowerCase()] = v;
  });

  if (lower.server) {
    findings.push({
      id: "disclosure-server",
      severity: "low",
      category: "disclosure",
      title: "Server version disclosed",
      description: "The Server header reveals software information useful to attackers.",
      evidence: `Server: ${lower.server}`,
      remediation: "Remove or genericize the Server header in production.",
    });
  }

  if (lower["x-powered-by"]) {
    findings.push({
      id: "disclosure-powered-by",
      severity: "low",
      category: "disclosure",
      title: "X-Powered-By header exposed",
      description: "Technology stack information is exposed to clients.",
      evidence: `X-Powered-By: ${lower["x-powered-by"]}`,
      remediation: "Disable X-Powered-By in your framework or reverse proxy.",
    });
  }

  return findings;
}
