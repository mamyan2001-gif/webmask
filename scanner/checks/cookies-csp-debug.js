export function checkCookiesAdvanced(setCookieHeaders) {
  const findings = [];
  if (!setCookieHeaders?.length) return findings;

  for (const raw of setCookieHeaders) {
    const name = raw.split("=")[0]?.trim() || "unknown";
    const lower = raw.toLowerCase();

    if (lower.includes("samesite=none") && !lower.includes("secure")) {
      findings.push({
        id: `cookie-samesite-none-insecure-${name}`,
        severity: "high",
        category: "cookies-advanced",
        title: `Cookie "${name}" uses SameSite=None without Secure`,
        description: "Browsers reject SameSite=None cookies without the Secure flag.",
        evidence: raw.slice(0, 160),
        remediation: "Add Secure attribute when using SameSite=None.",
      });
    }

    if (name.startsWith("__Secure-") && !lower.includes("secure")) {
      findings.push({
        id: `cookie-secure-prefix-violation-${name}`,
        severity: "high",
        category: "cookies-advanced",
        title: `Cookie "${name}" violates __Secure- prefix rules`,
        description: "Cookies with __Secure- prefix must include the Secure attribute.",
        evidence: raw.slice(0, 160),
        remediation: "Add Secure flag or rename the cookie.",
      });
    }

    if (name.startsWith("__Host-")) {
      const violations = [];
      if (!lower.includes("secure")) violations.push("missing Secure");
      if (!lower.includes("path=/")) violations.push("Path must be /");
      if (lower.includes("domain=")) violations.push("must not have Domain");
      if (violations.length) {
        findings.push({
          id: `cookie-host-prefix-violation-${name}`,
          severity: "high",
          category: "cookies-advanced",
          title: `Cookie "${name}" violates __Host- prefix rules`,
          description: `__Host- cookies require Secure, Path=/, and no Domain. Issues: ${violations.join(", ")}.`,
          evidence: raw.slice(0, 160),
          remediation: "Fix cookie attributes to comply with __Host- prefix specification.",
        });
      }
    }

    if (/^(session|sess|sid|auth|token|jwt)/i.test(name) && !lower.includes("secure") && !name.startsWith("__")) {
      findings.push({
        id: `cookie-session-no-secure-${name}`,
        severity: "medium",
        category: "cookies-advanced",
        title: `Session-like cookie "${name}" missing Secure flag`,
        description: "Authentication cookies should always include the Secure attribute.",
        evidence: raw.slice(0, 160),
        remediation: "Set Secure on all session and authentication cookies.",
      });
    }
  }

  return findings;
}

export function checkCspDeep(headers) {
  const findings = [];
  const csp = headers.get("content-security-policy") || "";
  if (!csp) return findings;

  if (/\bdefault-src\s+[^;]*\*/i.test(csp)) {
    findings.push({
      id: "csp-default-src-wildcard",
      severity: "high",
      category: "csp",
      title: "CSP default-src allows wildcard",
      description: "default-src * permits loading resources from any origin.",
      evidence: csp.match(/\bdefault-src\s+[^;]+/i)?.[0]?.slice(0, 120),
      remediation: "Replace wildcard with explicit trusted origins.",
    });
  }

  if (/\bscript-src\s+[^;]*\bdata:/i.test(csp)) {
    findings.push({
      id: "csp-script-src-data",
      severity: "medium",
      category: "csp",
      title: "CSP script-src allows data: URIs",
      description: "data: in script-src can enable certain XSS payloads.",
      evidence: csp.match(/\bscript-src\s+[^;]+/i)?.[0]?.slice(0, 120),
      remediation: "Remove data: from script-src unless strictly required.",
    });
  }

  if (!/\bobject-src\s/i.test(csp)) {
    findings.push({
      id: "csp-missing-object-src",
      severity: "low",
      category: "csp",
      title: "CSP missing object-src directive",
      description: "Without object-src, plugin content may fall back to default-src.",
      evidence: "No object-src in policy",
      remediation: "Add object-src 'none' unless plugins are required.",
    });
  }

  if (!/\bbase-uri\s/i.test(csp)) {
    findings.push({
      id: "csp-missing-base-uri",
      severity: "low",
      category: "csp",
      title: "CSP missing base-uri directive",
      description: "Missing base-uri allows injected base tags to hijack relative URLs.",
      evidence: "No base-uri in policy",
      remediation: "Add base-uri 'self' or 'none'.",
    });
  }

  if (/\bupgrade-insecure-requests\b/i.test(csp)) {
    findings.push({
      id: "csp-upgrade-insecure",
      severity: "info",
      category: "csp",
      title: "CSP upgrade-insecure-requests enabled",
      description: "Mixed content may be automatically upgraded to HTTPS.",
      evidence: "upgrade-insecure-requests present",
      remediation: "No action required.",
    });
  }

  return findings;
}

export function checkDebugHeaders(headers) {
  const findings = [];
  const debugHeaders = [
    { name: "x-aspnet-version", severity: "low", title: "ASP.NET version disclosed" },
    { name: "x-aspnetmvc-version", severity: "low", title: "ASP.NET MVC version disclosed" },
    { name: "x-generator", severity: "low", title: "X-Generator header exposed" },
    { name: "x-drupal-cache", severity: "info", title: "Drupal cache header exposed" },
    { name: "x-drupal-dynamic-cache", severity: "info", title: "Drupal dynamic cache header" },
    { name: "x-varnish", severity: "info", title: "Varnish cache header exposed" },
    { name: "x-debug-token", severity: "medium", title: "Symfony debug token exposed" },
    { name: "x-debug-token-link", severity: "high", title: "Symfony profiler link exposed" },
    { name: "x-runtime", severity: "low", title: "Application runtime header exposed" },
    { name: "x-version", severity: "low", title: "Application version header exposed" },
    { name: "x-backend-server", severity: "medium", title: "Backend server hostname disclosed" },
    { name: "x-served-by", severity: "low", title: "Backend node identifier disclosed" },
  ];

  for (const spec of debugHeaders) {
    const value = headers.get(spec.name);
    if (!value) continue;
    findings.push({
      id: `debug-header-${spec.name.replace(/\W/g, "-")}`,
      severity: spec.severity,
      category: "debug-headers",
      title: spec.title,
      description: "Response header reveals implementation or infrastructure details.",
      evidence: `${spec.name}: ${value.slice(0, 120)}`,
      remediation: "Strip internal debug and version headers at the reverse proxy.",
    });
  }

  return findings;
}
