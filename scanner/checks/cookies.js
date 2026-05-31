export function checkCookies(setCookieHeaders) {
  const findings = [];
  if (!setCookieHeaders.length) return findings;

  for (const raw of setCookieHeaders) {
    const name = raw.split("=")[0]?.trim() || "unknown";
    const lower = raw.toLowerCase();

    if (!lower.includes("secure") && !lower.includes("__host-")) {
      findings.push({
        id: `cookie-no-secure-${name}`,
        severity: "medium",
        category: "cookies",
        title: `Cookie "${name}" missing Secure flag`,
        description: "Cookie may be sent over unencrypted connections.",
        evidence: raw.slice(0, 160),
        remediation: "Set the Secure attribute on cookies transmitted over HTTPS.",
      });
    }

    if (!lower.includes("httponly")) {
      findings.push({
        id: `cookie-no-httponly-${name}`,
        severity: "medium",
        category: "cookies",
        title: `Cookie "${name}" missing HttpOnly flag`,
        description: "Cookie is accessible to JavaScript (XSS theft risk).",
        evidence: raw.slice(0, 160),
        remediation: "Set HttpOnly on session and sensitive cookies.",
      });
    }

    if (!lower.includes("samesite")) {
      findings.push({
        id: `cookie-no-samesite-${name}`,
        severity: "low",
        category: "cookies",
        title: `Cookie "${name}" missing SameSite attribute`,
        description: "Cookie may be sent in cross-site requests (CSRF risk).",
        evidence: raw.slice(0, 160),
        remediation: "Set SameSite=Lax or SameSite=Strict as appropriate.",
      });
    }
  }

  return findings;
}
