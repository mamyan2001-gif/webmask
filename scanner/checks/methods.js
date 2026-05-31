import { fetchTarget } from "../utils/http.js";

const PROBE_METHODS = ["OPTIONS", "TRACE", "PUT", "DELETE"];

export async function checkHttpMethods(targetUrl) {
  const findings = [];
  const allowed = [];

  for (const method of PROBE_METHODS) {
    try {
      const { res } = await fetchTarget(targetUrl, { method, followRedirects: false });
      if (res.status !== 405 && res.status !== 501 && res.status !== 403) {
        allowed.push(`${method} → ${res.status}`);
      }
    } catch {
      /* ignore */
    }
  }

  if (allowed.some((a) => a.startsWith("TRACE"))) {
    findings.push({
      id: "method-trace-enabled",
      severity: "medium",
      category: "methods",
      title: "HTTP TRACE method enabled",
      description: "TRACE can be used in cross-site tracing (XST) attacks.",
      evidence: allowed.find((a) => a.startsWith("TRACE")),
      remediation: "Disable TRACE at the web server or load balancer.",
    });
  }

  const dangerous = allowed.filter((a) => a.startsWith("PUT") || a.startsWith("DELETE"));
  if (dangerous.length) {
    findings.push({
      id: "method-write-enabled",
      severity: "low",
      category: "methods",
      title: "Write HTTP methods respond on root URL",
      description: "PUT/DELETE returned non-405 responses — verify unintended write access.",
      evidence: dangerous.join("; "),
      remediation: "Restrict write methods to authenticated API endpoints only.",
    });
  }

  if (allowed.length === 0) {
    findings.push({
      id: "methods-restricted",
      severity: "info",
      category: "methods",
      title: "Dangerous HTTP methods restricted",
      description: "TRACE/PUT/DELETE appear blocked or rejected on the target.",
      evidence: "No unexpected method responses",
      remediation: "No action required.",
    });
  }

  return findings;
}
