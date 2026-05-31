export function checkCachePolicy(headers, targetUrl) {
  const findings = [];
  const cacheControl = (headers.get("cache-control") || "").toLowerCase();
  const pragma = (headers.get("pragma") || "").toLowerCase();
  const setCookie = headers.get("set-cookie");
  const url = new URL(targetUrl);

  const isPublic =
    cacheControl.includes("public") ||
    (cacheControl.includes("max-age") && !cacheControl.includes("private") && !cacheControl.includes("no-store"));
  const isNoStore = cacheControl.includes("no-store") || cacheControl.includes("no-cache") || pragma.includes("no-cache");

  if (setCookie && isPublic && !isNoStore) {
    findings.push({
      id: "cache-cookie-public",
      severity: "medium",
      category: "cache",
      title: "Session cookies with publicly cacheable response",
      description: "Set-Cookie was issued but Cache-Control may allow shared caches to store the response.",
      evidence: `Cache-Control: ${cacheControl || "missing"}, Set-Cookie present`,
      remediation: "Use Cache-Control: no-store, private for responses that set session cookies.",
    });
  }

  const sensitivePath = /\/(login|signin|auth|account|admin|dashboard|checkout|payment|profile)\b/i.test(url.pathname);
  if (sensitivePath && !isNoStore) {
    findings.push({
      id: "cache-sensitive-path",
      severity: "medium",
      category: "cache",
      title: "Sensitive path without no-store caching",
      description: "A potentially sensitive URL path lacks Cache-Control: no-store or no-cache.",
      evidence: `${url.pathname} — Cache-Control: ${cacheControl || "missing"}`,
      remediation: "Add Cache-Control: no-store on authenticated or sensitive pages.",
    });
  }

  if (!cacheControl && !sensitivePath && !setCookie) {
    findings.push({
      id: "cache-no-policy",
      severity: "info",
      category: "cache",
      title: "No Cache-Control policy",
      description: "Response does not specify caching behavior — defaults may vary by browser and CDN.",
      evidence: "Cache-Control header not present",
      remediation: "Define explicit Cache-Control for static and dynamic content.",
    });
  } else if (isNoStore || cacheControl.includes("private")) {
    findings.push({
      id: "cache-restricted",
      severity: "info",
      category: "cache",
      title: "Restrictive cache policy",
      description: "Response uses private or no-store caching directives.",
      evidence: `Cache-Control: ${cacheControl || pragma}`,
      remediation: "No action required for dynamic or authenticated content.",
    });
  }

  return findings;
}
