import { fetchTarget, fetchRedirectChain } from "../utils/http.js";
import {
  chainUpgradesToHttps,
  hasEffectiveHsts,
  locationRedirectsToProbe,
  OPEN_REDIRECT_PROBE,
  parseLocationUrl,
  sameRegistrableDomain,
} from "../utils/validation.js";

const OPEN_REDIRECT_PARAMS = [
  "url", "redirect", "next", "return", "returnUrl", "dest", "destination", "redir", "continue",
];

function isSameSiteRedirect(fromUrl, location) {
  const dest = parseLocationUrl(location, fromUrl);
  if (!dest) return true;
  const fromHost = new URL(fromUrl).hostname;
  return sameRegistrableDomain(fromHost, dest.hostname);
}

export async function checkRedirects(targetUrl, { hstsHeader } = {}) {
  const findings = [];
  const url = new URL(targetUrl);
  const origin = url.origin;
  const hstsActive = hasEffectiveHsts(hstsHeader);

  if (url.protocol === "https:") {
    const httpUrl = `http://${url.host}${url.pathname}${url.search}`;
    try {
      const chain = await fetchRedirectChain(httpUrl, 10);
      const upgrades = chainUpgradesToHttps(chain);
      const finalHop = chain[chain.length - 1];
      const httpStillServesContent =
        finalHop &&
        finalHop.url.startsWith("http://") &&
        finalHop.status >= 200 &&
        finalHop.status < 400;

      if (upgrades) {
        findings.push({
          id: "redirect-https-upgrade",
          severity: "info",
          category: "redirects",
          title: "HTTP upgrades to HTTPS",
          description: "Plain HTTP redirects to a secure URL.",
          evidence: chain.map((h) => `${h.status} ${h.url}`).join(" → "),
          remediation: "Consider HSTS preload for stronger protection.",
        });
      } else if (httpStillServesContent && hstsActive) {
        findings.push({
          id: "redirect-hsts-enforced",
          severity: "info",
          category: "redirects",
          title: "HSTS enforces HTTPS in browsers",
          description:
            "The HTTP endpoint responded without a redirect chain to HTTPS, but the site publishes HSTS so modern browsers upgrade automatically.",
          evidence: `${chain.map((h) => `${h.status} ${h.url}`).join(" → ")}; HSTS: ${hstsHeader?.slice(0, 80)}`,
          remediation: "Optionally add explicit HTTP→HTTPS redirects for non-browser clients.",
        });
      } else if (httpStillServesContent) {
        const finalUrl = new URL(finalHop.url);
        const httpsProbe = `https://${finalUrl.host}${finalUrl.pathname}${finalUrl.search}`;
        let httpsAvailable = false;
        try {
          const { res: httpsRes } = await fetchTarget(httpsProbe, {
            followRedirects: false,
            timeout: 6000,
          });
          httpsAvailable = httpsRes.status >= 200 && httpsRes.status < 500;
        } catch {
          httpsAvailable = false;
        }

        if (httpsAvailable) {
          findings.push({
            id: "redirect-http-mirror",
            severity: "low",
            category: "redirects",
            title: "HTTP accessible without redirect",
            description:
              "Plain HTTP responds without redirecting to HTTPS, but TLS is available on the same host. Risk is mainly for clients that never upgrade.",
            evidence: `${chain.map((h) => `${h.status} ${h.url}`).join(" → ")}; HTTPS probe: ${httpsProbe} reachable`,
            remediation: "Add an explicit HTTP→HTTPS redirect (301/308) for defense in depth.",
          });
        } else {
          findings.push({
            id: "redirect-no-https-upgrade",
            severity: "high",
            category: "redirects",
            title: "HTTP not redirected to HTTPS",
            description: "Plain HTTP is reachable without upgrading to TLS and HTTPS does not appear available on the same host.",
            evidence: chain.map((h) => `${h.status} ${h.url}`).join(" → "),
            remediation: "Redirect all HTTP traffic to HTTPS with a 301/308 response and enable HSTS.",
          });
        }
      }
    } catch {
      /* skip */
    }
  }

  try {
    const chain = await fetchRedirectChain(targetUrl, 10);
    if (chain.length > 5) {
      findings.push({
        id: "redirect-long-chain",
        severity: "low",
        category: "redirects",
        title: "Long redirect chain",
        description: "Multiple redirects increase latency and may leak tokens in Referer headers.",
        evidence: chain.map((h) => `${h.status} ${h.url}`).join(" → "),
        remediation: "Reduce redirect hops; avoid chaining through third-party domains.",
      });
    }

    for (const hop of chain) {
      if (hop.status >= 300 && hop.status < 400 && hop.location) {
        const dest = parseLocationUrl(hop.location, hop.url);
        if (!dest) continue;
        const fromHost = new URL(hop.url).hostname;
        if (sameRegistrableDomain(fromHost, dest.hostname)) continue;

        findings.push({
          id: `redirect-cross-origin-${hop.status}`,
          severity: "low",
          category: "redirects",
          title: "Cross-origin redirect detected",
          description: "Response redirects users to a different registrable domain.",
          evidence: `${hop.url} → ${dest.href} (${hop.status})`,
          remediation: "Verify cross-origin redirects are intentional and do not accept user input.",
        });
        break;
      }
    }
  } catch {
    /* skip */
  }

  for (const param of OPEN_REDIRECT_PARAMS) {
    const probeUrl = `${origin}/?${param}=${encodeURIComponent(OPEN_REDIRECT_PROBE.url)}`;
    try {
      const { res } = await fetchTarget(probeUrl, { followRedirects: false, timeout: 6000 });
      const location = res.headers.get("location") || "";
      if (
        res.status >= 300 &&
        res.status < 400 &&
        locationRedirectsToProbe(location, probeUrl)
      ) {
        findings.push({
          id: `open-redirect-${param}`,
          severity: "high",
          category: "redirects",
          title: "Open redirect confirmed",
          description: `Query parameter "${param}" redirects the browser to an external domain.`,
          evidence: `${probeUrl} → HTTP ${res.status}, Location: ${location}`,
          remediation: "Validate redirect targets against an allowlist; use relative paths only.",
        });
        break;
      }
    } catch {
      /* skip */
    }
  }

  return findings;
}
