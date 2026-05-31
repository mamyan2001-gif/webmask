import { fetchTarget } from "../utils/http.js";
import {
  hostReflectedInBody,
  locationRedirectsToHost,
  parseLocationUrl,
} from "../utils/validation.js";

const POISON_HOST = "webmask-probe.invalid";

export async function checkHostInjection(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);

  try {
    const { res, body } = await fetchTarget(targetUrl, {
      headers: { Host: POISON_HOST },
      followRedirects: false,
      timeout: 8000,
    });

    const location = res.headers.get("location") || "";
    const locationHost = parseLocationUrl(location, targetUrl)?.hostname;

    if (locationHost && locationRedirectsToHost(location, targetUrl, POISON_HOST)) {
      findings.push({
        id: "host-header-redirect",
        severity: "high",
        category: "injection",
        title: "Host header influenced redirect",
        description: "Crafted Host header produced a redirect targeting the injected hostname.",
        evidence: `Location: ${location}`,
        remediation: "Build redirect URLs from configured base URL, not from Host header.",
      });
    }

    if (hostReflectedInBody(body, POISON_HOST)) {
      findings.push({
        id: "host-header-reflected",
        severity: "high",
        category: "injection",
        title: "Host header reflected in response",
        description: "The server echoes a crafted Host header in URLs or markup — cache poisoning or password-reset hijacking risk.",
        evidence: `Host: ${POISON_HOST} reflected in response body (HTTP ${res.status})`,
        remediation: "Use a fixed canonical host; reject requests with unexpected Host headers at the edge.",
      });
    }
  } catch {
    /* skip */
  }

  return findings;
}
