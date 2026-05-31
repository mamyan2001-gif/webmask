import { fetchTarget } from "../utils/http.js";
import { isHtmlResponse, isGenericSpaOrHomepage } from "../utils/validation.js";
import { NIKTO_PATHS } from "../wordlists/common-paths.js";

const MAX_PATHS = 65;
const BATCH = 8;

async function probePath(origin, probe) {
  const url = `${origin}${probe.path}`;
  const { res, body } = await fetchTarget(url, { followRedirects: false, timeout: 6000 });
  const contentType = res.headers.get("content-type") || "";
  const reachable = res.status >= 200 && res.status < 300 && body.length > 0;
  if (!reachable) return null;

  if (probe.expectFound) {
    if (probe.marker?.test(body) || !isHtmlResponse(body, contentType)) {
      return { probe, url, res, body, info: true };
    }
    return null;
  }

  if (!probe.marker?.test(body)) return null;
  if (isGenericSpaOrHomepage(body) && probe.severity !== "critical") return null;

  return { probe, url, res, body, info: false };
}

export async function checkNiktoPaths(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;
  const paths = NIKTO_PATHS.slice(0, MAX_PATHS);
  let exposed = 0;

  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.all(batch.map((p) => probePath(origin, p).catch(() => null)));

    for (const hit of results.filter(Boolean)) {
      if (hit.info) {
        findings.push({
          id: `nikto-info-${hit.probe.path.replace(/\W/g, "-")}`,
          severity: "info",
          category: "nikto",
          title: hit.probe.title,
          description: `Resource available at ${hit.probe.path}.`,
          evidence: `${hit.probe.path} → HTTP ${hit.res.status}`,
          remediation: "Verify exposure is intentional.",
        });
        continue;
      }

      exposed += 1;
      findings.push({
        id: `nikto-${hit.probe.path.replace(/\W/g, "-")}`,
        severity: hit.probe.severity,
        category: "nikto",
        title: hit.probe.title,
        description: "Nikto-class path responded with matching content signatures.",
        evidence: `${hit.url} → HTTP ${hit.res.status}`,
        remediation: "Remove or restrict access; block sensitive paths at the web server or WAF.",
      });
    }
  }

  if (exposed === 0 && findings.length === 0) {
    findings.push({
      id: "nikto-clean",
      severity: "info",
      category: "nikto",
      title: "No Nikto-class path exposures detected",
      description: `${paths.length} common scanner paths probed without confirmed sensitive content.`,
      evidence: `${paths.length} paths tested`,
      remediation: "No action required.",
    });
  }

  return findings;
}
