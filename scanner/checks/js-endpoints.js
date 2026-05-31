import { fetchTarget } from "../utils/http.js";
import { extractJsEndpoints } from "../utils/parse-html.js";

export async function checkJsEndpoints(crawlData, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const scriptUrls = [...new Set(crawlData.scriptUrls || [])].slice(0, 15);
  const discovered = new Set(crawlData.endpoints || []);

  for (const scriptUrl of scriptUrls) {
    try {
      const { res, body } = await fetchFn(scriptUrl, { timeout: 10000 });
      if (res.status >= 400 || !body) continue;
      for (const endpoint of extractJsEndpoints(body, scriptUrl)) {
        discovered.add(endpoint);
      }
    } catch {
      /* skip */
    }
  }

  const endpoints = [...discovered];
  if (endpoints.length === 0) {
    return { findings: [], endpoints: [] };
  }

  findings.push({
    id: "js-endpoints-discovered",
    severity: "info",
    category: "js-endpoints",
    title: `${endpoints.length} API endpoint(s) discovered in JavaScript`,
    description: "Endpoints extracted from inline scripts and fetched JS bundles (ZAP AJAX spider class).",
    evidence: endpoints.slice(0, 12).join(", "),
    remediation: "Verify all API routes require authentication and authorization.",
  });

  let probed = 0;
  for (const endpoint of endpoints.slice(0, 20)) {
    try {
      const { res, body } = await fetchFn(endpoint, { followRedirects: false, timeout: 6000 });
      probed += 1;
      if (res.status === 401 || res.status === 403) continue;
      if (res.status >= 200 && res.status < 300 && body.length > 0) {
        const isJson = body.trim().startsWith("{") || body.trim().startsWith("[");
        if (isJson && body.length < 50000) {
          findings.push({
            id: `js-endpoint-open-${endpoint.replace(/\W/g, "-").slice(0, 40)}`,
            severity: "medium",
            title: "Unauthenticated API endpoint responds",
            description: "A JS-discovered endpoint returned data without auth rejection.",
            evidence: `${endpoint} → HTTP ${res.status}, ${body.length} bytes`,
            remediation: "Require authentication on all API routes.",
            pageUrl: endpoint,
          });
        }
      }
    } catch {
      /* skip */
    }
  }

  return { findings, endpoints, endpointsProbed: probed };
}
