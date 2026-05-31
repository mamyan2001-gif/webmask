import { fetchTarget } from "../utils/http.js";
import { isGenericSpaOrHomepage } from "../utils/validation.js";
import { BUILTIN_TEMPLATES } from "../templates/builtin.js";

function matchTemplate(body, status, matchers) {
  if (status < 200 || status >= 400 || !body) return false;
  for (const matcher of matchers || []) {
    if (matcher.type === "word") {
      if (!matcher.words.some((w) => body.includes(w))) return false;
    } else if (matcher.type === "regex") {
      if (!matcher.regex.some((r) => new RegExp(r, "m").test(body))) return false;
    } else if (matcher.type === "status") {
      if (!matcher.status.includes(status)) return false;
    }
  }
  return (matchers || []).length > 0;
}

export async function runTemplateScan(baseUrl, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const templates = options.templates || BUILTIN_TEMPLATES;
  const origin = new URL(baseUrl).origin;
  const concurrency = options.concurrency || 8;
  let matched = 0;

  for (let i = 0; i < templates.length; i += concurrency) {
    const batch = templates.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(async (tpl) => {
        const url = `${origin}${tpl.path}`;
        try {
          const { res, body } = await fetchFn(url, {
            method: tpl.method || "GET",
            followRedirects: false,
            timeout: 8000,
            headers: tpl.headers || {},
          });
          if (isGenericSpaOrHomepage(body) && tpl.severity !== "critical") return null;
          if (!matchTemplate(body, res.status, tpl.matchers)) return null;
          return { tpl, url, status: res.status };
        } catch {
          return null;
        }
      }),
    );

    for (const hit of results.filter(Boolean)) {
      matched += 1;
      findings.push({
        id: hit.tpl.id,
        severity: hit.tpl.severity,
        category: "templates",
        title: hit.tpl.name,
        description: "Nuclei-class template matched response content.",
        evidence: `${hit.url} → HTTP ${hit.status}`,
        remediation: "Remove or restrict access to sensitive resources.",
        templateId: hit.tpl.id,
      });
    }
  }

  if (matched === 0) {
    findings.push({
      id: "templates-clean",
      severity: "info",
      category: "templates",
      title: "No template matches in built-in library",
      description: `${templates.length} Nuclei-style templates executed without confirmed matches.`,
      evidence: `${templates.length} templates tested`,
      remediation: "No action required.",
    });
  }

  return { findings, templatesRun: templates.length, templatesMatched: matched };
}
