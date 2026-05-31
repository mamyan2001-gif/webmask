import { checkFormSecurity } from "./forms-errors.js";
import { checkContentSecurity } from "./content-security.js";
import { checkInputReflection } from "./reflection.js";
import { checkHiddenDomains } from "./hidden-domains.js";

export function scanPageSurface(page, targetUrl) {
  const findings = [];
  const { url, body, headers } = page;
  const headerObj = headers;

  findings.push(
    ...checkFormSecurity(body).map((f) => ({ ...f, pageUrl: url, id: `${f.id}-${hashUrl(url)}` })),
  );
  findings.push(
    ...checkContentSecurity(url, body, headerObj).map((f) => ({ ...f, pageUrl: url, id: `${f.id}-${hashUrl(url)}` })),
  );

  const hidden = checkHiddenDomains(targetUrl, body, headerObj);
  for (const f of hidden.findings) {
    if (f.severity !== "info") {
      findings.push({ ...f, pageUrl: url, id: `${f.id}-${hashUrl(url)}` });
    }
  }

  return findings;
}

export async function scanPagesReflection(pages, targetUrl, fetchFn) {
  const findings = [];
  const tested = new Set();

  for (const page of pages.slice(0, 12)) {
    const url = new URL(page.url);
    if (!url.search) continue;
    if (tested.has(url.pathname)) continue;
    tested.add(url.pathname);

    const pageFindings = await checkInputReflection(page.url);
    for (const f of pageFindings) {
      if (f.id === "reflection-none") continue;
      findings.push({ ...f, pageUrl: page.url, id: `${f.id}-${hashUrl(page.url)}` });
    }
  }

  if (findings.length === 0 && pages.length > 1) {
    findings.push({
      id: "multipage-reflection-clean",
      severity: "info",
      category: "reflection",
      title: "Multi-page reflection scan complete",
      description: `Tested ${Math.min(pages.length, 12)} crawled pages for reflected input.`,
      evidence: `${pages.length} pages in scope`,
      remediation: "No action required.",
    });
  }

  return findings;
}

function hashUrl(url) {
  return url.replace(/\W/g, "").slice(-24);
}
