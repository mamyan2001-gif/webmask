import { fetchTarget } from "../utils/http.js";

const INTERNAL_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;

const COMMENT_PATTERNS = [
  { id: "todo-fixme", pattern: /<!--[\s\S]*?\b(TODO|FIXME|HACK|XXX|BUG)\b[\s\S]*?-->/gi, severity: "low", title: "Developer TODO/FIXME in HTML comment" },
  { id: "password-comment", pattern: /<!--[\s\S]*?\b(password|passwd|pwd|secret|apikey|api_key)\s*[:=][\s\S]*?-->/gi, severity: "high", title: "Sensitive keyword in HTML comment" },
  { id: "internal-path", pattern: /<!--[\s\S]*?(?:\/var\/|\/home\/|C:\\\\|D:\\\\)[\s\S]*?-->/gi, severity: "medium", title: "Internal file path in HTML comment" },
];

const EMAIL_PATTERN = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;

export async function checkRecon(targetUrl, body, headers) {
  const findings = [];
  const html = body || "";
  const origin = new URL(targetUrl).origin;

  // robots.txt disallowed paths
  try {
    const { res, body: robots } = await fetchTarget(`${origin}/robots.txt`, { timeout: 6000 });
    if (res.ok && robots.trim()) {
      const disallowed = [...robots.matchAll(/^Disallow:\s*(.+)$/gim)]
        .map((m) => m[1].trim())
        .filter((p) => p && p !== "/" && p.length > 1)
        .slice(0, 8);

      findings.push({
        id: "recon-robots-present",
        severity: "info",
        category: "recon",
        title: "robots.txt parsed",
        description: `${disallowed.length} disallowed path(s) extracted for probing.`,
        evidence: disallowed.slice(0, 5).join(", ") || "No Disallow entries",
        remediation: "Ensure disallowed paths are not accessible despite robots.txt.",
      });

      for (const path of disallowed.slice(0, 5)) {
        const probe = path.startsWith("/") ? path : `/${path}`;
        try {
          const { res: pRes, body: pBody } = await fetchTarget(`${origin}${probe}`, {
            followRedirects: false,
            timeout: 6000,
          });
          if (pRes.status >= 200 && pRes.status < 300 && pBody.length > 50) {
            findings.push({
              id: `recon-robots-exposed-${probe.replace(/\W/g, "-")}`,
              severity: "medium",
              category: "recon",
              title: "robots.txt disallowed path is accessible",
              description: `Path marked Disallow in robots.txt returned HTTP ${pRes.status}.`,
              evidence: `${probe} → ${pRes.status}`,
              remediation: "Block access to sensitive paths; robots.txt is not an access control mechanism.",
            });
          }
        } catch {
          /* skip */
        }
      }
    }
  } catch {
    /* skip */
  }

  // sitemap.xml
  try {
    const { res, body: sitemap } = await fetchTarget(`${origin}/sitemap.xml`, { timeout: 6000 });
    if (res.ok && /<urlset|<sitemapindex/i.test(sitemap)) {
      const urls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((m) => m[1]).slice(0, 10);
      findings.push({
        id: "recon-sitemap",
        severity: "info",
        category: "recon",
        title: "sitemap.xml discovered",
        description: "Sitemap reveals additional URLs for the site.",
        evidence: urls.slice(0, 3).join(", ") + (urls.length > 3 ? "…" : ""),
        remediation: "Verify sitemap URLs should be publicly known.",
      });
    }
  } catch {
    /* skip */
  }

  // HTML comments
  for (const spec of COMMENT_PATTERNS) {
    spec.pattern.lastIndex = 0;
    const matches = [...html.matchAll(spec.pattern)];
    if (matches.length > 0) {
      findings.push({
        id: `recon-${spec.id}`,
        severity: spec.severity,
        category: "recon",
        title: spec.title,
        description: "Information found in HTML source comments.",
        evidence: matches[0][0].slice(0, 100).replace(/\s+/g, " ") + "…",
        remediation: "Remove sensitive information from HTML comments before production deployment.",
      });
    }
  }

  // Internal IP disclosure
  const ips = [...new Set(html.match(INTERNAL_IP) || [])];
  if (ips.length > 0) {
    findings.push({
      id: "recon-internal-ip",
      severity: "medium",
      category: "recon",
      title: "Internal IP address in page source",
      description: "Private RFC 1918 addresses were found in the response body.",
      evidence: ips.slice(0, 5).join(", "),
      remediation: "Remove internal IP references from client-visible content.",
    });
  }

  // Meta generator version
  const generator = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1];
  if (generator) {
    findings.push({
      id: "recon-generator-meta",
      severity: "low",
      category: "recon",
      title: "Generator meta tag exposes version",
      description: "CMS or framework version may be disclosed via meta generator tag.",
      evidence: generator.slice(0, 120),
      remediation: "Remove or genericize the generator meta tag.",
    });
  }

  // Email harvesting (info)
  const emails = [...new Set((html.match(EMAIL_PATTERN) || []).filter((e) => !e.endsWith(".png")))].slice(0, 10);
  if (emails.length > 0) {
    findings.push({
      id: "recon-emails",
      severity: "info",
      category: "recon",
      title: `${emails.length} email address(es) in page source`,
      description: "Email addresses visible in HTML may increase spam and social-engineering risk.",
      evidence: emails.slice(0, 5).join(", "),
      remediation: "Use contact forms or obfuscate emails if harvest risk is a concern.",
    });
  }

  return findings;
}
