import { fetchTarget } from "../utils/http.js";

const CMS_PATHS = {
  wordpress: { paths: ["/wp-login.php", "/wp-content/"], marker: /wp-content|WordPress/i },
  drupal: { paths: ["/core/misc/drupal.js", "/user/login"], marker: /Drupal\.settings|drupal\.js/i },
  joomla: { paths: ["/administrator/", "/media/system/js/core.js"], marker: /Joomla!/i },
  laravel: { paths: ["/login"], marker: /laravel_session|Laravel v\d/i },
};

export async function checkTechnology(targetUrl, body, headers) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const html = body || "";
  const detected = new Set();

  const headerServer = headers.get("server") || "";
  const poweredBy = headers.get("x-powered-by") || "";

  if (/nginx/i.test(headerServer)) detected.add("Nginx");
  if (/apache/i.test(headerServer)) detected.add("Apache");
  if (/cloudflare/i.test(headerServer)) detected.add("Cloudflare");
  if (/PHP/i.test(poweredBy)) detected.add("PHP");
  if (/Express/i.test(poweredBy)) detected.add("Express.js");
  if (/ASP\.NET/i.test(poweredBy)) detected.add("ASP.NET");

  if (/wp-content|wordpress/i.test(html)) detected.add("WordPress");
  if (/Drupal\.settings|drupal\.js/i.test(html)) detected.add("Drupal");
  if (/Joomla!/i.test(html)) detected.add("Joomla");
  if (/laravel_session|Laravel v\d/i.test(html)) detected.add("Laravel");
  if (/react-root|__NEXT_DATA__|next\.js/i.test(html)) detected.add("Next.js");
  if (/\bng-version=|\bangular\.js/i.test(html)) detected.add("Angular");
  if (/data-reactroot|react\.production/i.test(html)) detected.add("React");

  for (const [cms, spec] of Object.entries(CMS_PATHS)) {
    if (detected.has(cms.charAt(0).toUpperCase() + cms.slice(1))) continue;
    for (const path of spec.paths) {
      try {
        const { res, body: probeBody } = await fetchTarget(`${origin}${path}`, {
          followRedirects: false,
          timeout: 6000,
        });
        if (res.status >= 200 && res.status < 400 && spec.marker.test(probeBody || html)) {
          detected.add(cms.charAt(0).toUpperCase() + cms.slice(1));
          break;
        }
      } catch {
        /* skip */
      }
    }
  }

  if (detected.size === 0) {
    findings.push({
      id: "tech-unknown",
      severity: "info",
      category: "technology",
      title: "Technology stack not fingerprinted",
      description: "No definitive CMS or framework signatures were identified.",
      evidence: headerServer ? `Server: ${headerServer}` : "No Server header",
      remediation: "Keep all components patched regardless of fingerprint visibility.",
    });
    return findings;
  }

  findings.push({
    id: "tech-detected",
    severity: "info",
    category: "technology",
    title: `Technology detected: ${[...detected].join(", ")}`,
    description: "Fingerprints from headers and page content identify the technology stack.",
    evidence: [...detected].join(", "),
    remediation: "Monitor CVE advisories for detected software and apply updates promptly.",
  });

  const risky = [...detected].filter((t) => ["WordPress", "Drupal", "Joomla", "PHP"].includes(t));
  if (risky.length) {
    findings.push({
      id: "tech-cms-patch",
      severity: "low",
      category: "technology",
      title: "CMS/framework requires active patching",
      description: `${risky.join(", ")} installations are frequent targets — ensure core, plugins, and themes are updated.`,
      evidence: risky.join(", "),
      remediation: "Enable automatic security updates where possible; remove unused plugins.",
    });
  }

  return findings;
}
