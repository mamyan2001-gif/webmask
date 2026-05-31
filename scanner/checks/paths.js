import { fetchTarget } from "../utils/http.js";
import { confirmsSensitiveExposure } from "../utils/validation.js";

const SENSITIVE_PATHS = [
  { path: "/.env", severity: "critical", title: "Environment file exposed" },
  { path: "/.env.local", severity: "critical", title: "Local environment file exposed" },
  { path: "/.env.production", severity: "critical", title: "Production environment file exposed" },
  { path: "/.git/HEAD", severity: "critical", title: "Git repository exposed" },
  { path: "/.git/config", severity: "critical", title: "Git config exposed" },
  { path: "/.svn/entries", severity: "high", title: "SVN repository exposed" },
  { path: "/.DS_Store", severity: "medium", title: "macOS .DS_Store exposed" },
  { path: "/backup.zip", severity: "high", title: "Backup archive exposed" },
  { path: "/backup.sql", severity: "critical", title: "Database backup exposed" },
  { path: "/db.sql", severity: "critical", title: "Database dump exposed" },
  { path: "/dump.sql", severity: "critical", title: "SQL dump exposed" },
  { path: "/config.json", severity: "high", title: "Config JSON exposed" },
  { path: "/config.yml", severity: "high", title: "Config YAML exposed" },
  { path: "/web.config", severity: "medium", title: "IIS web.config exposed" },
  { path: "/wp-config.php", severity: "critical", title: "WordPress config exposed" },
  { path: "/wp-config.php.bak", severity: "high", title: "WordPress backup config" },
  { path: "/phpinfo.php", severity: "high", title: "PHP info page" },
  { path: "/info.php", severity: "high", title: "PHP info page" },
  { path: "/server-status", severity: "medium", title: "Apache server-status" },
  { path: "/server-info", severity: "medium", title: "Apache server-info" },
  { path: "/admin", severity: "medium", title: "Admin login surface detected" },
  { path: "/administrator", severity: "medium", title: "Administrator login surface detected" },
  { path: "/cpanel", severity: "medium", title: "cPanel login detected" },
  { path: "/phpmyadmin", severity: "high", title: "phpMyAdmin exposed" },
  { path: "/.aws/credentials", severity: "critical", title: "AWS credentials file exposed" },
  { path: "/crossdomain.xml", severity: "low", title: "Flash crossdomain policy exposed" },
  { path: "/.well-known/security.txt", severity: "info", title: "security.txt present", expectFound: true },
  { path: "/robots.txt", severity: "info", title: "robots.txt present", expectFound: true },
  { path: "/sitemap.xml", severity: "info", title: "sitemap.xml present", expectFound: true },
];

export async function checkSensitivePaths(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  for (const probe of SENSITIVE_PATHS) {
    const url = `${origin}${probe.path}`;
    try {
      const { res, body } = await fetchTarget(url, { followRedirects: false, timeout: 8000 });
      const contentType = res.headers.get("content-type") || "";
      const reachable = res.status >= 200 && res.status < 300 && body.length > 0;

      if (probe.expectFound) {
        if (reachable) {
          findings.push({
            id: `path-found-${probe.path.replace(/\W/g, "-")}`,
            severity: "info",
            category: "paths",
            title: probe.title,
            description: `Resource available at ${probe.path}`,
            evidence: `${probe.path} → HTTP ${res.status}`,
            remediation: "Informational — verify content is intentional.",
          });
        }
        continue;
      }

      if (!reachable) continue;
      if (!confirmsSensitiveExposure(probe.path, body, contentType)) continue;

      const snippet = body.slice(0, 80).replace(/\s+/g, " ");
      findings.push({
        id: `path-exposed-${probe.path.replace(/\W/g, "-")}`,
        severity: probe.severity,
        category: "paths",
        title: probe.title,
        description: `Sensitive path responded with HTTP ${res.status} and content matching expected signatures.`,
        evidence: `${url} → ${res.status}, body: ${snippet}…`,
        remediation: "Remove or restrict access to sensitive files and directories.",
      });
    } catch {
      /* path probe failed — skip */
    }
  }

  return findings;
}
