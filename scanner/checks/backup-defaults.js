import { fetchTarget } from "../utils/http.js";
import { isHtmlResponse } from "../utils/validation.js";
import { BACKUP_SUFFIXES, DEFAULT_PAGE_SIGNATURES } from "../wordlists/common-paths.js";

export async function checkBackupDiscovery(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  const origin = url.origin;
  const basePath = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");

  const targets = basePath
    ? BACKUP_SUFFIXES.map((s) => `${basePath}${s}`)
    : ["/index.php", "/index.html", "/config.php", "/settings.py"].flatMap((p) =>
        BACKUP_SUFFIXES.slice(0, 6).map((s) => `${p}${s}`),
      );

  for (const path of targets.slice(0, 16)) {
    const probeUrl = `${origin}${path}`;
    try {
      const { res, body } = await fetchTarget(probeUrl, { followRedirects: false, timeout: 6000 });
      if (res.status < 200 || res.status >= 300 || !body.trim()) continue;
      if (isHtmlResponse(body) && body.length > 50000) continue;

      const looksLikeBackup =
        path.endsWith(".sql") ? /(CREATE TABLE|INSERT INTO)/i.test(body) :
        path.endsWith(".zip") || path.endsWith(".tar.gz") ? body.slice(0, 2) === "PK" || body.startsWith("\x1f\x8b") :
        path.endsWith(".bak") || path.endsWith(".old") ? body.length > 20 && !/^<!DOCTYPE html/i.test(body.slice(0, 100)) :
        body.length > 0;

      if (!looksLikeBackup) continue;

      findings.push({
        id: `backup-${path.replace(/\W/g, "-")}`,
        severity: path.includes(".sql") ? "critical" : "high",
        category: "backup",
        title: "Backup file discovered",
        description: `A backup or alternate version of a file may be exposed at ${path}.`,
        evidence: `${probeUrl} → HTTP ${res.status}, ${body.length} bytes`,
        remediation: "Remove backup files from the web root; block backup extensions in the server config.",
      });
    } catch {
      /* skip */
    }
  }

  return findings;
}

export async function checkDefaultPages(targetUrl, headers) {
  const findings = [];
  const origin = new URL(targetUrl).origin;
  const server = headers.get("server") || "";

  for (const spec of DEFAULT_PAGE_SIGNATURES) {
    try {
      const { res, body } = await fetchTarget(`${origin}${spec.path}`, {
        followRedirects: false,
        timeout: 6000,
      });
      if (res.status < 200 || res.status >= 400) continue;
      const serverMatch = !spec.server || spec.server.test(server);
      if (spec.marker.test(body) && serverMatch) {
        findings.push({
          id: `default-${spec.title.replace(/\W/g, "-").toLowerCase()}`,
          severity: "medium",
          category: "default-pages",
          title: spec.title,
          description: "Default installation page indicates an unconfigured or freshly installed server.",
          evidence: `${origin}${spec.path} → HTTP ${res.status}`,
          remediation: "Replace default pages with your application; harden the server configuration.",
        });
      }
    } catch {
      /* skip */
    }
  }

  return findings;
}
