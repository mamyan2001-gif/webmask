import { fetchTarget } from "../utils/http.js";

const LISTING_PATHS = [
  "/uploads/", "/upload/", "/files/", "/file/", "/backup/", "/backups/",
  "/static/", "/media/", "/images/", "/img/", "/assets/", "/data/",
  "/tmp/", "/temp/", "/logs/", "/log/",
];

const LISTING_MARKERS = [
  /Index of \//i,
  /Directory listing for/i,
  /Parent Directory/i,
  /<title>Index of/i,
  /\[To Parent Directory\]/i,
];

export async function checkDirectoryListing(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  for (const path of LISTING_PATHS) {
    const url = `${origin}${path}`;
    try {
      const { res, body } = await fetchTarget(url, { followRedirects: false, timeout: 8000 });
      if (res.status < 200 || res.status >= 400 || !body) continue;

      const marker = LISTING_MARKERS.find((m) => m.test(body));
      if (!marker) continue;

      const hasFileLinks = (body.match(/<a\b[^>]+href=["'][^"']+["']/gi) || []).length >= 3;
      if (!hasFileLinks) continue;

      findings.push({
        id: `listing-${path.replace(/\W/g, "-")}`,
        severity: "high",
        category: "listing",
        title: "Directory listing enabled",
        description: `Path ${path} exposes a browsable directory index.`,
        evidence: `${url} → HTTP ${res.status}, pattern: ${marker}`,
        remediation: "Disable directory indexes in the web server configuration.",
      });
    } catch {
      /* skip */
    }
  }

  return findings;
}

export async function checkSecurityTxt(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;
  const url = `${origin}/.well-known/security.txt`;

  try {
    const { res, body } = await fetchTarget(url, { followRedirects: true, timeout: 8000 });
    if (res.status < 200 || res.status >= 300 || !body.trim()) {
      findings.push({
        id: "security-txt-missing",
        severity: "info",
        category: "security-txt",
        title: "security.txt not published",
        description: "No security.txt file was found at /.well-known/security.txt.",
        evidence: `${url} → HTTP ${res.status}`,
        remediation: "Publish security.txt with Contact and Policy fields for responsible disclosure.",
      });
      return findings;
    }

    const lines = body.split("\n").map((l) => l.trim()).filter(Boolean);
    const fields = Object.fromEntries(
      lines
        .filter((l) => !l.startsWith("#") && l.includes(":"))
        .map((l) => {
          const idx = l.indexOf(":");
          return [l.slice(0, idx).toLowerCase(), l.slice(idx + 1).trim()];
        }),
    );

    findings.push({
      id: "security-txt-present",
      severity: "info",
      category: "security-txt",
      title: "security.txt published",
      description: "A security.txt file is available for responsible disclosure.",
      evidence: `${url} → HTTP ${res.status}`,
      remediation: "Keep Contact and Expires fields up to date.",
    });

    if (!fields.contact) {
      findings.push({
        id: "security-txt-no-contact",
        severity: "low",
        category: "security-txt",
        title: "security.txt missing Contact field",
        description: "RFC 9116 recommends a Contact field for reporting vulnerabilities.",
        evidence: "No Contact: line found",
        remediation: "Add Contact: mailto:security@example.com or a valid HTTPS URL.",
      });
    }

    if (fields.expires) {
      const expires = new Date(fields.expires);
      if (Number.isNaN(expires.getTime())) {
        findings.push({
          id: "security-txt-bad-expires",
          severity: "low",
          category: "security-txt",
          title: "security.txt Expires field invalid",
          description: "The Expires value could not be parsed as a date.",
          evidence: `Expires: ${fields.expires}`,
          remediation: "Use an ISO 8601 date, e.g. Expires: 2026-12-31T23:59:59Z",
        });
      } else if (expires < new Date()) {
        findings.push({
          id: "security-txt-expired",
          severity: "low",
          category: "security-txt",
          title: "security.txt has expired",
          description: "The Expires date is in the past.",
          evidence: `Expires: ${fields.expires}`,
          remediation: "Update security.txt and set a future Expires date.",
        });
      }
    } else {
      findings.push({
        id: "security-txt-no-expires",
        severity: "info",
        category: "security-txt",
        title: "security.txt missing Expires field",
        description: "An Expires field helps consumers know when to refresh the file.",
        evidence: "No Expires: line found",
        remediation: "Add Expires with a date within the next 12 months.",
      });
    }
  } catch {
    findings.push({
      id: "security-txt-unreachable",
      severity: "info",
      category: "security-txt",
      title: "security.txt unreachable",
      description: "Could not fetch /.well-known/security.txt.",
      evidence: url,
      remediation: "Publish security.txt if you accept external security reports.",
    });
  }

  return findings;
}
