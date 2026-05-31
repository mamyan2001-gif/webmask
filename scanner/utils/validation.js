import { getApexDomain } from "./domain.js";

export const OPEN_REDIRECT_PROBE = {
  host: "evil-probe.example",
  origin: "https://evil-probe.example",
  path: "/redirect-test",
  url: "https://evil-probe.example/redirect-test",
};

export function parseHstsMaxAge(header) {
  if (!header) return 0;
  const match = String(header).match(/max-age=(\d+)/i);
  return match ? Number(match[1]) : 0;
}

export function hasEffectiveHsts(header) {
  return parseHstsMaxAge(header) > 0;
}

export function sameRegistrableDomain(hostA, hostB) {
  try {
    const a = getApexDomain(String(hostA).toLowerCase());
    const b = getApexDomain(String(hostB).toLowerCase());
    return a === b;
  } catch {
    return false;
  }
}

export function parseLocationUrl(location, baseUrl) {
  if (!location) return null;
  try {
    return new URL(location, baseUrl);
  } catch {
    return null;
  }
}

export function locationRedirectsToHost(location, baseUrl, targetHost) {
  const dest = parseLocationUrl(location, baseUrl);
  if (!dest) return false;
  return dest.hostname.toLowerCase() === targetHost.toLowerCase();
}

export function locationRedirectsToProbe(location, baseUrl) {
  const dest = parseLocationUrl(location, baseUrl);
  if (!dest) return false;
  return (
    dest.origin === OPEN_REDIRECT_PROBE.origin &&
    dest.pathname === OPEN_REDIRECT_PROBE.path
  );
}

export function chainUpgradesToHttps(chain) {
  return chain.some((hop) => {
    if (hop.url?.startsWith("https://")) return true;
    const dest = parseLocationUrl(hop.location, hop.url);
    return dest?.protocol === "https:";
  });
}

export function isHtmlResponse(body, contentType = "") {
  const ct = String(contentType).toLowerCase();
  if (ct.includes("text/html")) return true;
  const sample = String(body || "").slice(0, 800).trimStart();
  return /^<!DOCTYPE html/i.test(sample) || /^<html[\s>]/i.test(sample);
}

export function isGenericSpaOrHomepage(body) {
  if (!isHtmlResponse(body)) return false;
  if (body.length > 25000) return true;
  return /(<nav\b|<footer\b|<meta[^>]+name=["']viewport["'])/i.test(body);
}

function envFileValidator(body) {
  return /^[A-Z][A-Z0-9_]*\s*=\s*\S+/m.test(body) && !/<html/i.test(body);
}

function sqlDumpValidator(body) {
  return /(CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump)/i.test(body);
}

function adminLoginValidator(body) {
  return /(wp-admin|administrator\/index|name=["']password["']|type=["']password["'])/i.test(body);
}

const PATH_VALIDATORS = {
  "/.env": envFileValidator,
  "/.env.local": envFileValidator,
  "/.env.production": envFileValidator,
  "/.git/HEAD": (body) => /^ref: refs\//m.test(body.trim()),
  "/.git/config": (body) => /\[core\]/i.test(body) && /repositoryformatversion/i.test(body),
  "/.svn/entries": (body) => (/dir\n|\nsvn:/i.test(body) && !/<html/i.test(body)),
  "/.DS_Store": (body) => body.includes("Bud1") || /^[\x00-\x08]/.test(body),
  "/backup.sql": sqlDumpValidator,
  "/db.sql": sqlDumpValidator,
  "/dump.sql": sqlDumpValidator,
  "/wp-config.php": (body) => /define\s*\(\s*['"]DB_(NAME|USER|PASSWORD)['"]/i.test(body),
  "/wp-config.php.bak": (body) => /define\s*\(\s*['"]DB_(NAME|USER|PASSWORD)['"]/i.test(body),
  "/phpinfo.php": (body) => /phpinfo\(\)|PHP Version|Configuration/i.test(body) && /php/i.test(body),
  "/info.php": (body) => /phpinfo\(\)|PHP Version|Configuration/i.test(body) && /php/i.test(body),
  "/server-status": (body) => /Apache Server Status|Server Version/i.test(body),
  "/server-info": (body) => /Apache Server Information/i.test(body),
  "/.aws/credentials": (body) => /\[(?:default|profile [^\]]+)\]/i.test(body) && /aws_access_key_id/i.test(body),
  "/web.config": (body) => /<configuration[\s>]/i.test(body),
  "/config.json": (body) => {
    try {
      const data = JSON.parse(body);
      return data && typeof data === "object" && !Array.isArray(data);
    } catch {
      return false;
    }
  },
  "/config.yml": (body) => /^[a-z0-9_]+:\s*\S+/im.test(body) && !/<html/i.test(body),
  "/backup.zip": (body) => body.slice(0, 2) === "PK",
  "/phpmyadmin": (body) => /phpMyAdmin|pma_username/i.test(body),
  "/admin": adminLoginValidator,
  "/administrator": adminLoginValidator,
  "/cpanel": (body) => /cPanel|whm/i.test(body) && /login/i.test(body),
  "/crossdomain.xml": (body) => /<cross-domain-policy|<allow-access-from/i.test(body),
};

export function confirmsSensitiveExposure(path, body, contentType = "") {
  if (!body || !String(body).trim()) return false;

  const validator = PATH_VALIDATORS[path];
  if (validator) return validator(body);

  if (isHtmlResponse(body, contentType)) return false;
  if (isGenericSpaOrHomepage(body)) return false;
  return true;
}

export function confirmsApiExposure(body, contentType = "", marker) {
  if (!marker?.match.test(body)) return false;
  if (isHtmlResponse(body, contentType) || isGenericSpaOrHomepage(body)) return false;
  return true;
}

export function looksLikeJwt(value) {
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    return typeof header.alg === "string";
  } catch {
    return false;
  }
}

export function hostReflectedInBody(body, poisonHost) {
  if (!body || !poisonHost) return false;
  const escaped = poisonHost.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`https?://${escaped}(?:[:/]|["'])`, "i"),
    new RegExp(`//${escaped}(?:[:/]|["'])`, "i"),
    new RegExp(`["']${escaped}["']`, "i"),
  ];
  return patterns.some((pattern) => pattern.test(body));
}
