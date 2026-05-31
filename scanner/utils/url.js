import dns from "dns/promises";
import { URL } from "url";

const BLOCKED_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "[::1]",
  "metadata.google.internal",
]);

function isPrivateIp(ip) {
  if (ip.includes(":")) {
    const lower = ip.toLowerCase();
    if (lower === "::1" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
      return true;
    }
    const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return false;
  }
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

export function normalizeTargetUrl(input) {
  const raw = String(input || "").trim();
  if (!raw) throw new Error("Target URL is required");
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed;
  try {
    parsed = new URL(withProto);
  } catch {
    throw new Error("Invalid URL — use https://example.com");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http:// and https:// URLs are allowed");
  }
  if (parsed.username || parsed.password) {
    throw new Error("URLs with embedded credentials are not allowed");
  }
  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host) || host.endsWith(".local")) {
    throw new Error("Scanning local or internal hosts is not allowed");
  }
  return parsed.href.replace(/\/$/, "") || parsed.origin;
}

export async function assertSafeTarget(urlString) {
  const url = new URL(urlString);
  const host = url.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host)) {
    throw new Error("Target host is not allowed");
  }
  const addresses = await dns.resolve4(host).catch(() => []);
  const v6 = await dns.resolve6(host).catch(() => []);
  const all = [...addresses, ...v6];
  if (all.length === 0) throw new Error(`Could not resolve hostname: ${host}`);
  for (const ip of all) {
    if (isPrivateIp(ip)) {
      throw new Error("Target resolves to a private or internal IP address");
    }
  }
  return urlString;
}
