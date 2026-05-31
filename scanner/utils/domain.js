import dns from "dns/promises";

export function getApexDomain(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

export function isUnderApex(hostname, apex) {
  const host = hostname.toLowerCase();
  return host === apex || host.endsWith(`.${apex}`);
}

export function hostnameFromUrl(value) {
  try {
    const u = new URL(value.includes("://") ? value : `https://${value}`);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function resolveHostname(hostname) {
  try {
    const [a, aaaa] = await Promise.all([
      dns.resolve4(hostname).catch(() => []),
      dns.resolve6(hostname).catch(() => []),
    ]);
    return [...a, ...aaaa];
  } catch {
    return [];
  }
}

export async function isLiveHost(hostname) {
  const records = await resolveHostname(hostname);
  return records.length > 0;
}

export function extractHostnamesFromText(text, apex) {
  const found = new Set();
  if (!text) return found;

  const patterns = [
    /https?:\/\/([a-z0-9][a-z0-9.-]+\.[a-z]{2,})/gi,
    /(?:^|[\s"'`(=])((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,})/gi,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const raw = (match[1] || match[0]).toLowerCase().replace(/^[\s"'`(=]+/, "");
      const host = raw.split(/[/:?#]/)[0].split(":")[0];
      if (!host.includes(".") || host.endsWith(".png") || host.endsWith(".js")) continue;
      if (isUnderApex(host, apex) || host.includes(apex)) {
        found.add(host);
      }
    }
  }

  return found;
}
