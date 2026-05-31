import { fetchTarget } from "../utils/http.js";
import {
  getApexDomain,
  isUnderApex,
  isLiveHost,
  resolveHostname,
} from "../utils/domain.js";

const COMMON_SUBDOMAINS = [
  "www", "mail", "webmail", "smtp", "remote", "vpn", "api", "dev", "development",
  "staging", "stage", "test", "testing", "qa", "uat", "admin", "portal", "app",
  "cdn", "static", "assets", "media", "blog", "shop", "store", "m", "mobile",
  "internal", "intranet", "git", "gitlab", "jenkins", "ci", "beta", "demo",
  "auth", "login", "sso", "id", "oauth", "pay", "billing", "support", "help",
  "docs", "wiki", "status", "grafana", "kibana", "backup", "old", "legacy",
  "ns1", "ns2", "ftp", "secure", "panel", "cpanel", "whm", "mx", "imap",
];

const REVIEW_LABELS = new Set([
  "admin", "staging", "stage", "dev", "development", "test", "testing", "qa",
  "uat", "internal", "intranet", "jenkins", "gitlab", "grafana", "kibana",
  "backup", "cpanel", "whm", "panel", "vpn", "legacy", "old", "beta", "demo",
]);

async function fetchCrtShSubdomains(apex) {
  const url = `https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`;
  try {
    const { res, body } = await fetchTarget(url, { timeout: 20000 });
    if (!res.ok) return [];
    const entries = JSON.parse(body);
    const names = new Set();
    for (const entry of entries) {
      const value = entry?.name_value || "";
      for (const line of value.split("\n")) {
        const name = line.trim().toLowerCase().replace(/^\*\./, "");
        if (name && isUnderApex(name, apex) && name !== apex) {
          names.add(name);
        }
      }
    }
    return [...names];
  } catch {
    return [];
  }
}

async function probeDnsWordlist(apex, limit = 48) {
  const live = [];
  const batch = COMMON_SUBDOMAINS.slice(0, limit);

  await Promise.all(
    batch.map(async (label) => {
      const host = `${label}.${apex}`;
      if (await isLiveHost(host)) {
        live.push({ host, source: "dns-bruteforce", label });
      }
    }),
  );

  return live;
}

export async function checkSubdomains(targetUrl) {
  const findings = [];
  const apex = getApexDomain(new URL(targetUrl).hostname);
  const discovered = new Map();

  function add(host, source) {
    if (!isUnderApex(host, apex) || host === apex) return;
    if (!discovered.has(host)) {
      discovered.set(host, { host, source, live: true });
    }
  }

  const [crtHosts, dnsHosts] = await Promise.all([
    fetchCrtShSubdomains(apex),
    probeDnsWordlist(apex),
  ]);

  for (const host of crtHosts.slice(0, 40)) {
    if (await isLiveHost(host)) add(host, "certificate-transparency");
  }

  for (const entry of dnsHosts) {
    add(entry.host, entry.source);
  }

  const hosts = [...discovered.values()].sort((a, b) => a.host.localeCompare(b.host));

  if (hosts.length === 0) {
    findings.push({
      id: "subdomains-none",
      severity: "info",
      category: "subdomains",
      title: "No additional subdomains discovered",
      description: `DNS wordlist and certificate transparency produced no live hosts under ${apex}.`,
      evidence: `Apex: ${apex}`,
      remediation: "No action required.",
    });
    return { findings, subdomains: [] };
  }

  findings.push({
    id: "subdomains-discovered",
    severity: "info",
    category: "subdomains",
    title: `${hosts.length} subdomain(s) discovered`,
    description: "Live hosts found via DNS probing and certificate transparency logs.",
    evidence: hosts.map((h) => `${h.host} (${h.source})`).join(", "),
    remediation: "Review each subdomain for unintended exposure, default credentials, and missing patches.",
  });

  for (const entry of hosts) {
    const label = entry.host.split(".")[0];
    if (!REVIEW_LABELS.has(label)) continue;
    findings.push({
      id: `subdomain-review-${entry.host.replace(/\./g, "-")}`,
      severity: "info",
      category: "subdomains",
      title: `Review subdomain: ${entry.host}`,
      description: `The "${label}" label often indicates non-production or administrative infrastructure — verify access controls.`,
      evidence: `Source: ${entry.source}, resolves: ${(await resolveHostname(entry.host)).join(", ") || "unknown"}`,
      remediation: "Confirm the subdomain is intentional, patched, and not exposing internal tools publicly.",
    });
  }

  return { findings, subdomains: hosts };
}
