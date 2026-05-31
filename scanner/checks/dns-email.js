import dns from "dns/promises";
import { getApexDomain } from "../utils/domain.js";

async function resolveTxt(name) {
  try {
    const records = await dns.resolveTxt(name);
    return records.map((parts) => parts.join("")).join(" ");
  } catch {
    return null;
  }
}

export async function checkDnsEmail(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  const apex = getApexDomain(url.hostname);

  const spf = await resolveTxt(apex);
  if (!spf) {
    findings.push({
      id: "dns-no-spf",
      severity: "medium",
      category: "dns",
      title: "No SPF record found",
      description: "Missing SPF allows attackers to spoof email from this domain.",
      evidence: `No TXT SPF record at ${apex}`,
      remediation: `Publish a TXT record: v=spf1 … -all (tune for your mail providers).`,
    });
  } else if (!/v=spf1/i.test(spf)) {
    findings.push({
      id: "dns-spf-malformed",
      severity: "low",
      category: "dns",
      title: "SPF record may be malformed",
      description: "TXT record at apex does not look like a valid SPF policy.",
      evidence: spf.slice(0, 160),
      remediation: "Ensure SPF starts with v=spf1 and ends with -all or ~all.",
    });
  } else if (/\+all|\?all/i.test(spf)) {
    findings.push({
      id: "dns-spf-permissive",
      severity: "medium",
      category: "dns",
      title: "Permissive SPF policy",
      description: "SPF uses +all or ?all, which does not strongly restrict senders.",
      evidence: spf.slice(0, 160),
      remediation: "Use -all (hard fail) or ~all (soft fail) after listing authorized senders.",
    });
  } else {
    findings.push({
      id: "dns-spf-present",
      severity: "info",
      category: "dns",
      title: "SPF record configured",
      description: "Sender Policy Framework record found at apex domain.",
      evidence: spf.slice(0, 160),
      remediation: "Review SPF includes periodically when adding mail services.",
    });
  }

  const dmarc = await resolveTxt(`_dmarc.${apex}`);
  if (!dmarc) {
    findings.push({
      id: "dns-no-dmarc",
      severity: "medium",
      category: "dns",
      title: "No DMARC record found",
      description: "Without DMARC, spoofed email is harder to detect and reject.",
      evidence: `No TXT at _dmarc.${apex}`,
      remediation: "Publish _dmarc TXT: v=DMARC1; p=reject or p=quarantine; rua=mailto:…",
    });
  } else if (/p=none/i.test(dmarc)) {
    findings.push({
      id: "dns-dmarc-none",
      severity: "low",
      category: "dns",
      title: "DMARC policy set to none",
      description: "DMARC is in monitoring-only mode and does not block spoofed mail.",
      evidence: dmarc.slice(0, 160),
      remediation: "Move toward p=quarantine or p=reject after reviewing aggregate reports.",
    });
  } else {
    findings.push({
      id: "dns-dmarc-present",
      severity: "info",
      category: "dns",
      title: "DMARC record configured",
      description: "Domain-based Message Authentication policy is published.",
      evidence: dmarc.slice(0, 160),
      remediation: "Monitor rua/ruf reports and tighten policy over time.",
    });
  }

  const dkimSelectors = ["default", "google", "selector1", "selector2", "k1", "s1"];
  let dkimFound = false;
  for (const sel of dkimSelectors) {
    const record = await resolveTxt(`${sel}._domainkey.${apex}`);
    if (record && /v=DKIM1/i.test(record)) {
      dkimFound = true;
      findings.push({
        id: `dns-dkim-${sel}`,
        severity: "info",
        category: "dns",
        title: "DKIM record found",
        description: `DKIM public key published for selector "${sel}".`,
        evidence: record.slice(0, 120),
        remediation: "Rotate DKIM keys on a regular schedule.",
      });
      break;
    }
  }
  if (!dkimFound) {
    findings.push({
      id: "dns-no-dkim",
      severity: "low",
      category: "dns",
      title: "No common DKIM selectors found",
      description: "Could not find DKIM at common selector names (may use custom selectors).",
      evidence: `Checked: ${dkimSelectors.map((s) => `${s}._domainkey.${apex}`).join(", ")}`,
      remediation: "Publish DKIM if you send transactional or marketing email from this domain.",
    });
  }

  try {
    const caa = await dns.resolveCaa(apex);
    if (caa?.length) {
      findings.push({
        id: "dns-caa-present",
        severity: "info",
        category: "dns",
        title: "CAA records configured",
        description: "Certificate Authority Authorization restricts who may issue TLS certs.",
        evidence: caa.map((r) => `${r.critical ? "!" : ""}${r.issue || r.issuewild || r.iodef}`).join(", "),
        remediation: "Keep CAA aligned with your certificate provider.",
      });
    } else {
      findings.push({
        id: "dns-no-caa",
        severity: "low",
        category: "dns",
        title: "No CAA records",
        description: "Any public CA can issue certificates for this domain.",
        evidence: `No CAA at ${apex}`,
        remediation: "Add CAA records listing only your authorized certificate authorities.",
      });
    }
  } catch {
    findings.push({
      id: "dns-no-caa",
      severity: "low",
      category: "dns",
      title: "No CAA records",
      description: "Any public CA can issue certificates for this domain.",
      evidence: `No CAA at ${apex}`,
      remediation: "Add CAA records listing only your authorized certificate authorities.",
    });
  }

  return findings;
}
