import dns from "dns/promises";
import { getApexDomain } from "../utils/domain.js";

export async function checkDnsSecurity(targetUrl) {
  const findings = [];
  const apex = getApexDomain(new URL(targetUrl).hostname);

  let hasDnssec = false;
  try {
    if (typeof dns.resolveDnskey === "function") {
      const keys = await dns.resolveDnskey(apex);
      hasDnssec = keys?.length > 0;
    }
  } catch {
    hasDnssec = false;
  }

  if (hasDnssec) {
    findings.push({
      id: "dns-dnssec-enabled",
      severity: "info",
      category: "dns-security",
      title: "DNSSEC enabled",
      description: "DNSKEY records were found for the apex domain.",
      evidence: `DNSKEY records at ${apex}`,
      remediation: "Monitor DNSSEC key rollovers and DS record updates at the registrar.",
    });
  } else {
    findings.push({
      id: "dns-dnssec-missing",
      severity: "info",
      category: "dns-security",
      title: "DNSSEC not detected",
      description: "No DNSKEY records were found — DNS responses are not cryptographically signed.",
      evidence: `No DNSKEY at ${apex}`,
      remediation: "Consider enabling DNSSEC at your DNS provider to prevent DNS spoofing.",
    });
  }

  try {
    const mx = await dns.resolveMx(apex);
    if (mx?.length) {
      findings.push({
        id: "dns-mx-present",
        severity: "info",
        category: "dns-security",
        title: "MX records configured",
        description: "Mail exchange records define where email for this domain is delivered.",
        evidence: mx.slice(0, 5).map((r) => `${r.exchange} (pri ${r.priority})`).join(", "),
        remediation: "Ensure MX hosts are patched and support TLS for mail transport.",
      });
    }
  } catch {
    findings.push({
      id: "dns-no-mx",
      severity: "info",
      category: "dns-security",
      title: "No MX records",
      description: "This domain does not appear to receive email directly.",
      evidence: `No MX at ${apex}`,
      remediation: "No action required if the domain is web-only.",
    });
  }

  try {
    const txt = await dns.resolveTxt(apex);
    const flat = txt.map((parts) => parts.join("")).join(" ");
    if (/google-site-verification|facebook-domain-verification|v=spf1/i.test(flat)) {
      findings.push({
        id: "dns-txt-verification",
        severity: "info",
        category: "dns-security",
        title: "Domain verification TXT records",
        description: "TXT records used for search console or third-party domain verification were found.",
        evidence: flat.slice(0, 120),
        remediation: "Remove verification records for services you no longer use.",
      });
    }
  } catch {
    /* skip */
  }

  return findings;
}
