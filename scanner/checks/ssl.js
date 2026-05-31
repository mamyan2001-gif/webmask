import tls from "tls";

export async function checkSsl(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  if (url.protocol !== "https:") {
    findings.push({
      id: "ssl-no-https",
      severity: "high",
      category: "ssl",
      title: "Site not served over HTTPS",
      description: "The target URL uses plain HTTP. Traffic and credentials may be intercepted.",
      evidence: `Protocol: ${url.protocol}`,
      remediation: "Enable TLS/HTTPS and redirect all HTTP traffic to HTTPS.",
    });
    return findings;
  }

  const host = url.hostname;
  const port = url.port || 443;

  const certInfo = await new Promise((resolve) => {
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 10000 },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve(cert);
      },
    );
    socket.on("error", () => resolve(null));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });

  if (!certInfo || !certInfo.valid_to) {
    findings.push({
      id: "ssl-handshake-failed",
      severity: "high",
      category: "ssl",
      title: "TLS handshake failed",
      description: "Could not retrieve a certificate from the server.",
      evidence: `${host}:${port}`,
      remediation: "Verify TLS is configured correctly on the server.",
    });
    return findings;
  }

  const expires = new Date(certInfo.valid_to);
  const daysLeft = Math.floor((expires - Date.now()) / (1000 * 60 * 60 * 24));

  if (daysLeft < 0) {
    findings.push({
      id: "ssl-expired",
      severity: "critical",
      category: "ssl",
      title: "TLS certificate expired",
      description: "The server certificate is past its expiration date.",
      evidence: `Expired: ${certInfo.valid_to}`,
      remediation: "Renew the TLS certificate immediately.",
    });
  } else if (daysLeft < 14) {
    findings.push({
      id: "ssl-expiring-soon",
      severity: "medium",
      category: "ssl",
      title: "TLS certificate expiring soon",
      description: `Certificate expires in ${daysLeft} day(s).`,
      evidence: `Valid until: ${certInfo.valid_to}`,
      remediation: "Renew the certificate before it expires.",
    });
  }

  if (certInfo.subject?.CN || certInfo.subjectaltname) {
    const altNames = String(certInfo.subjectaltname || "")
      .split(", ")
      .filter((entry) => entry.startsWith("DNS:"))
      .map((entry) => entry.slice(4).toLowerCase());
    const cn = certInfo.subject?.CN?.toLowerCase() || "";
    const coversHost =
      cn === host ||
      altNames.includes(host) ||
      (cn.startsWith("*.") && host.endsWith(cn.slice(2))) ||
      altNames.some((name) => name.startsWith("*.") && host.endsWith(name.slice(2)));

    if (!coversHost) {
      findings.push({
        id: "ssl-name-mismatch",
        severity: "high",
        category: "ssl",
        title: "Certificate hostname mismatch",
        description: "The certificate may not match the requested hostname.",
        evidence: `CN: ${certInfo.subject?.CN || "n/a"}, SAN: ${altNames.join(", ") || "none"}, requested: ${host}`,
        remediation: "Issue a certificate that includes the correct hostname in CN or SAN.",
      });
    }
  }

  if (certInfo.issuer?.O) {
    findings.push({
      id: "ssl-cert-info",
      severity: "info",
      category: "ssl",
      title: "TLS certificate present",
      description: "A valid TLS certificate was retrieved.",
      evidence: `Issuer: ${certInfo.issuer.O}, expires: ${certInfo.valid_to}`,
      remediation: "No action required.",
    });
  }

  return findings;
}
