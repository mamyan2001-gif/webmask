import tls from "tls";

export async function checkTlsChain(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  if (url.protocol !== "https:") return findings;

  const host = url.hostname;
  const port = Number(url.port) || 443;

  const chain = await new Promise((resolve) => {
    const certs = [];
    const socket = tls.connect(
      { host, port, servername: host, rejectUnauthorized: false, timeout: 10000 },
      () => {
        try {
          const peer = socket.getPeerCertificate(true);
          let cert = peer;
          const seen = new Set();
          let depth = 0;
          while (cert && cert.raw && depth < 8) {
            if (seen.has(cert.fingerprint)) break;
            seen.add(cert.fingerprint);
            certs.push(cert);
            cert = cert.issuerCertificate;
            if (!cert || cert === peer) break;
            depth += 1;
          }
        } catch {
          /* ignore */
        }
        socket.end();
        resolve(certs);
      },
    );
    socket.on("error", () => resolve([]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([]);
    });
  });

  if (chain.length === 0) return findings;

  if (chain.length === 1) {
    findings.push({
      id: "tls-incomplete-chain",
      severity: "medium",
      category: "tls-chain",
      title: "Incomplete TLS certificate chain",
      description: "Only the leaf certificate was retrieved — intermediate certificates may be missing.",
      evidence: `1 certificate received for ${host}`,
      remediation: "Install the full certificate chain on the server to avoid client trust warnings.",
    });
  } else {
    findings.push({
      id: "tls-chain-present",
      severity: "info",
      category: "tls-chain",
      title: "TLS certificate chain retrieved",
      description: `${chain.length} certificate(s) in chain.`,
      evidence: chain.map((c) => c.subject?.CN || "unknown").join(" → "),
      remediation: "Verify chain is complete up to a trusted root.",
    });
  }

  const leaf = chain[0];
  if (leaf?.issuer?.O && leaf?.subject?.O && leaf.issuer.O === leaf.subject.O) {
    findings.push({
      id: "tls-self-signed",
      severity: "high",
      category: "tls-chain",
      title: "Self-signed TLS certificate",
      description: "Leaf certificate issuer matches subject — likely self-signed.",
      evidence: `Subject/O: ${leaf.subject.O}`,
      remediation: "Use a certificate from a trusted public CA.",
    });
  }

  return findings;
}
