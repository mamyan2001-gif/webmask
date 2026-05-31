import tls from "tls";

function probeTls(host, port, options) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 8000,
        ...options,
      },
      () => {
        const result = {
          protocol: socket.getProtocol?.() || null,
          cipher: socket.getCipher?.() || null,
        };
        socket.end();
        resolve(result);
      },
    );
    socket.on("error", () => resolve(null));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(null);
    });
  });
}

const WEAK_CIPHER_PATTERNS = [
  /NULL/i,
  /EXPORT/i,
  /RC4/i,
  /DES(?!CBC3)/i,
  /3DES/i,
  /MD5/i,
  /anon/i,
];

export async function checkTlsAdvanced(targetUrl) {
  const findings = [];
  const url = new URL(targetUrl);
  if (url.protocol !== "https:") return findings;

  const host = url.hostname;
  const port = Number(url.port) || 443;

  const legacyVersions = [
    { min: "TLSv1", max: "TLSv1", id: "tls10", label: "TLS 1.0" },
    { min: "TLSv1.1", max: "TLSv1.1", id: "tls11", label: "TLS 1.1" },
  ];

  for (const version of legacyVersions) {
    const result = await probeTls(host, port, {
      minVersion: version.min,
      maxVersion: version.max,
    });
    if (result?.protocol) {
      findings.push({
        id: `tls-legacy-${version.id}`,
        severity: "high",
        category: "tls",
        title: `${version.label} still enabled`,
        description: `${version.label} is deprecated and vulnerable to known attacks (POODLE, BEAST, etc.).`,
        evidence: `Negotiated ${result.protocol} with cipher ${result.cipher?.name || "unknown"}`,
        remediation: `Disable ${version.label} on the load balancer or web server; require TLS 1.2+.`,
      });
    }
  }

  const modern = await probeTls(host, port, { minVersion: "TLSv1.2" });
  if (modern?.cipher?.name) {
    const cipherName = modern.cipher.name;
    if (WEAK_CIPHER_PATTERNS.some((p) => p.test(cipherName))) {
      findings.push({
        id: "tls-weak-cipher",
        severity: "high",
        category: "tls",
        title: "Weak TLS cipher negotiated",
        description: "The server negotiated a cipher suite considered cryptographically weak.",
        evidence: `Cipher: ${cipherName}, protocol: ${modern.protocol}`,
        remediation: "Configure the server to prefer AEAD ciphers (AES-GCM, ChaCha20) and disable legacy suites.",
      });
    } else {
      findings.push({
        id: "tls-cipher-info",
        severity: "info",
        category: "tls",
        title: "TLS cipher suite",
        description: "Modern TLS connection details captured.",
        evidence: `${modern.protocol} / ${cipherName}`,
        remediation: "Review cipher order periodically against current best practices.",
      });
    }
  }

  return findings;
}
