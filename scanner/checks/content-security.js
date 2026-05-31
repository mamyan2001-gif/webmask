import { looksLikeJwt } from "../utils/validation.js";

const SECRET_PATTERNS = [
  {
    id: "aws-key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
    title: "Possible AWS access key in page source",
    validate: (match) => match.length === 20,
  },
  {
    id: "github-token",
    pattern: /ghp_[a-zA-Z0-9]{36,}/g,
    severity: "critical",
    title: "Possible GitHub personal access token in page source",
  },
  {
    id: "slack-token",
    pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
    severity: "critical",
    title: "Possible Slack token in page source",
  },
  {
    id: "generic-api-key",
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/gi,
    severity: "high",
    title: "Possible API key assignment in page source",
  },
  {
    id: "private-key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    title: "Private key material in page source",
  },
];

function maskMatch(value) {
  if (value.length <= 12) return `${value.slice(0, 4)}…`;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function extractJwtCandidates(html) {
  const candidates = new Set();
  const quoted = html.match(/['"](eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)['"]/g) || [];
  for (const raw of quoted) {
    candidates.add(raw.slice(1, -1));
  }
  return [...candidates];
}

export function checkContentSecurity(targetUrl, body, headers) {
  const findings = [];
  const url = new URL(targetUrl);
  const isHttps = url.protocol === "https:";
  const html = body || "";
  const targetHost = url.hostname;

  if (isHttps) {
    const mixed = [...html.matchAll(/(?:src|href|action)\s*=\s*["']http:\/\/([^"']+)["']/gi)]
      .map((m) => m[1])
      .filter((value) => {
        const host = value.split("/")[0].toLowerCase();
        return !["localhost", "127.0.0.1"].includes(host) && !value.startsWith("//");
      });
    if (mixed.length > 0) {
      findings.push({
        id: "mixed-content",
        severity: "medium",
        category: "content",
        title: "Mixed content references detected",
        description: "HTTPS page loads or links to insecure HTTP resources.",
        evidence: mixed.slice(0, 5).map((v) => `http://${v}`).join("\n"),
        remediation: "Serve all assets over HTTPS; use protocol-relative URLs or upgrade-insecure-requests.",
      });
    }
  }

  const externalScripts = [...html.matchAll(/<script[^>]+src\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi)]
    .filter((m) => {
      try {
        return new URL(m[1]).hostname !== targetHost;
      } catch {
        return true;
      }
    });
  const missingSri = externalScripts.filter((m) => !/\bintegrity=["'][^"']+["']/i.test(m[0]));
  if (missingSri.length >= 3) {
    findings.push({
      id: "missing-sri",
      severity: "low",
      category: "content",
      title: "External scripts without Subresource Integrity",
      description: "Multiple third-party scripts lack SRI and could be tampered with at the CDN.",
      evidence: missingSri.slice(0, 5).map((m) => m[1]).join("\n"),
      remediation: "Add integrity and crossorigin attributes to external script tags.",
    });
  }

  const passwordOnHttp =
    !isHttps && /<input[^>]+type\s*=\s*["']password["']/i.test(html);
  if (passwordOnHttp) {
    findings.push({
      id: "password-form-http",
      severity: "critical",
      category: "content",
      title: "Password field on non-HTTPS page",
      description: "Credentials may be transmitted in cleartext.",
      evidence: "Password input detected on HTTP URL",
      remediation: "Serve login forms exclusively over HTTPS.",
    });
  }

  for (const spec of SECRET_PATTERNS) {
    spec.pattern.lastIndex = 0;
    const matches = [...html.matchAll(spec.pattern)]
      .map((m) => m[0])
      .filter((match) => !spec.validate || spec.validate(match));
    if (matches.length > 0) {
      findings.push({
        id: `secret-${spec.id}`,
        severity: spec.severity,
        category: "content",
        title: spec.title,
        description: "Sensitive-looking material was found in the HTML or inline scripts.",
        evidence: matches.slice(0, 3).map(maskMatch).join(", "),
        remediation: "Remove secrets from client-side code; rotate any exposed credentials immediately.",
      });
    }
  }

  const jwtMatches = extractJwtCandidates(html).filter(looksLikeJwt);
  if (jwtMatches.length > 0) {
    findings.push({
      id: "secret-jwt",
      severity: "medium",
      category: "content",
      title: "JWT token in page source",
      description: "A JSON Web Token with a valid header was found embedded in page markup.",
      evidence: jwtMatches.slice(0, 2).map(maskMatch).join(", "),
      remediation: "Do not expose session or API tokens in HTML; store them in HttpOnly cookies or memory.",
    });
  }

  const csp = headers.get("content-security-policy") || "";
  if (csp && (/\bunsafe-inline\b/i.test(csp) || /\bunsafe-eval\b/i.test(csp))) {
    findings.push({
      id: "csp-unsafe-directives",
      severity: "medium",
      category: "content",
      title: "CSP allows unsafe directives",
      description: "Content-Security-Policy includes unsafe-inline or unsafe-eval, weakening XSS defenses.",
      evidence: csp.slice(0, 200),
      remediation: "Replace unsafe-inline/eval with nonces or hashes; avoid eval in application code.",
    });
  }

  return findings;
}
