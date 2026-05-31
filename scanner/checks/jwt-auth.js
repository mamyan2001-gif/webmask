import { fetchTarget } from "../utils/http.js";

function decodePart(part) {
  try {
    const json = Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function parseJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const header = decodePart(parts[0]);
  const payload = decodePart(parts[1]);
  if (!header || !payload) return null;
  return { header, payload, segments: parts };
}

function buildNoneAlgToken(original) {
  const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  return `${header}.${original.segments[1]}.`;
}

export async function checkJwtAuth(targetUrl, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const origin = new URL(targetUrl).origin;
  const authHeader = options.authHeaders?.Authorization || options.bearerToken || "";
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();

  const probePaths = ["/api/me", "/api/user", "/api/profile", "/api/v1/user", "/user", "/auth/me"];

  if (token && token.includes(".")) {
    const jwt = parseJwt(token);
    if (!jwt) {
      findings.push({
        id: "jwt-malformed",
        severity: "low",
        category: "auth",
        title: "Malformed JWT in Authorization header",
        description: "Bearer token does not decode as a valid JWT.",
        evidence: "Authorization: Bearer [malformed]",
        remediation: "Use well-formed JWTs with valid header and payload segments.",
      });
      return findings;
    }

    if (jwt.header.alg && jwt.header.alg.toLowerCase() === "none") {
      findings.push({
        id: "jwt-alg-none-header",
        severity: "critical",
        category: "auth",
        title: "JWT uses alg=none",
        description: "Token header declares no signature algorithm.",
        evidence: `alg: ${jwt.header.alg}`,
        remediation: "Reject alg=none tokens server-side; use HS256/RS256.",
      });
    }

    if (jwt.payload.exp && jwt.payload.exp * 1000 < Date.now()) {
      findings.push({
        id: "jwt-expired",
        severity: "medium",
        category: "auth",
        title: "JWT is expired",
        description: "Configured Bearer token exp claim is in the past.",
        evidence: `exp: ${new Date(jwt.payload.exp * 1000).toISOString()}`,
        remediation: "Refresh tokens before scanning authenticated routes.",
      });
    }

    if (!jwt.payload.exp) {
      findings.push({
        id: "jwt-no-exp",
        severity: "low",
        category: "auth",
        title: "JWT missing exp claim",
        description: "Token has no expiration — long-lived session risk.",
        evidence: `sub: ${jwt.payload.sub || "unknown"}`,
        remediation: "Add exp and rotate tokens regularly.",
      });
    }

    const noneToken = buildNoneAlgToken(jwt);
    for (const path of probePaths.slice(0, 3)) {
      try {
        const { res, body } = await fetchFn(`${origin}${path}`, {
          headers: { Authorization: `Bearer ${noneToken}` },
          followRedirects: false,
          timeout: 8000,
        });
        if (res.status >= 200 && res.status < 300 && !/"error"|unauthorized|invalid token/i.test(body)) {
          findings.push({
            id: "jwt-alg-none-accepted",
            severity: "critical",
            category: "auth",
            title: "Server accepts JWT with alg=none",
            description: `Endpoint ${path} accepted an unsigned JWT variant.`,
            evidence: `${path} → HTTP ${res.status}`,
            remediation: "Explicitly deny alg=none and verify signatures.",
          });
          break;
        }
      } catch {
        /* skip */
      }
    }
  } else if (authHeader) {
    findings.push({
      id: "jwt-bearer-opaque",
      severity: "info",
      category: "auth",
      title: "Opaque Bearer token configured",
      description: "Authorization header is not a JWT — skipping JWT-specific tests.",
      evidence: "Non-JWT Bearer token",
      remediation: "No action for opaque tokens.",
    });
  }

  return findings;
}
