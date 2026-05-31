import { fetchTarget } from "../utils/http.js";

export async function checkCors(targetUrl) {
  const findings = [];
  const origin = "https://evil-probe.example";

  try {
    const { res } = await fetchTarget(targetUrl, {
      headers: { Origin: origin },
      followRedirects: false,
    });

    const acao = res.headers.get("access-control-allow-origin");
    const acac = res.headers.get("access-control-allow-credentials");

    if (!acao) return findings;

    if (acao === "*") {
      findings.push({
        id: "cors-wildcard",
        severity: "medium",
        category: "cors",
        title: "CORS allows any origin (*)",
        description: "Access-Control-Allow-Origin: * permits any site to read responses.",
        evidence: "Access-Control-Allow-Origin: *",
        remediation: "Restrict CORS to trusted origins instead of wildcard.",
      });
    } else if (acao === origin) {
      findings.push({
        id: "cors-reflects-origin",
        severity: "high",
        category: "cors",
        title: "CORS reflects arbitrary Origin",
        description: "The server echoes the request Origin header, which may allow cross-origin data theft.",
        evidence: `Access-Control-Allow-Origin: ${acao}`,
        remediation: "Validate Origin against an allowlist; never reflect untrusted origins.",
      });
    }

    if (acac?.toLowerCase() === "true" && acao && acao !== "null" && acao !== "*") {
      findings.push({
        id: "cors-credentials",
        severity: "medium",
        category: "cors",
        title: "CORS allows credentials with reflected or broad origin",
        description: "Access-Control-Allow-Credentials is true — ensure origins are strictly controlled.",
        evidence: `Allow-Origin: ${acao}, Allow-Credentials: true`,
        remediation: "Only enable credentials with a strict origin allowlist.",
      });
    }
  } catch {
    /* non-fatal */
  }

  return findings;
}
