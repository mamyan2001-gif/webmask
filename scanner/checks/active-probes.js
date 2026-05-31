import { fetchTarget } from "../utils/http.js";
import { buildOastCallbackUrl } from "../utils/oast.js";
import { isGenericSpaOrHomepage } from "../utils/validation.js";
import { analyzeProbeResponse, wafRateLimitFinding } from "../utils/probe-response.js";

const SQLI_PAYLOADS = ["'", "1' OR '1'='1", "' OR 1=1--", "1; SELECT 1--"];
const XSS_PAYLOAD = "sfcanary7x";
const LFI_PAYLOADS = ["../../../etc/passwd", "..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd"];
const SSTI_PAYLOADS = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"];

const SQLI_ERRORS = [
  /SQL syntax.*MySQL/i,
  /mysql_fetch/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLite3::/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
];

function buildProbeUrl(base, param, value) {
  const url = new URL(base);
  url.searchParams.set(param, value);
  return url.href;
}

function finding(base) {
  return { ...base, category: "active" };
}

async function sendProbe(fetchFn, target, param, value) {
  const method = (target.method || "get").toLowerCase();
  const base = target.baseUrl || target.pageUrl;

  if (method === "post" && target.formInputs?.length) {
    const body = new URLSearchParams();
    for (const input of target.formInputs) {
      if (!input.name) continue;
      body.set(input.name, input.name === param ? value : (input.value || "test"));
    }
    return fetchFn(base, {
      method: "POST",
      body: body.toString(),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      followRedirects: true,
      timeout: 8000,
    });
  }

  return fetchFn(buildProbeUrl(base, param, value), { followRedirects: true, timeout: 8000 });
}

export async function checkActiveProbes(attackSurface, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const params = attackSurface.params || [];
  const forms = attackSurface.forms || [];
  const tested = new Set();
  const maxProbes = options.maxProbes || 48;
  const oastBaseUrl = options.oastBaseUrl || "";
  const oastToken = options.oastToken || "";
  let probeCount = 0;
  const blockStats = { totalProbes: 0, inconclusive: 0, rateLimited: 0, wafBlocked: 0 };

  const paramTargets = [...params];
  for (const form of forms.slice(0, 10)) {
    for (const input of form.inputs.slice(0, 4)) {
      paramTargets.push({
        pageUrl: form.pageUrl,
        name: input.name,
        baseUrl: form.action,
        method: form.method,
        formInputs: form.inputs,
      });
    }
  }

  function trackResponse(res, body) {
    blockStats.totalProbes += 1;
    const analysis = analyzeProbeResponse(res, body);
    if (analysis.rateLimited) blockStats.rateLimited += 1;
    if (analysis.wafBlocked) blockStats.wafBlocked += 1;
    if (analysis.inconclusive) blockStats.inconclusive += 1;
    return analysis;
  }

  for (const target of paramTargets) {
    if (probeCount >= maxProbes) break;
    const key = `${target.method || "get"}|${target.baseUrl}|${target.name}`;
    if (tested.has(key)) continue;
    tested.add(key);

    probeCount += 1;
    try {
      const xssPayload = oastToken && oastBaseUrl
        ? `<script src="${oastBaseUrl}/oast/${oastToken}?xss=1"></script>`
        : XSS_PAYLOAD;
      const { res, body } = await sendProbe(fetchFn, target, target.name, xssPayload);
      trackResponse(res, body);
      if (body.includes(XSS_PAYLOAD) && !body.includes(encodeURIComponent(XSS_PAYLOAD))) {
        const dangerous = /<script[^>]*sfcanary7x|on\w+\s*=[^>]*sfcanary7x/i.test(body);
        findings.push(finding({
          id: `active-xss-${target.name}-${probeCount}`,
          severity: dangerous ? "high" : "medium",
          title: dangerous ? "Reflected XSS (active probe)" : "Input reflected (active probe)",
          description: `${(target.method || "GET").toUpperCase()} param "${target.name}" reflects XSS canary.`,
          evidence: `${target.method || "GET"} ${target.baseUrl || target.pageUrl}`,
          remediation: "Encode all user input in HTML context; use CSP as defense in depth.",
          pageUrl: target.pageUrl,
        }));
      }
    } catch {
      /* skip */
    }

    for (const payload of SQLI_PAYLOADS.slice(0, 2)) {
      if (probeCount >= maxProbes) break;
      probeCount += 1;
      try {
        const { res, body } = await sendProbe(fetchFn, target, target.name, payload);
        const analysis = trackResponse(res, body);
        if (analysis.inconclusive) continue;
        if (isGenericSpaOrHomepage(body)) continue;
        if (SQLI_ERRORS.some((p) => p.test(body))) {
          findings.push(finding({
            id: `active-sqli-${target.name}-${probeCount}`,
            severity: "high",
            title: "SQL injection error (active probe)",
            description: `${(target.method || "GET").toUpperCase()} field "${target.name}" triggered DB error.`,
            evidence: `${target.method || "GET"} ${target.baseUrl || target.pageUrl}`,
            remediation: "Use parameterized queries; never concatenate user input into SQL.",
            pageUrl: target.pageUrl,
          }));
          break;
        }
      } catch {
        /* skip */
      }
    }

    if (/file|path|page|doc|template|include|folder|dir/i.test(target.name)) {
      if (probeCount >= maxProbes) continue;
      probeCount += 1;
      try {
        const { res, body } = await sendProbe(fetchFn, target, target.name, LFI_PAYLOADS[0]);
        trackResponse(res, body);
        if (/root:x:0:0:|\/bin\/bash/i.test(body)) {
          findings.push(finding({
            id: `active-lfi-${target.name}`,
            severity: "critical",
            title: "Local file inclusion (active probe)",
            description: `/etc/passwd content via "${target.name}".`,
            evidence: `${target.method || "GET"} ${target.baseUrl || target.pageUrl}`,
            remediation: "Validate and allowlist file paths.",
            pageUrl: target.pageUrl,
          }));
        }
      } catch {
        /* skip */
      }
    }

    if (probeCount >= maxProbes) continue;
    probeCount += 1;
    try {
      const { res, body } = await sendProbe(fetchFn, target, target.name, SSTI_PAYLOADS[0]);
      trackResponse(res, body);
      if (/\b49\b/.test(body) && !body.includes("7*7")) {
        findings.push(finding({
          id: `active-ssti-${target.name}-${probeCount}`,
          severity: "high",
          title: "Possible server-side template injection",
          description: `Template expression may have evaluated for "${target.name}".`,
          evidence: `${target.method || "GET"} ${target.baseUrl || target.pageUrl}`,
          remediation: "Never embed user input in server-side templates.",
          pageUrl: target.pageUrl,
        }));
      }
    } catch {
      /* skip */
    }

    if (
      oastBaseUrl
      && oastToken
      && /url|uri|link|href|redirect|callback|webhook|target|dest|return|next|continue|fetch|api|endpoint|proxy|site|src/i.test(target.name)
    ) {
      if (probeCount >= maxProbes) continue;
      probeCount += 1;
      try {
        const callback = buildOastCallbackUrl(oastBaseUrl, oastToken, { probe: "ssrf", param: target.name });
        const { res, body } = await sendProbe(fetchFn, target, target.name, callback);
        trackResponse(res, body);
      } catch {
        /* skip */
      }
    }
  }

  const wafFinding = wafRateLimitFinding(blockStats);
  if (wafFinding) findings.push(wafFinding);

  if (findings.filter((f) => f.severity !== "info").length === 0 && paramTargets.length > 0) {
    findings.push({
      id: "active-clean",
      severity: "info",
      category: "active",
      title: "Active probes completed",
      description: `${probeCount} probes (${forms.length} forms incl. POST) across ${tested.size} target(s).`,
      evidence: `Parameters tested: ${tested.size}`,
      remediation: "Continue testing authenticated routes separately.",
    });
  }

  return { findings, probesSent: probeCount, parametersTested: tested.size, blockStats };
}
