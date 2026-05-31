import { fetchTarget } from "../utils/http.js";
import { analyzeProbeResponse } from "../utils/probe-response.js";

const ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"];

async function gqlPost(fetchFn, url, body, headers = {}) {
  return fetchFn(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
    followRedirects: false,
    timeout: 9000,
  });
}

export async function checkGraphqlFuzz(targetUrl, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const origin = new URL(targetUrl).origin;
  let endpoint = null;
  let blocked = 0;

  for (const path of ENDPOINTS) {
    const url = `${origin}${path}`;
    try {
      const { res, body } = await gqlPost(fetchFn, url, { query: "{ __typename }" });
      if (res.status >= 200 && res.status < 400 && /"data"|__typename/i.test(body)) {
        endpoint = url;
        break;
      }
    } catch {
      /* skip */
    }
  }

  if (!endpoint) {
    return { findings, endpoint: null, probesSent: 0 };
  }

  let probesSent = 0;

  // SQLi-style injection in query argument
  probesSent += 1;
  try {
    const { res, body } = await gqlPost(fetchFn, endpoint, {
      query: 'query { __schema { queryType { name(arg: "webmask\' OR 1=1--") } } }',
    });
    const analysis = analyzeProbeResponse(res, body);
    if (analysis.inconclusive) blocked += 1;
    if (/SQL syntax|mysql|ORA-|PostgreSQL/i.test(body)) {
      findings.push({
        id: "graphql-sqli",
        severity: "high",
        category: "graphql",
        title: "GraphQL SQL error on injected query",
        description: "Database error triggered via GraphQL query injection.",
        evidence: endpoint,
        remediation: "Use parameterized queries; validate GraphQL inputs.",
      });
    }
  } catch {
    /* skip */
  }

  // Batch / alias abuse
  probesSent += 1;
  try {
    const aliases = Array.from({ length: 25 }, (_, i) => `a${i}: __typename`).join(" ");
    const { res, body } = await gqlPost(fetchFn, endpoint, {
      query: `query { ${aliases} }`,
    });
    const analysis = analyzeProbeResponse(res, body);
    if (analysis.inconclusive) blocked += 1;
    if (res.status === 200 && /"data"/i.test(body)) {
      findings.push({
        id: "graphql-batch-aliases",
        severity: "medium",
        category: "graphql",
        title: "GraphQL allows large alias batches",
        description: "Server processed a query with many aliases — potential DoS vector.",
        evidence: `25 aliases → HTTP ${res.status}`,
        remediation: "Limit query depth, alias count, and complexity.",
      });
    }
  } catch {
    /* skip */
  }

  // Introspection depth
  probesSent += 1;
  try {
    const { res, body } = await gqlPost(fetchFn, endpoint, {
      query: "{ __schema { types { name fields { name type { name } } } } }",
    });
    const analysis = analyzeProbeResponse(res, body);
    if (analysis.inconclusive) blocked += 1;
    if (res.status === 200 && /"__schema"/i.test(body)) {
      findings.push({
        id: "graphql-deep-introspection",
        severity: "medium",
        category: "graphql",
        title: "GraphQL deep introspection enabled",
        description: "Full schema introspection returned without auth.",
        evidence: endpoint,
        remediation: "Disable introspection in production.",
      });
    }
  } catch {
    /* skip */
  }

  if (blocked > 0) {
    findings.push({
      id: "graphql-waf-blocked",
      severity: "info",
      category: "graphql",
      title: "GraphQL probes partially blocked",
      description: `${blocked} GraphQL probe(s) hit rate limits or WAF.`,
      evidence: endpoint,
      remediation: "Review WAF rules; retest from allowlisted IP.",
    });
  }

  if (findings.length === 0) {
    findings.push({
      id: "graphql-fuzz-clean",
      severity: "info",
      category: "graphql",
      title: "GraphQL active fuzz completed",
      description: `${probesSent} probes sent to ${endpoint} without confirmed issues.`,
      evidence: endpoint,
      remediation: "Continue testing authenticated mutations separately.",
    });
  }

  return { findings, endpoint, probesSent, blocked };
}
