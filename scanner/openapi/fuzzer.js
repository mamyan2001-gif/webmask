import { fetchTarget } from "../utils/http.js";
import { buildOastCallbackUrl } from "../utils/oast.js";
import {
  buildJsonBodyFromSchema,
  resolveOperationUrl,
} from "./import.js";

const SQLI_PAYLOAD = "webmask' OR 1=1--";
const SQLI_ERRORS = [
  /SQL syntax.*MySQL/i,
  /mysql_fetch/i,
  /ORA-\d{5}/i,
  /PostgreSQL.*ERROR/i,
  /SQLite3::/i,
  /Unclosed quotation mark/i,
  /quoted string not properly terminated/i,
];

function finding(base) {
  return { ...base, category: "openapi" };
}

function detectSqli(body, context) {
  if (body && SQLI_ERRORS.some((p) => p.test(body))) {
    return finding({
      id: `openapi-sqli-${context.id}`,
      severity: "high",
      title: "Possible SQL injection via OpenAPI input",
      description: context.description,
      evidence: context.evidence,
      remediation: "Use parameterized queries and validate all API inputs.",
      pageUrl: context.pageUrl,
    });
  }
  return null;
}

async function probeRequest(fetchFn, { method, url, headers, body, contentType }) {
  const reqHeaders = { ...headers };
  if (body !== undefined) {
    reqHeaders["Content-Type"] = contentType || "application/json";
  }
  return fetchFn(url, {
    method,
    headers: reqHeaders,
    body: body !== undefined ? (typeof body === "string" ? body : JSON.stringify(body)) : undefined,
    timeout: 9000,
    followRedirects: false,
  });
}

export async function fuzzOpenApiOperations(operations, options = {}) {
  const findings = [];
  const fetchFn = options.fetchFn || fetchTarget;
  const maxOps = options.maxOperations || 40;
  const oastBaseUrl = options.oastBaseUrl || "";
  const oastToken = options.oastToken || "";
  let probesSent = 0;
  let bodyProbes = 0;
  let queryProbes = 0;

  for (const op of operations.slice(0, maxOps)) {
    const pathParams = {};
    const queryParams = new URLSearchParams();
    const headerParams = {};

    for (const param of op.parameters || []) {
      const sample = param.example || param.schema?.example || "webmask";
      if (param.in === "path") pathParams[param.name] = sample;
      if (param.in === "query") queryParams.set(param.name, sample);
      if (param.in === "header") headerParams[param.name] = String(sample);
    }

    const baseUrl = resolveOperationUrl(op.urlTemplate, pathParams);
    const urlWithQuery = queryParams.toString() ? `${baseUrl}?${queryParams}` : baseUrl;

    // Query parameter SQLi probes
    for (const param of (op.parameters || []).filter((p) => p.in === "query").slice(0, 4)) {
      probesSent += 1;
      queryProbes += 1;
      const q = new URLSearchParams(queryParams);
      q.set(param.name, SQLI_PAYLOAD);
      const target = `${baseUrl}?${q.toString()}`;
      try {
        const { body } = await probeRequest(fetchFn, {
          method: op.method,
          url: target,
          headers: headerParams,
        });
        const hit = detectSqli(body, {
          id: `${op.operationId}-query-${param.name}`,
          description: `Query parameter "${param.name}" on ${op.method} ${op.path} triggered a database error.`,
          evidence: target,
          pageUrl: target,
        });
        if (hit) findings.push(hit);
      } catch {
        /* skip */
      }
    }

    // Header parameter probes (light)
    for (const param of (op.parameters || []).filter((p) => p.in === "header").slice(0, 2)) {
      probesSent += 1;
      try {
        const headers = { ...headerParams, [param.name]: SQLI_PAYLOAD };
        const { body } = await probeRequest(fetchFn, {
          method: op.method,
          url: urlWithQuery,
          headers,
        });
        const hit = detectSqli(body, {
          id: `${op.operationId}-header-${param.name}`,
          description: `Header "${param.name}" on ${op.method} ${op.path} triggered a database error.`,
          evidence: `${op.method} ${urlWithQuery} (header ${param.name})`,
          pageUrl: urlWithQuery,
        });
        if (hit) findings.push(hit);
      } catch {
        /* skip */
      }
    }

    // POST/PUT/PATCH JSON body fuzzing
    if (["POST", "PUT", "PATCH"].includes(op.method) && op.requestBody?.hasBody) {
      const schema = op.requestBody.jsonSchema;
      const stringFields = schema?.properties
        ? Object.entries(schema.properties).filter(([, p]) => p.type === "string").map(([k]) => k)
        : ["payload"];

      const fieldsToTest = stringFields.slice(0, 4);
      if (fieldsToTest.length === 0) fieldsToTest.push("payload");

      for (const field of fieldsToTest) {
        probesSent += 1;
        bodyProbes += 1;

        const sqliBody = buildJsonBodyFromSchema(schema, field, SQLI_PAYLOAD);
        try {
          const { body } = await probeRequest(fetchFn, {
            method: op.method,
            url: urlWithQuery,
            headers: headerParams,
            body: sqliBody,
            contentType: op.requestBody.contentType,
          });
          const hit = detectSqli(body, {
            id: `${op.operationId}-body-sqli-${field}`,
            description: `JSON body field "${field}" on ${op.method} ${op.path} triggered a database error.`,
            evidence: `${op.method} ${urlWithQuery} body.${field}`,
            pageUrl: urlWithQuery,
          });
          if (hit) findings.push(hit);
        } catch {
          /* skip */
        }

        if (oastBaseUrl && oastToken) {
          probesSent += 1;
          bodyProbes += 1;
          const callback = buildOastCallbackUrl(oastBaseUrl, oastToken, {
            probe: "openapi-body",
            op: op.operationId,
            field,
          });
          const oastBody = buildJsonBodyFromSchema(schema, field, callback);
          if (!schema?.properties) {
            oastBody.url = callback;
            oastBody.callback = callback;
          }
          try {
            await probeRequest(fetchFn, {
              method: op.method,
              url: urlWithQuery,
              headers: headerParams,
              body: oastBody,
              contentType: op.requestBody.contentType,
            });
          } catch {
            /* skip */
          }
        }
      }

      // Form-urlencoded body
      if (op.requestBody.contentType === "application/x-www-form-urlencoded") {
        probesSent += 1;
        bodyProbes += 1;
        const form = new URLSearchParams();
        form.set("payload", SQLI_PAYLOAD);
        try {
          const { body } = await probeRequest(fetchFn, {
            method: op.method,
            url: urlWithQuery,
            headers: headerParams,
            body: form.toString(),
            contentType: "application/x-www-form-urlencoded",
          });
          const hit = detectSqli(body, {
            id: `${op.operationId}-form-sqli`,
            description: `Form body on ${op.method} ${op.path} triggered a database error.`,
            evidence: `${op.method} ${urlWithQuery}`,
            pageUrl: urlWithQuery,
          });
          if (hit) findings.push(hit);
        } catch {
          /* skip */
        }
      }
    }

    // OAST via query callback param on GET-like ops
    if (oastBaseUrl && oastToken && ["GET", "POST"].includes(op.method)) {
      probesSent += 1;
      const callback = buildOastCallbackUrl(oastBaseUrl, oastToken, {
        probe: "openapi-query",
        op: op.operationId,
      });
      const q = new URLSearchParams(queryParams);
      q.set("url", callback);
      q.set("callback", callback);
      try {
        await probeRequest(fetchFn, {
          method: "GET",
          url: `${baseUrl}?${q.toString()}`,
          headers: headerParams,
        });
      } catch {
        /* skip */
      }
    }
  }

  if (operations.length > 0) {
    findings.push(finding({
      id: "openapi-fuzz-complete",
      severity: "info",
      title: "OpenAPI fuzzing complete",
      description: `${Math.min(operations.length, maxOps)} operation(s) probed — ${queryProbes} query, ${bodyProbes} body probes.`,
      evidence: `${operations.length} operations in spec, ${probesSent} total probes`,
      remediation: "Review API auth, input validation, and rate limits on all documented routes.",
    }));
  }

  return {
    findings,
    operationsTested: Math.min(operations.length, maxOps),
    probesSent,
    bodyProbes,
    queryProbes,
  };
}

// Re-export for callers
export { loadOpenApiSpec } from "./import.js";
