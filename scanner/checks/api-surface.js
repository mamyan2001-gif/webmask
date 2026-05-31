import { fetchTarget } from "../utils/http.js";
import { confirmsApiExposure, isHtmlResponse } from "../utils/validation.js";

const API_PATHS = [
  { path: "/graphql", severity: "medium", title: "GraphQL endpoint exposed", marker: /"(?:query|mutation)"\s*:|__schema|IntrospectionQuery/i },
  { path: "/api/graphql", severity: "medium", title: "GraphQL API exposed", marker: /"(?:query|mutation)"\s*:|__schema|IntrospectionQuery/i },
  { path: "/swagger", severity: "medium", title: "Swagger UI exposed", marker: /swagger-ui|"swagger"\s*:\s*"/i },
  { path: "/swagger/index.html", severity: "medium", title: "Swagger UI exposed", marker: /swagger-ui|"swagger"\s*:\s*"/i },
  { path: "/swagger.json", severity: "high", title: "Swagger/OpenAPI spec exposed", marker: /"swagger"\s*:\s*"|"openapi"\s*:\s*"/i },
  { path: "/openapi.json", severity: "high", title: "OpenAPI specification exposed", marker: /"openapi"\s*:\s*"/i },
  { path: "/api-docs", severity: "medium", title: "API documentation exposed", marker: /swagger|openapi|api-docs/i },
  { path: "/v2/api-docs", severity: "high", title: "Spring API docs exposed", marker: /"swagger"\s*:\s*"|"basePath"\s*:/i },
  { path: "/v3/api-docs", severity: "high", title: "OpenAPI v3 docs exposed", marker: /"openapi"\s*:\s*"/i },
  { path: "/actuator", severity: "high", title: "Spring Actuator root exposed", marker: /"_links"\s*:\s*\{|\/actuator\//i },
  { path: "/actuator/env", severity: "critical", title: "Spring Actuator /env exposed", marker: /"propertySources"|"systemProperties"/i },
  { path: "/actuator/heapdump", severity: "critical", title: "Spring Actuator heap dump exposed", marker: /^PK|\x1f\x8b/ },
  { path: "/.well-known/openid-configuration", severity: "info", title: "OpenID configuration published", expectFound: true, marker: /"issuer"\s*:\s*"/i },
  { path: "/debug", severity: "high", title: "Debug endpoint exposed", marker: /debug|stack trace|exception/i },
  { path: "/debug/default/view", severity: "critical", title: "Yii/Laravel debug view exposed", marker: /Yii\\|Whoops\\|stack trace/i },
  { path: "/telescope", severity: "high", title: "Laravel Telescope exposed", marker: /telescope|Laravel Telescope/i },
  { path: "/horizon", severity: "high", title: "Laravel Horizon exposed", marker: /Laravel Horizon|horizon-dashboard/i },
  { path: "/wp-json/wp/v2/users", severity: "medium", title: "WordPress user enumeration API", marker: /"slug"\s*:\s*"|"name"\s*:\s*"/i },
  { path: "/api/v1", severity: "info", title: "REST API v1 path reachable", expectFound: true },
  { path: "/metrics", severity: "high", title: "Prometheus metrics exposed", marker: /^# HELP |# TYPE /m },
  { path: "/health", severity: "info", title: "Health check endpoint exposed", expectFound: true, marker: /"status"\s*:\s*"(?:ok|up|healthy)"/i },
  { path: "/status", severity: "info", title: "Status endpoint exposed", expectFound: true, marker: /"status"\s*:\s*"/i },
];

export async function checkApiSurface(baseUrl) {
  const findings = [];
  const origin = new URL(baseUrl).origin;

  for (const probe of API_PATHS) {
    const url = `${origin}${probe.path}`;
    try {
      const { res, body } = await fetchTarget(url, { followRedirects: false, timeout: 8000 });
      const contentType = res.headers.get("content-type") || "";
      const reachable = res.status >= 200 && res.status < 300 && body.length > 0;

      if (probe.expectFound) {
        if (reachable && (!probe.marker || probe.marker.test(body) || !isHtmlResponse(body, contentType))) {
          if (probe.marker && !probe.marker.test(body) && isHtmlResponse(body, contentType)) {
            continue;
          }
          findings.push({
            id: `api-info-${probe.path.replace(/\W/g, "-")}`,
            severity: "info",
            category: "api",
            title: probe.title,
            description: `Endpoint responded at ${probe.path}.`,
            evidence: `${probe.path} → HTTP ${res.status}`,
            remediation: "Verify exposure is intentional and not leaking sensitive data.",
          });
        }
        continue;
      }

      if (!reachable || !probe.marker) continue;
      if (!confirmsApiExposure(body, contentType, probe.marker)) continue;

      const snippet = body.slice(0, 80).replace(/\s+/g, " ");
      findings.push({
        id: `api-exposed-${probe.path.replace(/\W/g, "-")}`,
        severity: probe.severity,
        category: "api",
        title: probe.title,
        description: "Response content matches known API or debug signatures.",
        evidence: `${url} → ${res.status}, body: ${snippet}…`,
        remediation: "Restrict API documentation and debug endpoints to authenticated admin networks.",
      });
    } catch {
      /* skip */
    }
  }

  return findings;
}
