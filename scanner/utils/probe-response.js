const WAF_BODY = [
  /cloudflare/i,
  /attention required/i,
  /akamai/i,
  /incapsula/i,
  /sucuri/i,
  /request blocked/i,
  /access denied/i,
  /bot detection/i,
  /security service/i,
];

const WAF_HEADERS = [/cloudflare/i, /akamai/i, /incapsula/i, /sucuri/i];

export function analyzeProbeResponse(res, body = "") {
  const status = res?.status || 0;
  const server = res?.headers?.get?.("server") || "";
  const cfRay = res?.headers?.get?.("cf-ray");
  const rateLimited = status === 429 || /rate.?limit|too many requests/i.test(body);
  const wafBlocked =
    (status === 403 || status === 406)
    && (WAF_BODY.some((p) => p.test(body)) || WAF_HEADERS.some((p) => p.test(server)) || Boolean(cfRay));
  const serviceBlocked = status === 503 && /rate|limit|blocked/i.test(body);

  return {
    status,
    rateLimited,
    wafBlocked,
    blocked: rateLimited || wafBlocked || serviceBlocked,
    inconclusive: rateLimited || wafBlocked,
  };
}

export function wafRateLimitFinding(stats) {
  if (!stats.rateLimited && !stats.wafBlocked) return null;

  const parts = [];
  if (stats.rateLimited) parts.push(`${stats.rateLimited} rate-limited (429)`);
  if (stats.wafBlocked) parts.push(`${stats.wafBlocked} WAF-blocked`);

  return {
    id: "probe-waf-rate-limit",
    severity: "info",
    category: "active",
    title: "Probes blocked by rate limiting or WAF",
    description: `${parts.join(", ")} — some injection tests may be inconclusive.`,
    evidence: `${stats.totalProbes} probes sent, ${stats.inconclusive} inconclusive`,
    remediation: "Whitelist scanner IP or run during off-peak; review WAF logs for true positives.",
  };
}
