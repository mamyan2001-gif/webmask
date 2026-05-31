export const DEFAULT_TARGET_CONFIG = {
  url: "",
  faviconUrl: null,
  authCookie: "",
  authBearer: "",
  authApiKey: "",
  authApiKeyHeader: "X-API-Key",
  authProfile: null,
  openApiSpec: null,
  seedUrls: [],
  scopeRules: { allowedHosts: [], deniedPaths: [], allowedPaths: [] },
  scanRoles: [],
  scanOptions: { profile: "standard" },
};

export const TRIAGE_STATES = [
  { id: "open", label: "Open" },
  { id: "confirmed", label: "Confirmed" },
  { id: "false_positive", label: "False positive" },
  { id: "accepted", label: "Accepted risk" },
];

export const DEFAULT_AUTH_PROFILE = {
  loginUrl: "https://example.com/login",
  credentials: { username: "", password: "" },
  steps: [
    { action: "fill", selector: "#username", value: "{{username}}" },
    { action: "fill", selector: "#password", value: "{{password}}" },
    { action: "click", selector: "button[type=submit]" },
    { action: "wait", ms: 2000 },
  ],
  successUrlContains: "/dashboard",
};

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function severityClass(severity) {
  return `severity severity--${severity || "info"}`;
}

export function scanLabel(scan) {
  return scan.targetUrl || `Scan #${scan.scanNumber}`;
}

export function formatSummary(summary) {
  if (!summary) return "No findings";
  const parts = SEVERITY_ORDER.filter((s) => summary[s] > 0).map((s) => `${summary[s]} ${s}`);
  return parts.length ? parts.join(" · ") : "No issues found";
}
