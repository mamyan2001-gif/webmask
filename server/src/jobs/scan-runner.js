import path from "path";
import fs from "fs/promises";
import { loadSites, saveSites, REPORTS_DIR } from "../store.js";
import { loadScannerSettings } from "../settings.js";
import { getOastServer } from "../oast/callback-server.js";
import { diffScans } from "../../../scanner/diff/scan-diff.js";
import { mergeRoleScanResults } from "../../../scanner/diff/role-scan.js";
import { sendWebhookAlert } from "../alerts/webhooks.js";
import { loadTriage, triageDiffMap } from "../settings.js";

function buildAuthHeaders(options, site) {
  const headers = { ...(site.config.authHeaders || {}), ...(options.authHeaders || {}) };
  const bearer = options.authBearer ?? site.config.authBearer ?? "";
  const apiKey = options.authApiKey ?? site.config.authApiKey ?? "";
  const apiKeyHeader = options.authApiKeyHeader ?? site.config.authApiKeyHeader ?? "X-API-Key";
  if (bearer.trim()) headers.Authorization = bearer.trim().startsWith("Bearer ") ? bearer.trim() : `Bearer ${bearer.trim()}`;
  if (apiKey.trim()) headers[apiKeyHeader] = apiKey.trim();
  return headers;
}

function resolveScanRoles(options, site) {
  const roles = options.scanRoles ?? site.config.scanRoles ?? [];
  if (!Array.isArray(roles) || roles.length === 0) {
    return [{
      name: "default",
      authCookie: options.authCookie ?? site.config.authCookie ?? "",
      authHeaders: buildAuthHeaders(options, site),
    }];
  }
  return roles.slice(0, 3).map((role, i) => ({
    name: role.name || `role-${i + 1}`,
    authCookie: role.authCookie || "",
    authHeaders: { ...buildAuthHeaders(options, site), ...(role.authHeaders || {}) },
  }));
}

async function runSingleScan({
  runVulnerabilityScan,
  targetUrl,
  scanOptions,
  role,
  oastToken,
  oastGetHits,
  onLog,
}) {
  return runVulnerabilityScan({
    targetUrl,
    scanOptions: {
      ...scanOptions,
      authCookie: role.authCookie,
      authHeaders: role.authHeaders,
    },
    onLog,
    oastToken,
    oastGetHits,
  });
}

const siteScanLocks = new Map();

export function isSiteScanRunning(siteId) {
  return siteScanLocks.has(siteId);
}

export async function executeSiteScan(siteId, options = {}) {
  if (siteScanLocks.get(siteId)) {
    throw new Error("A scan is already running for this target");
  }
  siteScanLocks.set(siteId, true);

  try {
    return await runSiteScan(siteId, options);
  } finally {
    siteScanLocks.delete(siteId);
  }
}

async function runSiteScan(siteId, options = {}) {
  const { runVulnerabilityScan } = await import("../../../scanner/run.js");
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === siteId);
  if (idx === -1) throw new Error("Target not found");

  const site = data.sites[idx];
  const targetUrl = options.url || site.config.url;
  if (!targetUrl?.trim()) throw new Error("Target URL is required");

  const settings = await loadScannerSettings();
  const oastPublicBaseUrl = options.oastPublicBaseUrl ?? settings.oastPublicBaseUrl;
  const oast = getOastServer({
    port: settings.oastPort,
    publicBaseUrl: oastPublicBaseUrl,
  });
  await oast.start();
  oast.updatePublicBaseUrl(oastPublicBaseUrl);

  const scanNumber = (site.scanCount || 0) + 1;
  const scanId = `scan-${scanNumber}`;
  const oastReg = oast.registerToken(scanId);

  const baseScanOptions = {
    ...(site.config.scanOptions || {}),
    ...(options.scanOptions || {}),
    authProfile: options.authProfile ?? site.config.authProfile ?? null,
    openApiSpec: options.openApiSpec ?? site.config.openApiSpec ?? null,
    seedUrls: options.seedUrls ?? site.config.seedUrls ?? [],
    scopeRules: options.scopeRules ?? site.config.scopeRules ?? {},
    oastBaseUrl: oastPublicBaseUrl,
    oastToken: oastReg.token,
    authHeaders: buildAuthHeaders(options, site),
  };

  if (options.authProfile !== undefined) site.config.authProfile = options.authProfile;
  if (options.openApiSpec !== undefined) site.config.openApiSpec = options.openApiSpec;
  if (options.seedUrls !== undefined) site.config.seedUrls = options.seedUrls;
  if (options.scopeRules !== undefined) site.config.scopeRules = options.scopeRules;
  if (options.scanRoles !== undefined) site.config.scanRoles = options.scanRoles;
  if (options.authBearer !== undefined) site.config.authBearer = options.authBearer;
  if (options.authApiKey !== undefined) site.config.authApiKey = options.authApiKey;
  if (options.authApiKeyHeader !== undefined) site.config.authApiKeyHeader = options.authApiKeyHeader;

  let previousReport = null;
  const prevScan = site.scans?.[0];
  if (prevScan?.scanId) {
    try {
      const raw = await fs.readFile(path.join(REPORTS_DIR, site.id, prevScan.scanId, "report.json"), "utf8");
      previousReport = JSON.parse(raw);
    } catch {
      /* no previous */
    }
  }

  const roles = resolveScanRoles(options, site);
  const roleResults = [];

  for (const role of roles) {
    const result = await runSingleScan({
      runVulnerabilityScan,
      targetUrl,
      scanOptions: baseScanOptions,
      role,
      oastToken: oastReg.token,
      oastGetHits: () => oast.getHits(oastReg.token),
      onLog: options.onLog,
    });
    roleResults.push({ roleName: role.name, result });
  }

  const merged = roles.length > 1 ? mergeRoleScanResults(roleResults) : roleResults[0].result;

  const triageData = await loadTriage();
  const triageMap = triageDiffMap(triageData.entries || {});

  const regression = previousReport
    ? diffScans(previousReport, { ...merged, scanId }, triageMap)
    : null;

  site.config.url = merged.targetUrl;
  if (merged.faviconUrl) site.config.faviconUrl = merged.faviconUrl;

  const scan = {
    scanId,
    scanNumber,
    ...merged,
    regression,
  };

  const reportDir = path.join(REPORTS_DIR, site.id, scanId);
  await fs.mkdir(reportDir, { recursive: true });
  await fs.writeFile(path.join(reportDir, "report.json"), JSON.stringify(scan, null, 2), "utf8");

  site.scanCount = scanNumber;
  site.scans.unshift({
    scanId,
    scanNumber,
    targetUrl: scan.targetUrl,
    faviconUrl: scan.faviconUrl || null,
    status: scan.status,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    durationMs: scan.durationMs,
    summary: scan.summary,
    checksRun: scan.checksRun,
    findingCount: scan.findings.length,
    profile: scan.scanOptions?.profile,
    regressionSummary: regression?.summary,
    scanRoles: scan.scanRoles,
  });
  site.lastScan = { scanId, finishedAt: scan.finishedAt, summary: scan.summary };
  site.updatedAt = new Date().toISOString();
  data.sites[idx] = site;
  await saveSites(data);

  if (options.notify !== false) {
    await sendWebhookAlert(await loadScannerSettings(), { site, scan, regression });
  }

  return { site, scan };
}
