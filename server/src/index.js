import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs/promises";
import { nanoid } from "nanoid";
import { CHECK_MODULES, SCAN_PROFILES, diffScans } from "../../scanner/run.js";
import { testAuthProfile } from "../../scanner/auth/profiles.js";
import { executeSiteScan } from "./jobs/scan-runner.js";
import { startScheduler } from "./jobs/scheduler.js";
import { getOastServer } from "./oast/callback-server.js";
import {
  loadScannerSettings,
  saveScannerSettings,
  loadSchedules,
  saveSchedules,
  loadTriage,
  saveTriage,
  triageKey,
  triageMapForScan,
  triageDiffMap,
} from "./settings.js";
import { reportToHtml, reportToCsv } from "./export/report-export.js";
import { installLocalDependencies, checkLocalDependencies } from "./deploy/local-setup.js";
import {
  ensureDirs,
  loadSites,
  saveSites,
  defaultSiteConfig,
  REPORTS_DIR,
  ROOT,
} from "./store.js";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

await ensureDirs();

const scannerSettings = await loadScannerSettings();
const oast = getOastServer({
  port: scannerSettings.oastPort,
  publicBaseUrl: scannerSettings.oastPublicBaseUrl,
});
await oast.start();
startScheduler();

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "webmask", version: "1.0.0", mode: "vulnerability-scanner" });
});

app.get("/api/profiles", (_req, res) => {
  res.json({
    profiles: Object.values(SCAN_PROFILES).map(({ id, label, description }) => ({ id, label, description })),
  });
});

app.get("/api/settings", async (_req, res) => {
  res.json(await loadScannerSettings());
});

app.patch("/api/settings", async (req, res) => {
  const current = await loadScannerSettings();
  const next = { ...current, ...req.body };
  if (req.body.slackWebhookUrl && !next.webhooks?.length) {
    next.webhooks = [req.body.slackWebhookUrl];
  }
  await saveScannerSettings(next);
  if (req.body.oastPublicBaseUrl !== undefined) {
    oast.updatePublicBaseUrl(next.oastPublicBaseUrl);
  }
  res.json(next);
});

app.get("/api/oast/status", async (_req, res) => {
  const settings = await loadScannerSettings();
  const { validateOastConfig } = await import("../../scanner/utils/oast.js");
  const validation = validateOastConfig(settings.oastPublicBaseUrl);

  let tunnelReachable = null;
  if (validation.remoteReady) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);
      const healthRes = await fetch(`${validation.base}/oast/health`, { signal: controller.signal });
      clearTimeout(timer);
      tunnelReachable = healthRes.ok;
    } catch {
      tunnelReachable = false;
    }
  }

  res.json({
    ...oast.getStatus(),
    validation,
    tunnelReachable,
  });
});

app.get("/api/schedules", async (_req, res) => {
  res.json(await loadSchedules());
});

app.post("/api/schedules", async (req, res) => {
  const cronExpr = req.body.cron || "0 9 * * *";
  const cron = (await import("node-cron")).default;
  if (!cron.validate(cronExpr)) {
    return res.status(400).json({ error: "Invalid cron expression" });
  }
  if (!req.body.siteId) {
    return res.status(400).json({ error: "siteId is required" });
  }
  const data = await loadSchedules();
  const job = {
    id: nanoid(8),
    siteId: req.body.siteId,
    cron: cronExpr,
    enabled: req.body.enabled !== false,
    lastRun: null,
  };
  data.schedules.push(job);
  await saveSchedules(data);
  const { reloadScheduler } = await import("./jobs/scheduler.js");
  await reloadScheduler();
  res.status(201).json(job);
});

app.delete("/api/schedules/:id", async (req, res) => {
  const data = await loadSchedules();
  data.schedules = data.schedules.filter((s) => s.id !== req.params.id);
  await saveSchedules(data);
  const { reloadScheduler } = await import("./jobs/scheduler.js");
  await reloadScheduler();
  res.json({ ok: true });
});

app.get("/api/checks", (_req, res) => {
  res.json({ checks: CHECK_MODULES });
});

app.get("/api/sites", async (_req, res) => {
  const data = await loadSites();
  res.json(data);
});

app.post("/api/sites", async (req, res) => {
  const data = await loadSites();
  const site = {
    id: nanoid(10),
    name: req.body.name?.trim() || "New Target",
    config: { ...defaultSiteConfig(), ...req.body.config },
    scans: [],
    scanCount: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  data.sites.unshift(site);
  await saveSites(data);
  res.status(201).json(site);
});

app.get("/api/sites/:id", async (req, res) => {
  const data = await loadSites();
  const site = data.sites.find((s) => s.id === req.params.id);
  if (!site) return res.status(404).json({ error: "Target not found" });
  res.json(site);
});

app.patch("/api/sites/:id", async (req, res) => {
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Target not found" });

  const site = data.sites[idx];
  if (req.body.name) site.name = req.body.name.trim();
  if (req.body.config) site.config = { ...site.config, ...req.body.config };
  site.updatedAt = new Date().toISOString();
  data.sites[idx] = site;
  await saveSites(data);
  res.json(site);
});

app.delete("/api/sites/:id", async (req, res) => {
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Target not found" });
  const [removed] = data.sites.splice(idx, 1);
  try {
    await fs.rm(path.join(REPORTS_DIR, removed.id), { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  await saveSites(data);
  res.json({ ok: true });
});

app.post("/api/sites/:id/auth/test", async (req, res) => {
  const data = await loadSites();
  const site = data.sites.find((s) => s.id === req.params.id);
  if (!site) return res.status(404).json({ error: "Target not found" });
  const profile = req.body.authProfile !== undefined
    ? req.body.authProfile
    : site.config.authProfile;
  if (!profile?.steps?.length) {
    return res.status(400).json({ error: "Auth profile with steps is required" });
  }
  try {
    const result = await testAuthProfile(profile);
    res.json({ ok: true, ...result, cookies: "[redacted]" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/sites/:id/openapi", express.json({ limit: "5mb" }), async (req, res) => {
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Target not found" });

  const raw = req.body.spec ?? req.body.openApiSpec;
  if (raw === undefined || raw === null || raw === "") {
    return res.status(400).json({ error: "OpenAPI spec is required (spec field)" });
  }

  let parsed;
  const rawText = typeof raw === "string" ? raw.trim() : "";

  if (typeof raw === "string" && /^https?:\/\//i.test(rawText)) {
    try {
      const { normalizeTargetUrl, assertSafeTarget } = await import("../../scanner/utils/url.js");
      const specUrl = normalizeTargetUrl(rawText);
      await assertSafeTarget(specUrl);
      data.sites[idx].config.openApiSpec = specUrl;
      data.sites[idx].updatedAt = new Date().toISOString();
      await saveSites(data);
      return res.json({ ok: true, title: "OpenAPI URL", url: specUrl, paths: 0 });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
  }

  try {
    parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
    if (!parsed.openapi && !parsed.swagger) {
      return res.status(400).json({ error: "Not a valid OpenAPI document" });
    }
  } catch {
    return res.status(400).json({ error: "Invalid JSON for OpenAPI spec" });
  }

  data.sites[idx].config.openApiSpec = parsed;
  data.sites[idx].updatedAt = new Date().toISOString();
  await saveSites(data);
  res.json({
    ok: true,
    title: parsed.info?.title || "OpenAPI",
    version: parsed.info?.version || parsed.openapi || parsed.swagger,
    paths: Object.keys(parsed.paths || {}).length,
  });
});

app.post("/api/sites/:id/scan", async (req, res) => {
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Target not found" });

  const site = data.sites[idx];
  const targetUrl = req.body.url || site.config.url;
  if (!targetUrl?.trim()) {
    return res.status(400).json({ error: "Target URL is required" });
  }

  if (req.body.scanOptions) {
    site.config.scanOptions = { ...site.config.scanOptions, ...req.body.scanOptions };
  }
  if (req.body.authCookie !== undefined) site.config.authCookie = req.body.authCookie;
  if (req.body.authProfile !== undefined) site.config.authProfile = req.body.authProfile;
  if (req.body.openApiSpec !== undefined) site.config.openApiSpec = req.body.openApiSpec;
  if (req.body.seedUrls !== undefined) site.config.seedUrls = req.body.seedUrls;
  if (req.body.scopeRules !== undefined) site.config.scopeRules = req.body.scopeRules;
  if (req.body.scanRoles !== undefined) site.config.scanRoles = req.body.scanRoles;
  if (req.body.authBearer !== undefined) site.config.authBearer = req.body.authBearer;
  if (req.body.authApiKey !== undefined) site.config.authApiKey = req.body.authApiKey;
  if (req.body.authApiKeyHeader !== undefined) site.config.authApiKeyHeader = req.body.authApiKeyHeader;
  data.sites[idx] = site;
  await saveSites(data);

  const wantsStream =
    req.body.stream === true ||
    String(req.headers.accept || "").includes("application/x-ndjson");

  const writeEvent = wantsStream
    ? (payload) => {
        res.write(`${JSON.stringify(payload)}\n`);
      }
    : null;

  if (wantsStream) {
    res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();
  }

  try {
    const { site: updated, scan } = await executeSiteScan(req.params.id, {
      url: targetUrl,
      scanOptions: site.config.scanOptions,
      authCookie: site.config.authCookie,
      authProfile: site.config.authProfile,
      openApiSpec: site.config.openApiSpec,
      seedUrls: site.config.seedUrls,
      scopeRules: site.config.scopeRules,
      scanRoles: site.config.scanRoles,
      authBearer: site.config.authBearer,
      authApiKey: site.config.authApiKey,
      authApiKeyHeader: site.config.authApiKeyHeader,
      oastPublicBaseUrl: req.body.oastPublicBaseUrl,
      onLog: writeEvent ? (entry) => writeEvent({ type: "log", ...entry }) : undefined,
    });

    if (wantsStream) {
      writeEvent({ type: "complete", site: updated, scan });
      res.end();
    } else {
      res.status(201).json({ site: updated, scan });
    }
  } catch (err) {
    console.error("[WebMask] Scan failed:", err);
    if (wantsStream) {
      writeEvent({ type: "error", error: err.message || "Scan failed" });
      res.end();
    } else {
      res.status(400).json({ error: err.message || "Scan failed" });
    }
  }
});

app.get("/api/sites/:id/scans/diff", async (req, res) => {
  const { base, compare } = req.query;
  if (!base || !compare) {
    return res.status(400).json({ error: "Query params base and compare are required" });
  }
  try {
    const baseRaw = await fs.readFile(path.join(REPORTS_DIR, req.params.id, base, "report.json"), "utf8");
    const compareRaw = await fs.readFile(path.join(REPORTS_DIR, req.params.id, compare, "report.json"), "utf8");
    const triage = await loadTriage();
    const triageMap = triageDiffMap(triage.entries || {});
    res.json(diffScans(JSON.parse(baseRaw), JSON.parse(compareRaw), triageMap));
  } catch {
    res.status(404).json({ error: "Scan report not found" });
  }
});

app.get("/api/sites/:id/scans/:scanId/export", async (req, res) => {
  const format = req.query.format || "html";
  const reportPath = path.join(REPORTS_DIR, req.params.id, req.params.scanId, "report.json");
  try {
    const report = JSON.parse(await fs.readFile(reportPath, "utf8"));
    if (format === "csv") {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="webmask-${req.params.scanId}.csv"`);
      return res.send(reportToCsv(report));
    }
    res.setHeader("Content-Type", "text/html");
    return res.send(reportToHtml(report));
  } catch {
    res.status(404).json({ error: "Scan report not found" });
  }
});

app.get("/api/sites/:id/scans/:scanId/triage", async (req, res) => {
  const triage = await loadTriage();
  res.json({ triage: triageMapForScan(req.params.id, req.params.scanId, triage.entries || {}) });
});

app.patch("/api/sites/:id/scans/:scanId/findings/:findingId/triage", async (req, res) => {
  const { state } = req.body;
  if (!["confirmed", "false_positive", "accepted", "open"].includes(state)) {
    return res.status(400).json({ error: "Invalid triage state" });
  }
  const triage = await loadTriage();
  const key = triageKey(req.params.id, req.params.scanId, req.params.findingId, req.body.pageUrl || "");
  if (state === "open") delete triage.entries[key];
  else triage.entries[key] = state;
  await saveTriage(triage);
  res.json({ ok: true, key, state });
});

app.get("/api/sites/:id/scans/:scanId", async (req, res) => {
  const reportPath = path.join(REPORTS_DIR, req.params.id, req.params.scanId, "report.json");
  try {
    const raw = await fs.readFile(reportPath, "utf8");
    res.json(JSON.parse(raw));
  } catch {
    res.status(404).json({ error: "Scan report not found" });
  }
});

app.delete("/api/sites/:id/scans/:scanId", async (req, res) => {
  const data = await loadSites();
  const idx = data.sites.findIndex((s) => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Target not found" });

  const site = data.sites[idx];
  const scanIdx = site.scans?.findIndex((s) => s.scanId === req.params.scanId);
  if (scanIdx === -1 || scanIdx === undefined) {
    return res.status(404).json({ error: "Scan not found" });
  }

  site.scans.splice(scanIdx, 1);
  try {
    await fs.rm(path.join(REPORTS_DIR, site.id, req.params.scanId), { recursive: true, force: true });
  } catch {
    /* ignore */
  }

  site.updatedAt = new Date().toISOString();
  data.sites[idx] = site;
  await saveSites(data);
  res.json({ ok: true, site });
});

app.get("/api/setup/status", async (_req, res) => {
  const deps = await checkLocalDependencies();
  res.json({
    dependencies: deps,
    needsSetup: !deps.ready,
  });
});

app.get("/api/dashboard", async (_req, res) => {
  const data = await loadSites();
  const deps = await checkLocalDependencies();
  const sites = data.sites || [];

  let totalScans = 0;
  let totalFindings = 0;
  const severityTotals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const recentActivity = [];

  for (const site of sites) {
    totalScans += site.scanCount || 0;
    for (const s of site.scans || []) {
      totalFindings += s.findingCount || 0;
      for (const [sev, count] of Object.entries(s.summary || {})) {
        if (severityTotals[sev] !== undefined) severityTotals[sev] += count;
      }
      recentActivity.push({
        siteId: site.id,
        siteName: site.name,
        scanId: s.scanId,
        scanNumber: s.scanNumber,
        targetUrl: s.targetUrl,
        faviconUrl: s.faviconUrl || site.config?.faviconUrl || null,
        createdAt: s.finishedAt || s.startedAt,
        summary: s.summary,
      });
    }
  }

  recentActivity.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  res.json({
    stats: {
      targets: sites.length,
      scans: totalScans,
      findings: totalFindings,
      critical: severityTotals.critical,
      high: severityTotals.high,
    },
    onboarding: {
      depsInstalled: deps.ready,
      hasTarget: sites.length > 0,
      hasScan: totalScans > 0,
      hasCritical: severityTotals.critical > 0,
    },
    recentActivity: recentActivity.slice(0, 10),
  });
});

app.post("/api/setup/install-local", async (_req, res) => {
  const logs = [];
  try {
    const result = await installLocalDependencies((msg) => logs.push(msg));
    res.json({ ...result, logs });
  } catch (err) {
    res.status(500).json({ error: err.message, logs });
  }
});

app.use(express.static(path.join(ROOT, "client/dist")));

app.get("*", (_req, res, next) => {
  if (_req.path.startsWith("/api")) return next();
  res.sendFile(path.join(ROOT, "client/dist/index.html"), (err) => {
    if (err) res.status(404).json({ error: "Not found" });
  });
});

app.listen(PORT, () => {
  console.log(`WebMask security scanner at http://localhost:${PORT}`);
});
