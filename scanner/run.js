import { normalizeTargetUrl, assertSafeTarget } from "./utils/url.js";
import { fetchTarget, setScanAuth, clearScanAuth } from "./utils/http.js";
import { checkSsl } from "./checks/ssl.js";
import { checkSecurityHeaders, checkDisclosureHeaders } from "./checks/headers.js";
import { checkCookies } from "./checks/cookies.js";
import { checkCors } from "./checks/cors.js";
import { checkHttpMethods } from "./checks/methods.js";
import { checkSensitivePaths } from "./checks/paths.js";
import { checkSubdomains } from "./checks/subdomains.js";
import { checkHiddenDomains } from "./checks/hidden-domains.js";
import { checkTlsAdvanced } from "./checks/tls-advanced.js";
import { checkRedirects } from "./checks/redirects.js";
import { checkContentSecurity } from "./checks/content-security.js";
import { checkDnsEmail } from "./checks/dns-email.js";
import { checkApiSurface } from "./checks/api-surface.js";
import { checkHostInjection } from "./checks/host-injection.js";
import { checkClickjacking } from "./checks/clickjacking.js";
import { checkCachePolicy } from "./checks/cache-policy.js";
import { checkFormSecurity, checkErrorDisclosure } from "./checks/forms-errors.js";
import { checkDirectoryListing, checkSecurityTxt } from "./checks/listing-securitytxt.js";
import { checkInputReflection } from "./checks/reflection.js";
import { checkDnsSecurity } from "./checks/dns-security.js";
import { checkTechnology } from "./checks/technology.js";
import { checkNiktoPaths } from "./checks/nikto-paths.js";
import { checkBackupDiscovery, checkDefaultPages } from "./checks/backup-defaults.js";
import { checkRecon } from "./checks/recon.js";
import { checkSourceMaps, checkCrlfInjection } from "./checks/sourcemaps-crlf.js";
import { checkCookiesAdvanced, checkCspDeep, checkDebugHeaders } from "./checks/cookies-csp-debug.js";
import { checkTlsChain } from "./checks/tls-chain.js";
import {
  checkTransportSecurity,
  checkWebDav,
  checkGraphql,
  checkCrossDomainPolicy,
} from "./checks/transport-webdav-graphql.js";
import { discoverFaviconUrl } from "./utils/favicon.js";
import { crawlSite } from "./crawler/spider.js";
import { crawlSiteWithPlaywright } from "./crawler/playwright-spider.js";
import { runTemplateScan } from "./engine/templates.js";
import { checkActiveProbes } from "./checks/active-probes.js";
import { checkJsEndpoints } from "./checks/js-endpoints.js";
import { scanPageSurface, scanPagesReflection } from "./checks/multipage.js";
import { resolveScanOptions, SCAN_PROFILES } from "./config/profiles.js";
import { runAuthProfile } from "./auth/profiles.js";
import { loadOpenApiSpec, fuzzOpenApiOperations } from "./openapi/fuzzer.js";
import { diffScans, summarizeRegression } from "./diff/scan-diff.js";
import { validateOastConfig, waitForOastCallbacks } from "./utils/oast.js";
import { checkJwtAuth } from "./checks/jwt-auth.js";
import { checkGraphqlFuzz } from "./checks/graphql-fuzz.js";
import { checkCveMatches, extractTechnologiesFromFinding } from "./checks/cve-match.js";
import { runNucleiScan } from "./nuclei/runner.js";

export { resolveScanOptions, SCAN_PROFILES, diffScans, summarizeRegression };

export const CHECK_MODULES = [
  { id: "ssl", label: "SSL/TLS certificate" },
  { id: "tls", label: "TLS hardening (versions & ciphers)" },
  { id: "tls-chain", label: "TLS certificate chain" },
  { id: "headers", label: "Security headers" },
  { id: "disclosure", label: "Information disclosure" },
  { id: "debug-headers", label: "Debug & version headers" },
  { id: "csp", label: "Content-Security-Policy deep audit" },
  { id: "cookies", label: "Cookie flags" },
  { id: "cookies-advanced", label: "Cookie prefix & session rules" },
  { id: "cors", label: "CORS policy" },
  { id: "methods", label: "HTTP methods" },
  { id: "webdav", label: "WebDAV methods" },
  { id: "paths", label: "Sensitive paths" },
  { id: "nikto", label: "Nikto-class path database" },
  { id: "api", label: "API & debug surface" },
  { id: "graphql", label: "GraphQL introspection" },
  { id: "graphql-fuzz", label: "GraphQL active fuzz" },
  { id: "jwt", label: "JWT / Bearer auth tests" },
  { id: "cve", label: "CVE version matching" },
  { id: "nuclei", label: "Nuclei template runner" },
  { id: "redirects", label: "Redirect & open redirect" },
  { id: "content", label: "Content & secret exposure" },
  { id: "dns", label: "DNS email security (SPF/DMARC/DKIM)" },
  { id: "dns-security", label: "DNS infrastructure (DNSSEC/MX)" },
  { id: "injection", label: "Host header injection" },
  { id: "crlf", label: "CRLF header injection" },
  { id: "clickjacking", label: "Clickjacking protection" },
  { id: "cache", label: "Cache policy" },
  { id: "transport", label: "WebSocket, BREACH, COEP" },
  { id: "cross-domain", label: "Flash/Silverlight cross-domain policy" },
  { id: "forms", label: "Form & CSRF analysis" },
  { id: "errors", label: "Verbose error disclosure" },
  { id: "listing", label: "Directory listing" },
  { id: "backup", label: "Backup file discovery" },
  { id: "default-pages", label: "Default install pages" },
  { id: "recon", label: "Recon (robots, sitemap, comments)" },
  { id: "source-maps", label: "JavaScript source maps" },
  { id: "security-txt", label: "security.txt audit" },
  { id: "reflection", label: "Input reflection (XSS)" },
  { id: "technology", label: "Technology fingerprint" },
  { id: "subdomains", label: "Subdomain discovery" },
  { id: "hidden-domains", label: "Hidden domain mapping" },
  { id: "crawl", label: "Web spider (multi-page)" },
  { id: "templates", label: "Nuclei-style template engine" },
  { id: "active", label: "Active injection probes" },
  { id: "js-endpoints", label: "JavaScript API discovery" },
  { id: "openapi", label: "OpenAPI fuzzing" },
  { id: "oast", label: "OAST blind callback detection" },
];

function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity]++;
  }
  return summary;
}

function formatMs(ms) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function createLogger(onLog) {
  const logs = [];
  const log = (level, phase, message, meta = {}) => {
    const entry = {
      at: new Date().toISOString(),
      level,
      phase,
      message,
      ...meta,
    };
    logs.push(entry);
    onLog?.(entry);
    return entry;
  };
  return { log, logs };
}

export async function runVulnerabilityScan({
  targetUrl,
  onLog,
  scanOptions: scanOptionsInput,
  oastToken,
  oastGetHits,
}) {
  const scanOptions = resolveScanOptions(scanOptionsInput);
  const { log, logs } = createLogger(onLog);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const checksRun = [];
  const findings = [];
  let discoveredAssets = {
    subdomains: [],
    hiddenDomains: [],
    crawledPages: [],
    endpoints: [],
    forms: [],
    crawlStats: null,
  };

  setScanAuth(scanOptions);
  try {
  log("info", "init", `Starting ${scanOptions.profile} scan (${scanOptions.mode})`);

  if (scanOptions.oast) {
    const oastCheck = validateOastConfig(scanOptions.oastBaseUrl, targetUrl);
    for (const w of oastCheck.warnings) log("warn", "oast", w);
    for (const e of oastCheck.errors) log("error", "oast", e);
    if (oastCheck.base) {
      scanOptions.oastBaseUrl = oastCheck.base;
      log("info", "oast", `OAST callbacks → ${oastCheck.base}/oast/{token}`, {
        remoteReady: oastCheck.remoteReady,
      });
    }
  }
  if (scanOptions.authProfile?.steps?.length) {
    try {
      log("info", "auth", "Running auth profile login flow…");
      const authResult = await runAuthProfile(scanOptions.authProfile);
      scanOptions.authCookie = authResult.cookies;
      log("success", "auth", `Authenticated — ${authResult.cookieCount} cookie(s)`, { finalUrl: authResult.finalUrl });
      checksRun.push("auth-profile");
    } catch (err) {
      log("warn", "auth", `Auth profile failed: ${err.message}`);
    }
  }

  let normalized;
  try {
    normalized = normalizeTargetUrl(targetUrl);
    log("info", "init", `Target URL normalized: ${normalized}`);
  } catch (err) {
    log("error", "init", err.message);
    throw err;
  }

  try {
    await assertSafeTarget(normalized);
    log("info", "init", "SSRF safety check passed — target resolves to public IP");
  } catch (err) {
    log("error", "init", err.message);
    throw err;
  }

  const url = new URL(normalized);
  const isHttps = url.protocol === "https:";

  log("info", "baseline", "Fetching target homepage…");
  let mainResponse;
  try {
    mainResponse = await fetchTarget(normalized);
    checksRun.push("http-baseline");
    const { res } = mainResponse;
    log("success", "baseline", `Target reachable — HTTP ${res.status}`, {
      status: res.status,
      contentType: res.headers.get("content-type") || "unknown",
    });
  } catch (err) {
    log("error", "baseline", `Could not reach target: ${err.message}`);
    throw new Error(`Could not reach target: ${err.message}`);
  }

  const { res, body } = mainResponse;
  const setCookies = res.headers.getSetCookie?.() ||
    (res.headers.get("set-cookie") ? [res.headers.get("set-cookie")] : []);

  let crawlData = {
    pages: [{
      url: mainResponse.url || normalized,
      body,
      status: res.status,
      headers: res.headers,
      depth: 0,
    }],
    forms: [],
    endpoints: [],
    params: [],
    scriptUrls: [],
  };

  if (scanOptions.crawl) {
    try {
      let pwData = null;
      if (scanOptions.spider === "playwright") {
        pwData = await crawlSiteWithPlaywright(normalized, {
          maxDepth: scanOptions.maxDepth,
          maxPages: scanOptions.maxPages,
          authCookie: scanOptions.authCookie,
          seedUrls: scanOptions.seedUrls,
          scopeRules: scanOptions.scopeRules,
          onLog: log,
        });
      }
      crawlData = pwData || await crawlSite(normalized, {
        maxDepth: scanOptions.maxDepth,
        maxPages: scanOptions.maxPages,
        concurrency: scanOptions.maxConcurrency,
        seedUrls: scanOptions.seedUrls,
        scopeRules: scanOptions.scopeRules,
        fetchFn: fetchTarget,
        onLog: log,
      });
      if (crawlData.pages.length === 0) {
        crawlData.pages = [{
          url: mainResponse.url || normalized,
          body,
          status: res.status,
          headers: res.headers,
          depth: 0,
        }];
      }
      discoveredAssets.crawledPages = crawlData.pages.map((p) => p.url);
      discoveredAssets.forms = crawlData.forms.slice(0, 50);
      discoveredAssets.endpoints = crawlData.endpoints;
      discoveredAssets.crawlStats = {
        pages: crawlData.pages.length,
        forms: crawlData.forms.length,
        endpoints: crawlData.endpoints.length,
        maxDepth: scanOptions.maxDepth,
        engine: crawlData.engine || "fetch",
      };
      checksRun.push("crawl");
    } catch (err) {
      log("warn", "crawl", `Spider error: ${err.message}`);
    }
  }

  const runners = [
    {
      checks: ["ssl"],
      phase: "ssl",
      label: "SSL/TLS certificate",
      run: () => checkSsl(normalized),
    },
    {
      checks: ["tls"],
      phase: "tls",
      label: "TLS hardening",
      run: () => checkTlsAdvanced(normalized),
    },
    {
      checks: ["tls-chain"],
      phase: "tls-chain",
      label: "TLS certificate chain",
      run: () => checkTlsChain(normalized),
    },
    {
      checks: ["headers", "disclosure", "debug-headers", "csp"],
      phase: "headers",
      label: "Security headers & disclosure",
      run: () => [
        ...checkSecurityHeaders(res.headers, isHttps),
        ...checkDisclosureHeaders(res.headers),
        ...checkDebugHeaders(res.headers),
        ...checkCspDeep(res.headers),
      ],
    },
    {
      checks: ["cookies", "cookies-advanced"],
      phase: "cookies",
      label: "Cookie flags",
      skipMessage: "No Set-Cookie headers — skipping cookie audit",
      run: () => (setCookies.length
        ? [...checkCookies(setCookies), ...checkCookiesAdvanced(setCookies)]
        : []),
    },
    {
      checks: ["cors"],
      phase: "cors",
      label: "CORS policy",
      run: () => checkCors(normalized),
    },
    {
      checks: ["methods"],
      phase: "methods",
      label: "HTTP methods",
      run: () => checkHttpMethods(normalized),
    },
    {
      checks: ["webdav"],
      phase: "webdav",
      label: "WebDAV methods",
      run: () => checkWebDav(normalized),
    },
    {
      checks: ["paths"],
      phase: "paths",
      label: "Sensitive paths",
      run: () => checkSensitivePaths(normalized),
    },
    {
      checks: ["nikto"],
      phase: "nikto",
      label: "Nikto-class path database",
      run: () => checkNiktoPaths(normalized),
    },
    {
      checks: ["api"],
      phase: "api",
      label: "API & debug surface",
      run: () => checkApiSurface(normalized),
    },
    {
      checks: ["graphql"],
      phase: "graphql",
      label: "GraphQL introspection",
      run: () => checkGraphql(normalized),
    },
    {
      checks: ["graphql-fuzz"],
      phase: "graphql-fuzz",
      label: "GraphQL active fuzz",
      skipMessage: scanOptions.mode === "fast" ? "Fast mode — skipping GraphQL fuzz" : undefined,
      run: async () => {
        if (scanOptions.mode === "fast") return [];
        const result = await checkGraphqlFuzz(normalized, { fetchFn: fetchTarget });
        return { findings: result.findings, note: result.endpoint ? `Probed ${result.endpoint}` : "No endpoint" };
      },
    },
    {
      checks: ["jwt"],
      phase: "jwt",
      label: "JWT / Bearer auth tests",
      run: async () => {
        const jwtFindings = await checkJwtAuth(normalized, {
          fetchFn: fetchTarget,
          authHeaders: scanOptions.authHeaders,
          bearerToken: scanOptions.authHeaders?.Authorization,
        });
        return jwtFindings;
      },
    },
    {
      checks: ["redirects"],
      phase: "redirects",
      label: "Redirect analysis",
      run: () => checkRedirects(normalized, {
        hstsHeader: res.headers.get("strict-transport-security"),
      }),
    },
    {
      checks: ["content"],
      phase: "content",
      label: "Content & secret exposure",
      run: () => checkContentSecurity(normalized, body, res.headers),
    },
    {
      checks: ["dns"],
      phase: "dns",
      label: "DNS email security",
      run: () => checkDnsEmail(normalized),
    },
    {
      checks: ["injection"],
      phase: "injection",
      label: "Host header injection",
      run: () => checkHostInjection(normalized),
    },
    {
      checks: ["crlf"],
      phase: "crlf",
      label: "CRLF header injection",
      run: () => checkCrlfInjection(normalized),
    },
    {
      checks: ["clickjacking"],
      phase: "clickjacking",
      label: "Clickjacking protection",
      run: () => checkClickjacking(res.headers),
    },
    {
      checks: ["cache"],
      phase: "cache",
      label: "Cache policy",
      run: () => checkCachePolicy(res.headers, mainResponse.url || normalized),
    },
    {
      checks: ["transport"],
      phase: "transport",
      label: "Transport security",
      run: () => checkTransportSecurity(normalized, body, res.headers),
    },
    {
      checks: ["cross-domain"],
      phase: "cross-domain",
      label: "Cross-domain policy files",
      run: () => checkCrossDomainPolicy(normalized),
    },
    {
      checks: ["forms"],
      phase: "forms",
      label: "Form & CSRF analysis",
      run: () => checkFormSecurity(body),
    },
    {
      checks: ["errors"],
      phase: "errors",
      label: "Verbose error disclosure",
      run: () => checkErrorDisclosure(normalized, fetchTarget),
    },
    {
      checks: ["listing"],
      phase: "listing",
      label: "Directory listing",
      run: () => checkDirectoryListing(normalized),
    },
    {
      checks: ["backup"],
      phase: "backup",
      label: "Backup file discovery",
      run: () => checkBackupDiscovery(normalized),
    },
    {
      checks: ["default-pages"],
      phase: "default-pages",
      label: "Default install pages",
      run: () => checkDefaultPages(normalized, res.headers),
    },
    {
      checks: ["recon"],
      phase: "recon",
      label: "Reconnaissance",
      run: () => checkRecon(normalized, body, res.headers),
    },
    {
      checks: ["source-maps"],
      phase: "source-maps",
      label: "JavaScript source maps",
      run: () => checkSourceMaps(normalized, body),
    },
    {
      checks: ["security-txt"],
      phase: "security-txt",
      label: "security.txt audit",
      run: () => checkSecurityTxt(normalized),
    },
    {
      checks: ["reflection"],
      phase: "reflection",
      label: "Input reflection (XSS)",
      run: () => checkInputReflection(normalized),
    },
    {
      checks: ["dns-security"],
      phase: "dns-security",
      label: "DNS infrastructure",
      run: () => checkDnsSecurity(normalized),
    },
    {
      checks: ["technology"],
      phase: "technology",
      label: "Technology fingerprint",
      run: async () => {
        const techFindings = await checkTechnology(normalized, body, res.headers);
        const techFinding = techFindings.find((f) => f.id === "tech-detected");
        const cveFindings = techFinding
          ? checkCveMatches(extractTechnologiesFromFinding(techFinding))
          : [];
        return [...techFindings, ...cveFindings];
      },
    },
    {
      checks: ["templates"],
      phase: "templates",
      label: "Nuclei-style templates",
      skipMessage: scanOptions.mode === "fast" ? "Fast mode — skipping template engine" : undefined,
      run: async () => {
        if (scanOptions.mode === "fast") return [];
        const result = await runTemplateScan(normalized, { fetchFn: fetchTarget });
        return { findings: result.findings, note: `${result.templatesMatched}/${result.templatesRun} matched` };
      },
    },
    {
      checks: ["nuclei"],
      phase: "nuclei",
      label: "Nuclei template runner",
      skipMessage: scanOptions.mode === "fast" ? "Fast mode — skipping Nuclei" : undefined,
      run: async () => {
        if (scanOptions.mode === "fast") return [];
        const result = await runNucleiScan(normalized, { fetchFn: fetchTarget });
        return { findings: result.findings, note: `${result.templatesRun} templates (${result.source})` };
      },
    },
    {
      checks: ["js-endpoints"],
      phase: "js-endpoints",
      label: "JavaScript API discovery",
      skipMessage: scanOptions.mode === "fast" ? "Fast mode — skipping JS endpoint mining" : undefined,
      run: async () => {
        if (scanOptions.mode === "fast") return [];
        const result = await checkJsEndpoints(crawlData, { fetchFn: fetchTarget });
        discoveredAssets.endpoints = [...new Set([...discoveredAssets.endpoints, ...result.endpoints])];
        return { findings: result.findings, note: `${result.endpoints?.length || 0} endpoint(s)` };
      },
    },
    {
      checks: ["active"],
      phase: "active",
      label: "Active injection probes",
      skipMessage: scanOptions.mode === "fast" ? "Fast mode — skipping active probes" : undefined,
      run: async () => {
        if (scanOptions.mode === "fast") return [];
        const attackSurface = {
          params: crawlData.params,
          forms: crawlData.forms,
        };
        if (!attackSurface.params.length && !attackSurface.forms.length) {
          return [{
            id: "active-no-params",
            severity: "info",
            category: "active",
            title: "No injectable parameters discovered",
            description: "Spider did not find query parameters or forms to probe. Try authenticated deep scan.",
            evidence: `${crawlData.pages.length} page(s) crawled`,
            remediation: "Provide session cookie auth and ensure the app exposes forms or query strings.",
          }];
        }
        const result = await checkActiveProbes(attackSurface, {
          fetchFn: fetchTarget,
          maxProbes: scanOptions.maxProbes || 64,
          oastBaseUrl: scanOptions.oastBaseUrl,
          oastToken,
        });
        return { findings: result.findings, note: `${result.probesSent} probes on ${result.parametersTested} params` };
      },
    },
    {
      checks: ["multipage"],
      phase: "multipage",
      label: "Multi-page passive scan",
      skipMessage: crawlData.pages.length <= 1 ? "Single page — skipping multi-page scan" : undefined,
      run: async () => {
        if (crawlData.pages.length <= 1) return [];
        const pageFindings = [];
        for (const page of crawlData.pages.slice(0, 15)) {
          pageFindings.push(...scanPageSurface(page, normalized));
        }
        pageFindings.push(...await scanPagesReflection(crawlData.pages, normalized, fetchTarget));
        return pageFindings;
      },
    },
    {
      checks: ["openapi"],
      phase: "openapi",
      label: "OpenAPI fuzzing",
      skipMessage: !scanOptions.openapiFuzz || scanOptions.mode === "fast" ? "Skipped — enable in Standard/Aggressive profile" : undefined,
      run: async () => {
        if (!scanOptions.openapiFuzz || scanOptions.mode === "fast") return [];
        let spec = scanOptions.openApiSpec;
        if (!spec) {
          try {
            const origin = new URL(normalized).origin;
            for (const path of ["/openapi.json", "/swagger.json", "/api/openapi.json"]) {
              const { res, body } = await fetchTarget(`${origin}${path}`, { timeout: 8000 });
              if (res.status === 200 && body.trim().startsWith("{")) {
                spec = body;
                break;
              }
            }
          } catch {
            /* skip */
          }
        }
        if (!spec) return [];
        const { operations, title } = await loadOpenApiSpec(spec, normalized);
        discoveredAssets.openApi = { title, operations: operations.length };
        const result = await fuzzOpenApiOperations(operations, {
          fetchFn: fetchTarget,
          oastBaseUrl: scanOptions.oastBaseUrl,
          oastToken,
        });
        return { findings: result.findings, note: `${result.operationsTested} API operation(s)` };
      },
    },
    {
      checks: ["subdomains"],
      phase: "subdomains",
      label: "Subdomain discovery",
      run: async () => {
        const result = await checkSubdomains(normalized);
        discoveredAssets.subdomains = result.subdomains;
        return { findings: result.findings, note: `${result.subdomains.length} subdomain(s) found` };
      },
    },
    {
      checks: ["hidden-domains"],
      phase: "hidden-domains",
      label: "Hidden domain mapping",
      run: () => {
        const result = checkHiddenDomains(normalized, body, res.headers);
        discoveredAssets.hiddenDomains = result.hiddenDomains;
        return { findings: result.findings, note: `${result.hiddenDomains.length} domain reference(s)` };
      },
    },
  ];

  const total = runners.length;
  let step = 0;

  for (const runner of runners) {
    step += 1;
    log("info", runner.phase, `[${step}/${total}] Running ${runner.label}…`, {
      progress: { current: step - 1, total },
    });

    const moduleT0 = Date.now();
    try {
      const result = await runner.run();
      let moduleFindings = [];
      let note = "";

      if (Array.isArray(result)) {
        moduleFindings = result;
        if (moduleFindings.length === 0 && runner.skipMessage) {
          checksRun.push(...runner.checks);
          log("info", runner.phase, runner.skipMessage, {
            progress: { current: step, total },
            durationMs: Date.now() - moduleT0,
          });
          continue;
        }
      } else if (result?.findings) {
        moduleFindings = result.findings;
        note = result.note ? `, ${result.note}` : "";
      }

      if (moduleFindings.length > 0 || runner.checks.some((c) => !["cookies"].includes(c))) {
        checksRun.push(...runner.checks);
      }

      findings.push(...moduleFindings);

      const durationMs = Date.now() - moduleT0;
      log("success", runner.phase, `Done — ${moduleFindings.length} finding(s)${note} (${formatMs(durationMs)})`, {
        progress: { current: step, total },
        findings: moduleFindings.length,
        durationMs,
      });
    } catch (err) {
      checksRun.push(...runner.checks);
      log("warn", runner.phase, `Module error: ${err.message}`, {
        progress: { current: step, total },
      });
      findings.push({
        id: `check-error-${runner.phase}`,
        severity: "info",
        category: "scanner",
        title: "Check module error",
        description: err.message,
        evidence: runner.phase,
        remediation: "Retry the scan or inspect server logs.",
      });
    }
  }

  if (scanOptions.oast && oastGetHits) {
    log("info", "oast", "Waiting for blind callbacks…");
    await waitForOastCallbacks(scanOptions.oastWaitMs || 2500);
    const hits = oastGetHits();
    if (hits.length > 0) {
      checksRun.push("oast");
      for (const [i, hit] of hits.entries()) {
        findings.push({
          id: `oast-callback-${i}`,
          severity: "high",
          category: "oast",
          title: "Blind callback received (OAST)",
          description: `Target invoked an out-of-band callback (${hit.probe || "unknown probe"}). Possible blind SSRF, XSS, or XXE.`,
          evidence: hit.url || JSON.stringify(hit),
          remediation: "Investigate the parameter that triggered the external request.",
        });
      }
    } else {
      findings.push({
        id: "oast-clean",
        severity: "info",
        category: "oast",
        title: "OAST probes sent — no callbacks received",
        description: "Out-of-band payloads were injected; no blind callbacks detected during scan.",
        evidence: oastToken ? `Token: ${oastToken}` : "OAST enabled",
        remediation: "No action required.",
      });
      checksRun.push("oast");
    }
  }

  findings.push({
    id: "scan-baseline",
    severity: res.status >= 400 ? "medium" : "info",
    category: "scanner",
    title: `Target responded HTTP ${res.status}`,
    description: `Final URL: ${mainResponse.url}`,
    evidence: `Status: ${res.status}, content-type: ${res.headers.get("content-type") || "unknown"}`,
    remediation: res.status >= 400 ? "Investigate error responses exposed to clients." : "Baseline response captured.",
  });

  log("info", "finalize", "Discovering favicon…");
  const faviconUrl = await discoverFaviconUrl(body, mainResponse.url || normalized);
  log("info", "finalize", faviconUrl ? "Favicon captured" : "No favicon found");

  const finishedAt = new Date().toISOString();
  const durationMs = Date.now() - t0;
  const summary = summarize(findings);

  log("success", "complete", `Scan complete — ${findings.length} findings (${formatMs(durationMs)})`, {
    progress: { current: total, total },
    summary,
  });

  return {
    targetUrl: normalized,
    faviconUrl,
    status: "completed",
    startedAt,
    finishedAt,
    durationMs,
    scanMode: scanOptions.mode,
    scanProfile: scanOptions.profile,
    scanOptions: {
      ...scanOptions,
      authCookie: scanOptions.authCookie ? "[redacted]" : "",
      authProfile: scanOptions.authProfile ? { ...scanOptions.authProfile, credentials: "[redacted]" } : null,
      openApiSpec: scanOptions.openApiSpec ? "[stored]" : null,
    },
    checksRun: [...new Set(checksRun)],
    findings,
    discoveredAssets,
    summary,
    logs,
  };
  } finally {
    clearScanAuth();
  }
}
