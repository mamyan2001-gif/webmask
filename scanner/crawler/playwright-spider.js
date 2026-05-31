import {
  extractForms,
  extractJsEndpoints,
  extractLinks,
  extractQueryParams,
  extractScriptUrls,
} from "../utils/parse-html.js";
import { assertSafeTarget } from "../utils/url.js";
import { isUrlInScope } from "../utils/scope.js";

const EMPTY_CRAWL = { pages: [], forms: [], endpoints: [], params: [], scriptUrls: [] };

export async function crawlSiteWithPlaywright(startUrl, options = {}) {
  const opts = {
    maxDepth: 3,
    maxPages: 40,
    concurrency: 4,
    authCookie: "",
    ...options,
  };
  const onLog = options.onLog || (() => {});

  let playwright;
  try {
    playwright = await import("playwright");
  } catch (err) {
    onLog("warn", "crawl", `Playwright unavailable (${err.message}) — using fetch spider`);
    return null;
  }

  await assertSafeTarget(startUrl);

  const origin = new URL(startUrl).origin;
  const scopeRules = options.scopeRules || {};
  const visited = new Set();
  const pages = [];
  const queue = [{ url: new URL(startUrl).href.split("#")[0], depth: 0 }];
  for (const seed of options.seedUrls || []) {
    try {
      const u = new URL(seed, startUrl).href.split("#")[0];
      if (isUrlInScope(u, startUrl, scopeRules)) queue.push({ url: u, depth: 0 });
    } catch {
      /* skip */
    }
  }
  const allForms = [];
  const allEndpoints = new Set();
  const allParams = [];

  onLog("info", "crawl", `Playwright spider — depth ${opts.maxDepth}, max ${opts.maxPages} pages`);

  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "WebMask-SecurityScanner/4.0 (+authorized-testing)",
  });

  if (opts.authCookie) {
    const cookies = opts.authCookie.split(";").map((part) => {
      const [name, ...rest] = part.trim().split("=");
      return name ? { name, value: rest.join("="), url: origin } : null;
    }).filter(Boolean);
    if (cookies.length) await context.addCookies(cookies);
  }

  try {
    while (queue.length > 0 && pages.length < opts.maxPages) {
      const { url, depth } = queue.shift();
      const key = url.split("#")[0];
      if (visited.has(key)) continue;
      visited.add(key);

      const page = await context.newPage();
      try {
        const response = await page.goto(key, { waitUntil: "networkidle", timeout: 15000 });
        const status = response?.status() || 0;
        if (status >= 400) continue;

        const body = await page.content();
        const finalUrl = page.url().split("#")[0];

        pages.push({
          url: finalUrl,
          body,
          status,
          headers: { get: (h) => response?.headers()?.[h.toLowerCase()] },
          depth,
        });

        allParams.push(...extractQueryParams(finalUrl));
        allForms.push(...extractForms(body, finalUrl));
        for (const ep of extractJsEndpoints(body, finalUrl)) allEndpoints.add(ep);

        if (depth < opts.maxDepth) {
          const links = await page.$$eval("a[href]", (els) => els.map((a) => a.href));
          for (const link of [...extractLinks(body, finalUrl), ...links]) {
            try {
              const linkKey = link.split("#")[0];
              if (!visited.has(linkKey) && isUrlInScope(linkKey, startUrl, scopeRules)) {
                queue.push({ url: linkKey, depth: depth + 1 });
              }
            } catch {
              /* skip invalid */
            }
          }
        }
      } catch {
        /* skip page */
      } finally {
        await page.close();
      }

      onLog("info", "crawl", `Playwright crawled ${pages.length} page(s)`);
    }
  } finally {
    await browser.close();
  }

  onLog("success", "crawl", `Playwright complete — ${pages.length} pages, ${allForms.length} forms`);

  return {
    pages,
    forms: allForms,
    endpoints: [...allEndpoints],
    params: allParams,
    scriptUrls: pages.flatMap((p) => extractScriptUrls(p.body, p.url)).slice(0, 40),
    engine: "playwright",
  };
}
