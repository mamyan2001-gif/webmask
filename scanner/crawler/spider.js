import { fetchTarget } from "../utils/http.js";
import {
  extractForms,
  extractJsEndpoints,
  extractLinks,
  extractQueryParams,
  extractScriptUrls,
} from "../utils/parse-html.js";
import { isUrlInScope } from "../utils/scope.js";

const DEFAULTS = { maxDepth: 3, maxPages: 40, concurrency: 6 };

function seedQueue(startUrl, seedUrls = [], scopeRules = {}) {
  const normalizedStart = new URL(startUrl).href.split("#")[0];
  const queue = [{ url: normalizedStart, depth: 0 }];
  const seen = new Set([normalizedStart]);

  for (const seed of seedUrls) {
    try {
      const u = new URL(seed, startUrl).href.split("#")[0];
      if (!seen.has(u) && isUrlInScope(u, startUrl, scopeRules)) {
        seen.add(u);
        queue.push({ url: u, depth: 0 });
      }
    } catch {
      /* skip invalid seed */
    }
  }
  return queue;
}

export async function crawlSite(startUrl, options = {}) {
  const opts = { ...DEFAULTS, ...options };
  const fetchFn = options.fetchFn || fetchTarget;
  const onLog = options.onLog || (() => {});
  const scopeRules = options.scopeRules || {};

  const visited = new Set();
  const pages = [];
  const queue = seedQueue(startUrl, options.seedUrls, scopeRules);
  const allForms = [];
  const allEndpoints = new Set();
  const allParams = [];

  onLog("info", "crawl", `Starting spider — max depth ${opts.maxDepth}, max pages ${opts.maxPages}, seeds ${queue.length - 1}`);

  while (queue.length > 0 && pages.length < opts.maxPages) {
    const batch = queue.splice(0, opts.concurrency);

    await Promise.all(
      batch.map(async ({ url, depth }) => {
        const key = url.split("#")[0];
        if (visited.has(key)) return;
        if (!isUrlInScope(key, startUrl, scopeRules)) return;
        visited.add(key);

        try {
          const { res, body } = await fetchFn(key, { timeout: 12000 });
          const finalUrl = (res.url || key).split("#")[0];
          if (res.status >= 400) return;

          pages.push({
            url: finalUrl,
            body: body || "",
            status: res.status,
            headers: res.headers,
            depth,
          });

          allParams.push(...extractQueryParams(finalUrl));
          allForms.push(...extractForms(body, finalUrl));

          for (const endpoint of extractJsEndpoints(body, finalUrl)) {
            allEndpoints.add(endpoint);
          }

          if (depth >= opts.maxDepth) return;

          for (const link of extractLinks(body, finalUrl)) {
            const linkKey = link.split("#")[0];
            if (!visited.has(linkKey) && isUrlInScope(linkKey, startUrl, scopeRules)) {
              queue.push({ url: linkKey, depth: depth + 1 });
            }
          }
        } catch {
          /* skip unreachable page */
        }
      }),
    );

    onLog("info", "crawl", `Crawled ${pages.length} page(s), queue ${queue.length}`, { pages: pages.length });
  }

  onLog("success", "crawl", `Spider complete — ${pages.length} pages, ${allForms.length} forms, ${allEndpoints.size} JS endpoints`);

  return {
    pages,
    forms: allForms,
    endpoints: [...allEndpoints],
    params: allParams,
    scriptUrls: pages.flatMap((p) => extractScriptUrls(p.body, p.url)).slice(0, 40),
    engine: "fetch",
  };
}
