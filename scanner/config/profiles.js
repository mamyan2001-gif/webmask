export const SCAN_PROFILES = {
  quick: {
    id: "quick",
    label: "Quick",
    description: "Passive checks only — ~30 seconds",
    mode: "fast",
    crawl: false,
    spider: "fetch",
    maxDepth: 1,
    maxPages: 1,
    maxConcurrency: 4,
    maxProbes: 0,
    oast: false,
    openapiFuzz: false,
  },
  standard: {
    id: "standard",
    label: "Standard",
    description: "Deep scan with fetch spider, templates, and active probes",
    mode: "deep",
    crawl: true,
    spider: "fetch",
    maxDepth: 3,
    maxPages: 40,
    maxConcurrency: 6,
    maxProbes: 64,
    oast: true,
    openapiFuzz: true,
  },
  aggressive: {
    id: "aggressive",
    label: "Aggressive",
    description: "Playwright spider, max coverage, OAST, and API fuzzing",
    mode: "deep",
    crawl: true,
    spider: "playwright",
    maxDepth: 5,
    maxPages: 120,
    maxConcurrency: 8,
    maxProbes: 128,
    oast: true,
    openapiFuzz: true,
  },
};

export function resolveScanOptions(input = {}) {
  const profileId = input.profile || "standard";
  const profile = SCAN_PROFILES[profileId] || SCAN_PROFILES.standard;
  const mode = input.mode === "fast" || profile.mode === "fast" ? "fast" : "deep";

  return {
    profile: profileId in SCAN_PROFILES ? profileId : "standard",
    mode,
    maxDepth: input.maxDepth ?? profile.maxDepth,
    maxPages: input.maxPages ?? profile.maxPages,
    maxConcurrency: input.maxConcurrency ?? profile.maxConcurrency,
    maxProbes: input.maxProbes ?? profile.maxProbes,
    spider: input.spider ?? profile.spider,
    oast: input.oast ?? profile.oast,
    openapiFuzz: input.openapiFuzz ?? profile.openapiFuzz,
    authCookie: input.authCookie || "",
    authHeaders: input.authHeaders || {},
    authProfile: input.authProfile || null,
    openApiSpec: input.openApiSpec || null,
    oastBaseUrl: input.oastBaseUrl || "",
    seedUrls: input.seedUrls || [],
    scopeRules: input.scopeRules || {},
    crawl: mode === "deep" && (input.crawl ?? profile.crawl) !== false,
  };
}
