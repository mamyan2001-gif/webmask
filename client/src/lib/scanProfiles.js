export const PROFILE_META = {
  quick: {
    duration: "~30 sec",
    intensity: "Light",
    shortLabel: "Passive only",
    runHint: "Headers, TLS, cookies",
  },
  standard: {
    duration: "5–15 min",
    intensity: "Balanced",
    shortLabel: "Crawl + probes",
    runHint: "Spider, OAST, API fuzz",
  },
  aggressive: {
    duration: "15–45 min",
    intensity: "Deep",
    shortLabel: "Max coverage",
    runHint: "Playwright + 128 probes",
  },
};

export const FALLBACK_PROFILES = [
  { id: "quick", label: "Quick", description: "Passive checks only — ~30 seconds" },
  { id: "standard", label: "Standard", description: "Deep scan with fetch spider, templates, and active probes" },
  { id: "aggressive", label: "Aggressive", description: "Playwright spider, max coverage, OAST, and API fuzzing" },
];

export function getProfileMeta(id) {
  return PROFILE_META[id] || PROFILE_META.standard;
}

export function mergeProfiles(apiProfiles) {
  const list = apiProfiles?.length ? apiProfiles : FALLBACK_PROFILES;
  return list.map((p) => ({
    ...p,
    meta: getProfileMeta(p.id),
  }));
}
