export function hostMatchesPattern(hostname, pattern) {
  const p = pattern.trim().toLowerCase();
  const h = hostname.toLowerCase();
  if (!p) return false;
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h === base || h.endsWith(`.${base}`);
  }
  return h === p;
}

export function normalizeScopeRules(rules = {}) {
  return {
    allowedHosts: (rules.allowedHosts || []).map((h) => h.trim()).filter(Boolean),
    deniedPaths: (rules.deniedPaths || []).map((p) => p.trim()).filter(Boolean),
    allowedPaths: (rules.allowedPaths || []).map((p) => p.trim()).filter(Boolean),
  };
}

export function isUrlInScope(urlString, baseUrl, scopeRules = {}) {
  try {
    const url = new URL(urlString);
    const base = new URL(baseUrl);
    const scope = normalizeScopeRules(scopeRules);

    if (scope.allowedHosts.length > 0) {
      if (!scope.allowedHosts.some((p) => hostMatchesPattern(url.hostname, p))) {
        return false;
      }
    } else if (url.hostname !== base.hostname && !url.hostname.endsWith(`.${base.hostname}`)) {
      return false;
    }

    const path = url.pathname || "/";
    if (scope.deniedPaths.some((denied) => path.startsWith(denied))) {
      return false;
    }
    if (scope.allowedPaths.length > 0) {
      return scope.allowedPaths.some((allowed) => path.startsWith(allowed));
    }
    return true;
  } catch {
    return false;
  }
}

export function filterUrlsInScope(urls, baseUrl, scopeRules) {
  return urls.filter((u) => isUrlInScope(u, baseUrl, scopeRules));
}
