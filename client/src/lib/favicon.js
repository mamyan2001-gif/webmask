export function faviconUrlFromTarget(targetUrl) {
  if (!targetUrl?.trim()) return null;
  try {
    const withProto = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;
    return new URL("/favicon.ico", new URL(withProto).origin).href;
  } catch {
    return null;
  }
}

export function faviconCandidates(targetUrl, storedUrl) {
  const candidates = [];
  const seen = new Set();
  for (const url of [storedUrl, faviconUrlFromTarget(targetUrl)]) {
    if (url && !seen.has(url)) {
      seen.add(url);
      candidates.push(url);
    }
  }
  return candidates;
}
