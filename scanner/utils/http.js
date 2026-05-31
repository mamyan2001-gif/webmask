const DEFAULT_TIMEOUT = 15000;
const DEFAULT_MAX_REDIRECTS = 8;

let activeScanHeaders = {};

export function setScanAuth(options = {}) {
  activeScanHeaders = {};
  if (options.authCookie?.trim()) {
    activeScanHeaders.Cookie = options.authCookie.trim();
  }
  if (options.authHeaders && typeof options.authHeaders === "object") {
    Object.assign(activeScanHeaders, options.authHeaders);
  }
}

export function clearScanAuth() {
  activeScanHeaders = {};
}

async function validateRedirectTarget(url) {
  const { assertSafeTarget } = await import("./url.js");
  await assertSafeTarget(url);
}

export async function fetchTarget(url, options = {}) {
  const follow = options.followRedirects !== false;
  const maxHops = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const method = options.method || "GET";
  let current = url;

  for (let hop = 0; hop <= maxHops; hop++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeout || DEFAULT_TIMEOUT);
    try {
      const res = await fetch(current, {
        method,
        redirect: "manual",
        signal: controller.signal,
        body: options.body,
        headers: {
          "User-Agent": "WebMask-SecurityScanner/4.0 (+authorized-testing)",
          Accept: "text/html,application/xhtml+xml,application/json,*/*",
          ...activeScanHeaders,
          ...options.headers,
        },
      });

      if (
        follow
        && method === "GET"
        && res.status >= 300
        && res.status < 400
        && hop < maxHops
      ) {
        const location = res.headers.get("location");
        if (location) {
          current = new URL(location, current).href;
          if (options.validateRedirects !== false) {
            await validateRedirectTarget(current);
          }
          continue;
        }
      }

      const body = method === "HEAD" ? "" : await res.text().catch(() => "");
      return { res, body, url: current };
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error("Too many redirects");
}

export async function fetchRedirectChain(startUrl, maxHops = 10) {
  const chain = [];
  let current = startUrl;

  for (let i = 0; i < maxHops; i++) {
    const { res } = await fetchTarget(current, {
      followRedirects: false,
      method: "GET",
      timeout: 8000,
      validateRedirects: false,
    });
    const location = res.headers.get("location");
    chain.push({ url: current, status: res.status, location });

    if (res.status >= 300 && res.status < 400 && location) {
      current = new URL(location, current).href;
      await validateRedirectTarget(current);
      continue;
    }
    break;
  }

  return chain;
}
