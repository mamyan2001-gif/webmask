const SKIP_EXTENSIONS = /\.(png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|eot|mp4|mp3|zip|pdf|dmg)(\?|#|$)/i;

export function isScannableUrl(href, baseOrigin) {
  if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) {
    return false;
  }
  try {
    const url = new URL(href, baseOrigin);
    if (!["http:", "https:"].includes(url.protocol)) return false;
    if (url.origin !== baseOrigin) return false;
    if (SKIP_EXTENSIONS.test(url.pathname)) return false;
    return true;
  } catch {
    return false;
  }
}

export function extractLinks(html, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const found = new Set();
  const patterns = [
    /<a\b[^>]+href=["']([^"']+)["']/gi,
    /<form\b[^>]+action=["']([^"']+)["']/gi,
    /<iframe\b[^>]+src=["']([^"']+)["']/gi,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(html || "")) !== null) {
      const href = match[1].trim();
      if (isScannableUrl(href, origin)) {
        found.add(new URL(href, baseUrl).href.replace(/\/$/, "") || new URL(href, baseUrl).origin);
      }
    }
  }
  return [...found];
}

export function extractForms(html, pageUrl) {
  const forms = [];
  const blocks = [...(html || "").matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)];
  for (const block of blocks) {
    const tag = block[0];
    const inner = block[1] || "";
    const method = (tag.match(/\bmethod=["']?(\w+)["']?/i)?.[1] || "get").toLowerCase();
    const action = tag.match(/\baction=["']([^"']*)["']/i)?.[1] || pageUrl;
    let actionUrl;
    try {
      actionUrl = new URL(action, pageUrl).href;
    } catch {
      continue;
    }
    const inputs = [...inner.matchAll(/<input\b[^>]*>/gi)].map((m) => {
      const el = m[0];
      return {
        name: el.match(/\bname=["']([^"']+)["']/i)?.[1] || "",
        type: (el.match(/\btype=["']([^"']+)["']/i)?.[1] || "text").toLowerCase(),
      };
    }).filter((i) => i.name && !["submit", "button", "image", "reset"].includes(i.type));
    if (inputs.length) forms.push({ action: actionUrl, method, inputs, pageUrl });
  }
  return forms;
}

export function extractScriptUrls(html, pageUrl) {
  const origin = new URL(pageUrl).origin;
  const urls = [];
  for (const match of (html || "").matchAll(/<script\b[^>]+src=["']([^"']+)["']/gi)) {
    try {
      const url = new URL(match[1], pageUrl);
      if (url.origin === origin) urls.push(url.href);
    } catch {
      /* skip */
    }
  }
  return urls;
}

const JS_ENDPOINT_PATTERNS = [
  /["'](\/api\/[^"'`\s]+)["']/gi,
  /["'](\/v\d+\/[^"'`\s]+)["']/gi,
  /fetch\s*\(\s*["']([^"']+)["']/gi,
  /axios\.(?:get|post|put|delete)\s*\(\s*["']([^"']+)["']/gi,
  /["']https?:\/\/[^"']+\/graphql["']/gi,
];

export function extractJsEndpoints(source, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const found = new Set();
  for (const pattern of JS_ENDPOINT_PATTERNS) {
    let match;
    while ((match = pattern.exec(source || "")) !== null) {
      const raw = match[1] || match[0].replace(/["']/g, "");
      try {
        const url = new URL(raw, baseUrl);
        if (url.origin === origin) found.add(url.href.split("?")[0]);
      } catch {
        if (raw.startsWith("/")) found.add(`${origin}${raw.split("?")[0]}`);
      }
    }
  }
  return [...found];
}

export function extractQueryParams(pageUrl) {
  const url = new URL(pageUrl);
  const params = [];
  for (const [name] of url.searchParams) {
    params.push({ pageUrl, name, baseUrl: `${url.origin}${url.pathname}` });
  }
  return params;
}
