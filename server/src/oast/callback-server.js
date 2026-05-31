import { nanoid } from "nanoid";

const tokens = new Map();
let config = { port: 9099, publicBaseUrl: "http://127.0.0.1:9099" };
let server = null;

function recordHit(token, req, parsed) {
  const entry = tokens.get(token);
  if (!entry) return;

  const hit = {
    at: new Date().toISOString(),
    method: req.method,
    url: req.url,
    path: parsed.pathname,
    query: parsed.searchParams ? Object.fromEntries(parsed.searchParams) : {},
    headers: {
      "user-agent": req.headers["user-agent"],
      referer: req.headers.referer,
      host: req.headers.host,
    },
    ip: req.socket.remoteAddress,
    probe: parsed.searchParams?.get("probe") || parsed.searchParams?.get("src") || "unknown",
  };

  entry.hits.push(hit);
}

function handleRequest(req, res) {
  const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);

  if (url.pathname === "/oast/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "webmask-oast", tokens: tokens.size }));
    return;
  }

  const match = url.pathname.match(/^\/oast\/([^/]+)/);
  if (match) {
    recordHit(match[1], req, url);
    res.writeHead(200, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
    res.end("ok");
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
}

export function createOastServer(options = {}) {
  config = {
    port: options.port || config.port,
    publicBaseUrl: (options.publicBaseUrl || config.publicBaseUrl).replace(/\/+$/, ""),
  };

  function registerToken(scanId, meta = {}) {
    const token = nanoid(12);
    tokens.set(token, {
      scanId,
      token,
      meta,
      hits: [],
      createdAt: new Date().toISOString(),
    });
    return {
      token,
      callbackUrl: `${config.publicBaseUrl}/oast/${token}`,
      publicBaseUrl: config.publicBaseUrl,
    };
  }

  function getHits(token) {
    return tokens.get(token)?.hits || [];
  }

  function getHitsForScan(scanId) {
    const hits = [];
    for (const entry of tokens.values()) {
      if (entry.scanId === scanId) hits.push(...entry.hits);
    }
    return hits;
  }

  function getStatus() {
    return {
      port: config.port,
      publicBaseUrl: config.publicBaseUrl,
      activeTokens: tokens.size,
      localUrl: `http://127.0.0.1:${config.port}`,
    };
  }

  function updatePublicBaseUrl(publicBaseUrl) {
    if (publicBaseUrl) {
      config.publicBaseUrl = publicBaseUrl.replace(/\/+$/, "");
    }
    return config.publicBaseUrl;
  }

  async function start() {
    if (server) return getStatus();

    const http = await import("http");
    server = http.createServer(handleRequest);

    await new Promise((resolve, reject) => {
      server.listen(config.port, "127.0.0.1", resolve);
      server.on("error", reject);
    });

    return getStatus();
  }

  async function stop() {
    if (!server) return;
    await new Promise((resolve) => server.close(resolve));
    server = null;
  }

  return {
    start,
    stop,
    registerToken,
    getHits,
    getHitsForScan,
    getStatus,
    updatePublicBaseUrl,
    get publicBaseUrl() {
      return config.publicBaseUrl;
    },
  };
}

let sharedOast = null;

export function getOastServer(options = {}) {
  if (!sharedOast) {
    sharedOast = createOastServer(options);
  } else if (options.publicBaseUrl) {
    sharedOast.updatePublicBaseUrl(options.publicBaseUrl);
  }
  if (options.port && sharedOast.getStatus().port !== options.port) {
    sharedOast = createOastServer(options);
  }
  return sharedOast;
}
