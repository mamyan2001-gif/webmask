export function normalizeOastBaseUrl(url) {
  if (!url?.trim()) return "";
  return url.trim().replace(/\/+$/, "");
}

export function isLocalOastUrl(url) {
  if (!url) return true;
  try {
    const host = new URL(url).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  } catch {
    return true;
  }
}

export function buildOastCallbackUrl(baseUrl, token, params = {}) {
  const base = normalizeOastBaseUrl(baseUrl);
  const query = new URLSearchParams(params).toString();
  return `${base}/oast/${token}${query ? `?${query}` : ""}`;
}

export function validateOastConfig(publicBaseUrl, targetUrl) {
  const base = normalizeOastBaseUrl(publicBaseUrl);
  const warnings = [];
  const errors = [];

  if (!base) {
    warnings.push("No OAST public URL configured — blind callbacks only work on same-machine tests.");
    return { ok: false, base: "", warnings, errors, remoteReady: false };
  }

  try {
    const parsed = new URL(base);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      errors.push("OAST public URL must use http or https.");
    }
  } catch {
    errors.push("OAST public URL is not a valid URL.");
    return { ok: false, base, warnings, errors, remoteReady: false };
  }

  const local = isLocalOastUrl(base);
  if (local) {
    warnings.push("OAST URL points to localhost — remote targets cannot reach it. Use ngrok or cloudflared and paste the public URL.");
  }

  if (targetUrl && !local) {
    try {
      const targetHost = new URL(targetUrl).hostname;
      const oastHost = new URL(base).hostname;
      if (targetHost === oastHost) {
        warnings.push("OAST host matches target host — some apps block self-callbacks.");
      }
    } catch {
      /* skip */
    }
  }

  return {
    ok: errors.length === 0,
    base,
    warnings,
    errors,
    remoteReady: !local && errors.length === 0,
  };
}

export async function waitForOastCallbacks(ms = 2500) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
