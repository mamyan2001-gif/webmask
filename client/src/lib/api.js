const BASE = "";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || res.statusText);
    if (data.logs) err.logs = data.logs;
    throw err;
  }
  return data;
}

async function readNdjsonStream(res, onEvent) {
  if (!res.body) throw new Error("Streaming not supported in this browser");
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let complete = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      onEvent?.(event);
      if (event.type === "complete") complete = event;
      if (event.type === "error") {
        throw new Error(event.error || "Scan failed");
      }
    }
  }

  if (buffer.trim()) {
    try {
      const event = JSON.parse(buffer);
      onEvent?.(event);
      if (event.type === "complete") complete = event;
      if (event.type === "error") throw new Error(event.error || "Scan failed");
    } catch (err) {
      if (!(err instanceof SyntaxError)) throw err;
    }
  }

  if (!complete) throw new Error("Scan ended without a result");
  return complete;
}

export const api = {
  getSetupStatus: () => request("/api/setup/status"),
  getDashboard: () => request("/api/dashboard"),
  getChecks: () => request("/api/checks"),
  getProfiles: () => request("/api/profiles"),
  getSettings: () => request("/api/settings"),
  updateSettings: (body) => request("/api/settings", { method: "PATCH", body: JSON.stringify(body) }),
  getOastStatus: () => request("/api/oast/status"),
  getSchedules: () => request("/api/schedules"),
  createSchedule: (body) => request("/api/schedules", { method: "POST", body: JSON.stringify(body) }),
  deleteSchedule: (id) => request(`/api/schedules/${id}`, { method: "DELETE" }),
  getScanTriage: (siteId, scanId) => request(`/api/sites/${siteId}/scans/${scanId}/triage`),
  installLocal: () => request("/api/setup/install-local", { method: "POST" }),

  getSites: () => request("/api/sites"),
  getSite: (id) => request(`/api/sites/${id}`),
  createSite: (body) => request("/api/sites", { method: "POST", body: JSON.stringify(body) }),
  updateSite: (id, body) => request(`/api/sites/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteSite: (id) => request(`/api/sites/${id}`, { method: "DELETE" }),
  testAuth: (siteId, body) =>
    request(`/api/sites/${siteId}/auth/test`, { method: "POST", body: JSON.stringify(body) }),
  saveOpenApiSpec: (siteId, spec) =>
    request(`/api/sites/${siteId}/openapi`, { method: "POST", body: JSON.stringify({ spec }) }),
  runScan: (id, body) =>
    request(`/api/sites/${id}/scan`, { method: "POST", body: JSON.stringify(body) }),
  runScanStream: async (id, body, { onEvent } = {}) => {
    const res = await fetch(`${BASE}/api/sites/${id}/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/x-ndjson",
      },
      body: JSON.stringify({ ...body, stream: true }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || res.statusText);
    }

    return readNdjsonStream(res, onEvent);
  },
  getScan: (siteId, scanId) => request(`/api/sites/${siteId}/scans/${scanId}`),
  getScanDiff: (siteId, base, compare) =>
    request(`/api/sites/${siteId}/scans/diff?base=${encodeURIComponent(base)}&compare=${encodeURIComponent(compare)}`),
  exportScanUrl: (siteId, scanId, format = "html") =>
    `${BASE}/api/sites/${siteId}/scans/${scanId}/export?format=${format}`,
  setFindingTriage: (siteId, scanId, findingId, body) =>
    request(`/api/sites/${siteId}/scans/${scanId}/findings/${encodeURIComponent(findingId)}/triage`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteScan: (siteId, scanId) =>
    request(`/api/sites/${siteId}/scans/${scanId}`, { method: "DELETE" }),
};
