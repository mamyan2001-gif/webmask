import fs from "fs/promises";
import { SCANNER_SETTINGS_FILE, DATA_DIR, ensureDirs } from "./store.js";

const DEFAULT_SETTINGS = {
  oastPort: 9099,
  oastPublicBaseUrl: "http://127.0.0.1:9099",
  webhooks: [],
  slackWebhookUrl: "",
  alertMinSeverity: "high",
};

export async function loadScannerSettings() {
  await ensureDirs();
  try {
    const raw = await fs.readFile(SCANNER_SETTINGS_FILE, "utf8");
    return { ...DEFAULT_SETTINGS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export async function saveScannerSettings(settings) {
  await ensureDirs();
  await fs.writeFile(SCANNER_SETTINGS_FILE, JSON.stringify(settings, null, 2), "utf8");
}

export const SCHEDULES_FILE = `${DATA_DIR}/schedules.json`;
export const TRIAGE_FILE = `${DATA_DIR}/triage.json`;

export async function loadSchedules() {
  await ensureDirs();
  try {
    const raw = await fs.readFile(SCHEDULES_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return { schedules: [] };
  }
}

export async function saveSchedules(data) {
  await ensureDirs();
  await fs.writeFile(SCHEDULES_FILE, JSON.stringify(data, null, 2), "utf8");
}

export async function loadTriage() {
  await ensureDirs();
  try {
    const raw = await fs.readFile(TRIAGE_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return { entries: {} };
  }
}

export async function saveTriage(data) {
  await ensureDirs();
  await fs.writeFile(TRIAGE_FILE, JSON.stringify(data, null, 2), "utf8");
}

export function triageKey(siteId, scanId, findingId, pageUrl = "") {
  return `${siteId}:${scanId}:${findingId}:${pageUrl}`;
}

export function triageMapForScan(siteId, scanId, entries = {}) {
  const prefix = `${siteId}:${scanId}:`;
  const map = {};
  for (const [key, val] of Object.entries(entries)) {
    if (!key.startsWith(prefix)) continue;
    const rest = key.slice(prefix.length);
    const sep = rest.indexOf(":");
    const findingId = sep === -1 ? rest : rest.slice(0, sep);
    map[findingId] = val;
  }
  return map;
}

export function triageDiffMap(entries = {}) {
  const map = {};
  for (const [key, val] of Object.entries(entries)) {
    const parts = key.split(":");
    if (parts.length < 4) continue;
    map[`${parts[2]}|${parts.slice(3).join(":")}`] = val;
  }
  return map;
}
