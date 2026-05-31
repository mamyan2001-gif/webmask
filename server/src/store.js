import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, "../..");
export const REPORTS_DIR = path.join(ROOT, "reports");
export const DATA_DIR = path.join(ROOT, "server", "data");
export const SITES_FILE = path.join(DATA_DIR, "sites.json");
export const SCANNER_SETTINGS_FILE = path.join(DATA_DIR, "scanner-settings.json");

export function defaultSiteConfig() {
  return {
    url: "",
    faviconUrl: null,
    authCookie: "",
    authBearer: "",
    authApiKey: "",
    authApiKeyHeader: "X-API-Key",
    authHeaders: {},
    authProfile: null,
    openApiSpec: null,
    seedUrls: [],
    scopeRules: { allowedHosts: [], deniedPaths: [], allowedPaths: [] },
    scanRoles: [],
    scanOptions: {
      profile: "standard",
      mode: "deep",
      maxDepth: 3,
      maxPages: 40,
      maxConcurrency: 6,
    },
  };
}

export async function ensureDirs() {
  await fs.mkdir(REPORTS_DIR, { recursive: true });
  await fs.mkdir(DATA_DIR, { recursive: true });
}

export async function loadSites() {
  await ensureDirs();
  try {
    const raw = await fs.readFile(SITES_FILE, "utf8");
    const data = JSON.parse(raw);
    for (const site of data.sites || []) {
      site.scans = site.scans || site.builds || [];
      site.scanCount = site.scanCount ?? site.buildCount ?? site.scans.length;
      delete site.builds;
      delete site.buildCount;
      delete site.lastDeploy;
      if (site.config && !site.config.url && site.config.customHtml) {
        site.config = { url: "" };
      }
    }
    return data;
  } catch {
    return { sites: [] };
  }
}

export async function saveSites(data) {
  await ensureDirs();
  await fs.writeFile(SITES_FILE, JSON.stringify(data, null, 2), "utf8");
}
