import { fetchTarget, setScanAuth, clearScanAuth } from "../utils/http.js";
import { normalizeTargetUrl, assertSafeTarget } from "../utils/url.js";

function interpolate(value, credentials = {}) {
  if (typeof value !== "string") return value;
  return value.replace(/\{\{(\w+)\}\}/g, (_, key) => credentials[key] ?? "");
}

async function validateAuthUrl(url, credentials = {}) {
  const resolved = interpolate(url, credentials);
  const normalized = normalizeTargetUrl(resolved);
  await assertSafeTarget(normalized);
  return normalized;
}

export async function runAuthProfile(profile, options = {}) {
  if (!profile?.steps?.length) {
    return { cookies: "", headers: {} };
  }

  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    throw new Error("Playwright is required for auth profiles. Run: npx playwright install chromium");
  }

  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent: "WebMask-SecurityScanner/4.0 (+authorized-testing)",
    ignoreHTTPSErrors: false,
  });
  const page = await context.newPage();
  const creds = profile.credentials || {};
  const applyAuth = options.applyAuth !== false;

  try {
    const loginUrl = await validateAuthUrl(profile.loginUrl, creds);
    await page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: 20000 });

    for (const step of profile.steps) {
      const action = step.action;
      if (action === "fill") {
        await page.fill(step.selector, interpolate(step.value, creds), { timeout: 8000 });
      } else if (action === "click") {
        await page.click(step.selector, { timeout: 8000 });
      } else if (action === "wait") {
        await page.waitForTimeout(step.ms || 1000);
      } else if (action === "waitForSelector") {
        await page.waitForSelector(step.selector, { timeout: step.timeout || 10000 });
      } else if (action === "goto") {
        const stepUrl = await validateAuthUrl(step.url, creds);
        await page.goto(stepUrl, { waitUntil: "domcontentloaded", timeout: 20000 });
      }
    }

    if (profile.successUrlContains) {
      const current = page.url();
      if (!current.includes(profile.successUrlContains)) {
        throw new Error(`Login may have failed — expected URL containing "${profile.successUrlContains}"`);
      }
    }

    const cookies = await context.cookies();
    const cookieHeader = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    const headers = { ...(profile.headers || {}) };

    if (applyAuth) {
      setScanAuth({ authCookie: cookieHeader, authHeaders: headers });
    }

    return {
      cookies: cookieHeader,
      headers,
      finalUrl: page.url(),
      cookieCount: cookies.length,
    };
  } finally {
    await browser.close();
  }
}

export async function testAuthProfile(profile) {
  try {
    return await runAuthProfile(profile, { applyAuth: false });
  } finally {
    clearScanAuth();
  }
}
