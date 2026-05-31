import { URL } from "url";
import { fetchTarget } from "./http.js";

function resolveHref(href, base) {
  try {
    return new URL(href, base).href;
  } catch {
    return null;
  }
}

function collectCandidates(html, pageUrl) {
  const base = new URL(pageUrl);
  const seen = new Set();
  const candidates = [];

  function add(url) {
    if (!url || seen.has(url)) return;
    seen.add(url);
    candidates.push(url);
  }

  const linkTags = html.match(/<link\b[^>]*>/gi) || [];
  for (const tag of linkTags) {
    const rel = tag.match(/\brel=["']([^"']+)["']/i)?.[1]?.toLowerCase() || "";
    if (!/(^|\s)(shortcut\s+icon|icon|apple-touch-icon)(\s|$)/.test(rel)) continue;
    const href = tag.match(/\bhref=["']([^"']+)["']/i)?.[1];
    add(resolveHref(href, base));
  }

  add(resolveHref("/favicon.ico", base));
  add(resolveHref("/favicon.png", base));
  add(resolveHref("/apple-touch-icon.png", base));

  return candidates;
}

async function isImageUrl(url) {
  try {
    const { res } = await fetchTarget(url, { method: "HEAD", followRedirects: true, timeout: 8000 });
    if (!res.ok) return false;
    const type = res.headers.get("content-type") || "";
    return type.startsWith("image/") || type.includes("icon");
  } catch {
    return false;
  }
}

export async function discoverFaviconUrl(html, pageUrl) {
  for (const candidate of collectCandidates(html, pageUrl)) {
    if (await isImageUrl(candidate)) {
      return candidate;
    }
  }
  return null;
}

export function faviconUrlFromTarget(targetUrl) {
  if (!targetUrl?.trim()) return null;
  try {
    const withProto = /^https?:\/\//i.test(targetUrl) ? targetUrl : `https://${targetUrl}`;
    return new URL("/favicon.ico", new URL(withProto).origin).href;
  } catch {
    return null;
  }
}
