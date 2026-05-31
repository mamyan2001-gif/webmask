import { summarizeRegression } from "../../../scanner/diff/scan-diff.js";

export async function sendWebhookAlert(settings, { site, scan, regression }) {
  const minRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const threshold = minRank[settings.alertMinSeverity] ?? 3;
  const scanRank = Math.max(
    scan.summary?.critical ? 4 : 0,
    scan.summary?.high ? 3 : 0,
    scan.summary?.medium ? 2 : 0,
  );
  const hasRegression = regression?.summary?.added > 0 || regression?.summary?.regressed > 0;

  if (scanRank < threshold && !hasRegression) return { sent: false, reason: "below threshold" };

  const payload = {
    text: `WebMask scan complete — ${site.name}`,
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*${site.name}* — ${scan.targetUrl}\nFindings: ${scan.findings?.length || scan.findingCount || 0} · Critical: ${scan.summary?.critical || 0} · High: ${scan.summary?.high || 0}${regression ? `\nRegression: ${summarizeRegression(regression)}` : ""}`,
        },
      },
    ],
  };

  const urls = [...(settings.webhooks || [])];
  if (settings.slackWebhookUrl) urls.push(settings.slackWebhookUrl);

  const results = [];
  for (const url of urls) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      results.push({ url, ok: res.ok });
    } catch (err) {
      results.push({ url, ok: false, error: err.message });
    }
  }

  return { sent: results.some((r) => r.ok), results };
}
