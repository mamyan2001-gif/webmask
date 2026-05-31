function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function reportToHtml(report) {
  const rows = (report.findings || []).map((f) => `
    <tr class="sev-${esc(f.severity)}">
      <td>${esc(f.severity)}</td>
      <td>${esc(f.category)}</td>
      <td>${esc(f.title)}</td>
      <td>${esc(f.description)}</td>
      <td><code>${esc(f.evidence)}</code></td>
    </tr>`).join("");

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>WebMask Report — ${esc(report.targetUrl)}</title>
<style>
body{font-family:system-ui,sans-serif;background:#0a0a0f;color:#eee;padding:32px}
h1{margin:0 0 8px} .meta{color:#999;margin-bottom:24px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{border:1px solid #333;padding:8px;text-align:left;vertical-align:top}
th{background:#151520}.sev-critical td:first-child{color:#f87171;font-weight:700}
.sev-high td:first-child{color:#fb923c}.sev-medium td:first-child{color:#fbbf24}
</style></head><body>
<h1>WebMask Scan Report</h1>
<p class="meta">${esc(report.targetUrl)} · Scan #${report.scanNumber} · ${esc(report.finishedAt)} · Profile: ${esc(report.scanOptions?.profile || report.scanMode)}</p>
<p class="meta">Critical: ${report.summary?.critical || 0} · High: ${report.summary?.high || 0} · Medium: ${report.summary?.medium || 0}</p>
<table><thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Evidence</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;
}

export function reportToCsv(report) {
  const header = ["severity", "category", "title", "description", "evidence", "pageUrl", "remediation"];
  const lines = [header.join(",")];
  for (const f of report.findings || []) {
    lines.push(header.map((k) => `"${String(f[k] || "").replace(/"/g, '""')}"`).join(","));
  }
  return lines.join("\n");
}
