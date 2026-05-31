import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { fetchTarget } from "../utils/http.js";
import { isGenericSpaOrHomepage } from "../utils/validation.js";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function nucleiAvailable() {
  try {
    await execFileAsync("nuclei", ["-version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function mapNucleiSeverity(sev) {
  const s = (sev || "info").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(s)) return s;
  return "info";
}

export async function runNucleiCli(targetUrl, options = {}) {
  const available = await nucleiAvailable();
  if (!available) {
    return {
      findings: [{
        id: "nuclei-cli-missing",
        severity: "info",
        category: "nuclei",
        title: "Nuclei CLI not installed",
        description: "Install nuclei (https://github.com/projectdiscovery/nuclei) for community template coverage.",
        evidence: "nuclei command not found in PATH",
        remediation: "brew install nuclei or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
      }],
      templatesRun: 0,
      source: "cli",
      skipped: true,
    };
  }

  const args = [
    "-u", targetUrl,
    "-jsonl",
    "-silent",
    "-severity", options.severity || "critical,high,medium,low",
    "-timeout", "8",
  ];

  if (options.templatesDir) {
    args.push("-t", options.templatesDir);
  } else {
    args.push("-tags", options.tags || "cve,misconfig,exposure");
  }

  try {
    const { stdout } = await execFileAsync("nuclei", args, {
      timeout: options.timeoutMs || 120000,
      maxBuffer: 10 * 1024 * 1024,
    });

    const findings = [];
    for (const line of stdout.split("\n")) {
      if (!line.trim()) continue;
      let row;
      try {
        row = JSON.parse(line);
      } catch {
        continue;
      }
      findings.push({
        id: `nuclei-${row["template-id"] || row.templateID || "hit"}`,
        severity: mapNucleiSeverity(row.info?.severity || row.severity),
        category: "nuclei",
        title: row.info?.name || row["template-id"] || "Nuclei template match",
        description: row.info?.description || "Community Nuclei template matched.",
        evidence: `${row.host || targetUrl} → ${row["matched-at"] || row.matched || ""}`.trim(),
        remediation: "Review Nuclei template reference and patch affected component.",
        templateId: row["template-id"] || row.templateID,
      });
    }

    if (findings.length === 0) {
      findings.push({
        id: "nuclei-cli-clean",
        severity: "info",
        category: "nuclei",
        title: "Nuclei CLI scan completed",
        description: "No matches from selected Nuclei templates.",
        evidence: targetUrl,
        remediation: "No action required.",
      });
    }

    return { findings, templatesRun: findings.length, source: "cli", skipped: false };
  } catch (err) {
    return {
      findings: [{
        id: "nuclei-cli-error",
        severity: "info",
        category: "nuclei",
        title: "Nuclei CLI run failed",
        description: err.message,
        evidence: targetUrl,
        remediation: "Check nuclei installation and template path.",
      }],
      templatesRun: 0,
      source: "cli",
      skipped: true,
    };
  }
}

export async function runBundledYamlTemplates(baseUrl, options = {}) {
  const fetchFn = options.fetchFn || fetchTarget;
  const dir = path.join(__dirname, "templates");
  let files = [];
  try {
    files = (await fs.readdir(dir)).filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"));
  } catch {
    return { findings: [], templatesRun: 0, source: "yaml" };
  }

  const origin = new URL(baseUrl).origin;
  const findings = [];
  let matched = 0;

  for (const file of files.slice(0, 30)) {
    const raw = await fs.readFile(path.join(dir, file), "utf8");
    const idMatch = raw.match(/^id:\s*(.+)$/m);
    const pathMatch = raw.match(/^\s+-\s+(.+)$/m);
    const wordMatch = raw.match(/words:\s*\n((?:\s+-\s+.+\n)+)/);
    const severityMatch = raw.match(/severity:\s*(\w+)/);

    const tplId = idMatch?.[1]?.trim() || file.replace(/\.\w+$/, "");
    const tplPath = pathMatch?.[1]?.trim() || "/";
    const words = [...(wordMatch?.[1]?.matchAll(/-\s*['"]?([^'"\n]+)/g) || [])].map((m) => m[1]);
    const url = `${origin}${tplPath.startsWith("/") ? tplPath : `/${tplPath}`}`;

    try {
      const { res, body } = await fetchFn(url, { followRedirects: false, timeout: 8000 });
      if (isGenericSpaOrHomepage(body)) continue;
      if (words.length && words.every((w) => body.includes(w))) {
        matched += 1;
        findings.push({
          id: `nuclei-yaml-${tplId}`,
          severity: severityMatch?.[1]?.toLowerCase() || "medium",
          category: "nuclei",
          title: tplId.replace(/-/g, " "),
          description: "Bundled YAML Nuclei-style template matched.",
          evidence: `${url} → HTTP ${res.status}`,
          remediation: "Restrict or remove exposed resource.",
          templateId: tplId,
        });
      }
    } catch {
      /* skip */
    }
  }

  return { findings, templatesRun: files.length, templatesMatched: matched, source: "yaml" };
}

export async function runNucleiScan(targetUrl, options = {}) {
  const cli = await runNucleiCli(targetUrl, options);
  if (!cli.skipped && cli.findings.some((f) => f.category === "nuclei" && !f.id.includes("clean"))) {
    return cli;
  }
  const yaml = await runBundledYamlTemplates(targetUrl, options);
  const findings = [
    ...cli.findings.filter((f) => !f.id.includes("clean") && !f.id.includes("missing")),
    ...yaml.findings,
  ];
  if (findings.length === 0) {
    findings.push({
      id: "nuclei-combined-clean",
      severity: "info",
      category: "nuclei",
      title: "Nuclei scan completed",
      description: cli.skipped
        ? "Bundled YAML templates checked; install nuclei CLI for full community coverage."
        : "CLI and bundled templates checked without matches.",
      evidence: targetUrl,
      remediation: "No action required.",
    });
  }
  return {
    findings,
    templatesRun: (cli.templatesRun || 0) + (yaml.templatesRun || 0),
    source: cli.skipped ? "yaml" : "cli+yaml",
  };
}
