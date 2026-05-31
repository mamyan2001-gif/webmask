import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { ROOT } from "../store.js";

const execFileAsync = promisify(execFile);

export async function installLocalDependencies(log = () => {}) {
  const steps = [];

  async function run(label, cwd, args) {
    log(`${label}…`);
    try {
      const { stdout, stderr } = await execFileAsync("npm", args, {
        cwd,
        maxBuffer: 10 * 1024 * 1024,
        env: { ...process.env, npm_config_loglevel: "error" },
      });
      steps.push({ label, ok: true, output: (stdout || stderr).slice(0, 500) });
      log(`${label} — done`);
    } catch (err) {
      const msg = err.stderr || err.message || "Install failed";
      steps.push({ label, ok: false, output: msg.slice(0, 500) });
      throw new Error(`${label} failed: ${msg.split("\n")[0]}`);
    }
  }

  await run("Installing server dependencies", path.join(ROOT, "server"), ["install", "--no-audit", "--no-fund"]);
  await run("Installing client dependencies", path.join(ROOT, "client"), ["install", "--no-audit", "--no-fund"]);

  return { ok: true, steps };
}

export async function checkLocalDependencies() {
  const checks = [
    { name: "server/node_modules", path: path.join(ROOT, "server", "node_modules") },
    { name: "client/node_modules", path: path.join(ROOT, "client", "node_modules") },
  ];

  const fs = await import("fs/promises");
  const results = await Promise.all(
    checks.map(async (c) => {
      try {
        await fs.access(c.path);
        return { ...c, installed: true };
      } catch {
        return { ...c, installed: false };
      }
    }),
  );

  return {
    ready: results.every((r) => r.installed),
    checks: results,
  };
}
