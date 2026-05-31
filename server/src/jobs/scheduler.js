import cron from "node-cron";
import { loadSchedules, saveSchedules } from "../settings.js";
import { executeSiteScan, isSiteScanRunning } from "./scan-runner.js";

const tasks = new Map();

export async function reloadScheduler() {
  for (const task of tasks.values()) task.stop();
  tasks.clear();

  const { schedules = [] } = await loadSchedules();
  for (const job of schedules) {
    if (!job.enabled || !job.cron || !job.siteId) continue;
    if (!cron.validate(job.cron)) continue;

    const task = cron.schedule(job.cron, async () => {
      if (isSiteScanRunning(job.siteId)) {
        console.log(`[WebMask] Skipping scheduled scan for ${job.siteId} — scan already in progress`);
        return;
      }
      try {
        console.log(`[WebMask] Scheduled scan: ${job.siteId}`);
        await executeSiteScan(job.siteId, { notify: true });
        job.lastRun = new Date().toISOString();
        const data = await loadSchedules();
        const idx = data.schedules.findIndex((s) => s.id === job.id);
        if (idx >= 0) {
          data.schedules[idx].lastRun = job.lastRun;
          await saveSchedules(data);
        }
      } catch (err) {
        console.error("[WebMask] Scheduled scan failed:", err.message);
      }
    });
    tasks.set(job.id, task);
  }

  console.log(`[WebMask] Scheduler loaded ${tasks.size} job(s)`);
}

export function startScheduler() {
  reloadScheduler().catch((err) => console.error("[WebMask] Scheduler init failed:", err.message));
}
