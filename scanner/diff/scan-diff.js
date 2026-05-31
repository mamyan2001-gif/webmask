const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function findingKey(f) {
  return `${f.id}|${f.pageUrl || ""}`;
}

export function diffScans(baseline, current, triage = {}) {
  const baseMap = new Map();
  const currMap = new Map();

  for (const f of baseline?.findings || []) {
    if (triage[findingKey(f)] === "false_positive" || triage[findingKey(f)] === "accepted") continue;
    baseMap.set(findingKey(f), f);
  }
  for (const f of current?.findings || []) {
    if (triage[findingKey(f)] === "false_positive" || triage[findingKey(f)] === "accepted") continue;
    currMap.set(findingKey(f), f);
  }

  const added = [];
  const fixed = [];
  const unchanged = [];
  const regressed = [];

  for (const [key, f] of currMap) {
    const prev = baseMap.get(key);
    if (!prev) {
      added.push(f);
    } else if (prev.severity !== f.severity) {
      const prevRank = SEVERITY_RANK[prev.severity] || 0;
      const currRank = SEVERITY_RANK[f.severity] || 0;
      if (currRank > prevRank) regressed.push({ before: prev, after: f });
      else unchanged.push(f);
    } else {
      unchanged.push(f);
    }
  }

  for (const [key, f] of baseMap) {
    if (!currMap.has(key)) fixed.push(f);
  }

  return {
    baseScanId: baseline?.scanId,
    compareScanId: current?.scanId,
    added,
    fixed,
    unchanged,
    regressed,
    summary: {
      added: added.length,
      fixed: fixed.length,
      unchanged: unchanged.length,
      regressed: regressed.length,
      newCritical: added.filter((f) => f.severity === "critical").length,
      newHigh: added.filter((f) => f.severity === "high").length,
    },
  };
}

export function summarizeRegression(diff) {
  if (!diff) return null;
  const parts = [];
  if (diff.summary.added) parts.push(`${diff.summary.added} new`);
  if (diff.summary.fixed) parts.push(`${diff.summary.fixed} fixed`);
  if (diff.summary.regressed) parts.push(`${diff.summary.regressed} regressed`);
  return parts.length ? parts.join(", ") : "No changes";
}
