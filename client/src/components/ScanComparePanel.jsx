import { useState } from "react";
import { api } from "../lib/api.js";
import Panel from "./Panel.jsx";
import { severityClass } from "../lib/defaults.js";

function DiffList({ title, items, variant }) {
  if (!items?.length) return null;
  return (
    <div className={`diff-block diff-block--${variant}`}>
      <h4>{title} ({items.length})</h4>
      <ul>
        {items.slice(0, 20).map((f) => (
          <li key={f.id + (f.pageUrl || "")}>
            <span className={severityClass(f.severity)}>{f.severity}</span> {f.title}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function ScanComparePanel({ siteId, baseScan, compareScan, onClose }) {
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadDiff() {
    if (!baseScan || !compareScan) return;
    setLoading(true);
    setError("");
    try {
      const data = await api.getScanDiff(siteId, baseScan.scanId, compareScan.scanId);
      setDiff(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Panel title="Compare scans" className="animate-in">
      <p className="hint">
        Base: Scan #{baseScan?.scanNumber} · Compare: Scan #{compareScan?.scanNumber}
      </p>
      <div className="toolbar" style={{ marginBottom: 16 }}>
        <button type="button" className="btn-primary btn-sm" onClick={loadDiff} disabled={loading || !baseScan || !compareScan}>
          {loading ? "Loading…" : "Run comparison"}
        </button>
        {onClose && (
          <button type="button" className="btn-secondary btn-sm" onClick={onClose}>Close</button>
        )}
      </div>
      {error && <div className="alert alert--error">{error}</div>}
      {diff && (
        <div className="diff-summary">
          <div className="diff-stats">
            <span className="diff-stat diff-stat--new">+{diff.summary.added} new</span>
            <span className="diff-stat diff-stat--fixed">−{diff.summary.fixed} fixed</span>
            <span className="diff-stat diff-stat--regressed">{diff.summary.regressed} regressed</span>
          </div>
          <DiffList title="New findings" items={diff.added} variant="new" />
          <DiffList title="Fixed findings" items={diff.fixed} variant="fixed" />
          {diff.regressed?.length > 0 && (
            <div className="diff-block diff-block--regressed">
              <h4>Regressed ({diff.regressed.length})</h4>
              <ul>
                {diff.regressed.map(({ before, after }) => (
                  <li key={after.id}>
                    {before.severity} → <span className={severityClass(after.severity)}>{after.severity}</span> {after.title}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}
