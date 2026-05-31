import { useState } from "react";
import Panel from "./Panel.jsx";
import { severityClass, scanLabel, formatSummary } from "../lib/defaults.js";
import { IconLayers } from "./icons.jsx";
import SiteFavicon from "./SiteFavicon.jsx";

export default function ScanHistoryPanel({ scans, activeScanId, onSelectScan, onDeleteScan, onCompare }) {
  const [compareBase, setCompareBase] = useState(null);

  function toggleCompare(scan) {
    if (!compareBase) {
      setCompareBase(scan);
      return;
    }
    if (compareBase.scanId === scan.scanId) {
      setCompareBase(null);
      return;
    }
    onCompare?.(compareBase, scan);
    setCompareBase(null);
  }

  return (
    <Panel icon={<IconLayers />} title="Scan history" className="animate-in-delay-3">
      {compareBase && (
        <p className="field-hint" style={{ marginBottom: 12 }}>
          Select a second scan to compare with Scan #{compareBase.scanNumber}
          <button type="button" className="btn-ghost btn-sm" style={{ marginLeft: 8 }} onClick={() => setCompareBase(null)}>Cancel</button>
        </p>
      )}
      {scans?.length ? (
        <div className="build-list">
          {scans.map((s, i) => (
            <div
              key={s.scanId}
              className={`build-card ${activeScanId === s.scanId ? "build-card--active" : ""} ${compareBase?.scanId === s.scanId ? "build-card--compare" : ""}`}
              style={{ animationDelay: `${i * 0.04}s` }}
            >
              <div>
                <div className="build-card__head">
                  <SiteFavicon url={s.targetUrl} faviconUrl={s.faviconUrl} size={28} />
                  <div>
                    <div className="build-card__num">Scan #{s.scanNumber}</div>
                    <span className="scan-url">{scanLabel(s)}</span>
                  </div>
                </div>
                <div className="build-card__meta">
                  {new Date(s.finishedAt || s.startedAt).toLocaleString()} · {formatSummary(s.summary)}
                  {s.regressionSummary && (
                    <> · +{s.regressionSummary.added} new</>
                  )}
                </div>
                <div className="summary-row" style={{ marginTop: 8 }}>
                  {["critical", "high", "medium"].map(
                    (sev) =>
                      s.summary?.[sev] > 0 && (
                        <span key={sev} className={severityClass(sev)}>
                          {s.summary[sev]} {sev}
                        </span>
                      ),
                  )}
                </div>
              </div>
              <div className="build-card__actions">
                <button type="button" className="btn-secondary btn-sm" onClick={() => onSelectScan(s)}>View</button>
                {scans.length > 1 && (
                  <button type="button" className="btn-secondary btn-sm" onClick={() => toggleCompare(s)}>Compare</button>
                )}
                <button type="button" className="btn-danger btn-sm" onClick={() => onDeleteScan(s)}>Remove</button>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </Panel>
  );
}
