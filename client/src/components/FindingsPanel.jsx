import { useEffect, useState } from "react";
import { api } from "../lib/api.js";
import Panel from "./Panel.jsx";
import { severityClass, SEVERITY_ORDER, TRIAGE_STATES } from "../lib/defaults.js";
import SiteFavicon from "./SiteFavicon.jsx";

function FindingCard({ finding, siteId, scanId, triage, onTriage }) {
  const state = triage[finding.id] || "open";

  return (
    <article className={`finding-card ${severityClass(finding.severity)} finding-card--triage-${state}`}>
      <div className="finding-card__head">
        <span className={severityClass(finding.severity)}>{finding.severity}</span>
        <span className="finding-card__cat">{finding.category}</span>
        {state !== "open" && <span className="triage-badge">{state.replace("_", " ")}</span>}
        {finding.scanRole && <span className="triage-badge triage-badge--role">{finding.scanRole}</span>}
      </div>
      <h4 className="finding-card__title">{finding.title}</h4>
      {finding.pageUrl && (
        <p className="finding-card__page">
          <a href={finding.pageUrl} target="_blank" rel="noreferrer">{finding.pageUrl}</a>
        </p>
      )}
      <p className="finding-card__desc">{finding.description}</p>
      {finding.evidence && <pre className="finding-card__evidence">{finding.evidence}</pre>}
      {finding.remediation && (
        <p className="finding-card__fix"><strong>Fix:</strong> {finding.remediation}</p>
      )}
      <div className="finding-card__triage">
        {TRIAGE_STATES.filter((s) => s.id !== "open").map((s) => (
          <button
            key={s.id}
            type="button"
            className={`triage-btn ${state === s.id ? "triage-btn--active" : ""}`}
            onClick={() => onTriage(finding, s.id)}
          >
            {s.label}
          </button>
        ))}
      </div>
    </article>
  );
}

export default function FindingsPanel({ siteId, scan, onScanUpdated }) {
  const [filter, setFilter] = useState("all");
  const [triage, setTriage] = useState({});
  const [triageError, setTriageError] = useState("");

  useEffect(() => {
    if (!siteId || !scan?.scanId) {
      setTriage({});
      return;
    }
    api.getScanTriage(siteId, scan.scanId)
      .then((data) => setTriage(data.triage || {}))
      .catch(() => setTriage({}));
  }, [siteId, scan?.scanId]);

  if (!scan) {
    return <Panel title="Findings" className="animate-in-delay-2" />;
  }

  const findings = scan.findings || [];
  const assets = scan.discoveredAssets || {};
  const reg = scan.regression?.summary;
  const filtered =
    filter === "all" ? findings : findings.filter((f) => f.severity === filter);

  async function handleTriage(finding, state) {
    if (!siteId) return;
    setTriageError("");
    const prev = triage[finding.id] || "open";
    setTriage((t) => ({ ...t, [finding.id]: state }));
    try {
      await api.setFindingTriage(siteId, scan.scanId, finding.id, {
        state,
        pageUrl: finding.pageUrl || "",
      });
    } catch (e) {
      setTriage((t) => ({ ...t, [finding.id]: prev }));
      setTriageError(e.message);
    }
  }

  return (
    <Panel title={`Scan #${scan.scanNumber} findings`} className="animate-in-delay-2">
      <div className="panel-title-row">
        <SiteFavicon url={scan.targetUrl} faviconUrl={scan.faviconUrl} size={28} />
        <span className="scan-url">{scan.targetUrl}</span>
        {(scan.scanProfile || scan.scanMode) && (
          <span className="scan-mode-badge">{scan.scanProfile || scan.scanMode}</span>
        )}
        {siteId && (
          <div className="panel-title-row__actions">
            <a className="btn-secondary btn-sm" href={api.exportScanUrl(siteId, scan.scanId, "html")} target="_blank" rel="noreferrer">Export HTML</a>
            <a className="btn-secondary btn-sm" href={api.exportScanUrl(siteId, scan.scanId, "csv")} target="_blank" rel="noreferrer">Export CSV</a>
          </div>
        )}
      </div>

      {reg && (
        <div className="regression-banner">
          <strong>Regression vs previous scan:</strong>
          {" "}{reg.added} new · {reg.fixed} fixed · {reg.regressed} regressed
          {reg.newCritical > 0 && <span className="regression-banner__warn"> · {reg.newCritical} new critical</span>}
        </div>
      )}

      {triageError && (
        <div className="alert alert--error alert--inline" role="alert">{triageError}</div>
      )}

      <div className="summary-row">
        {SEVERITY_ORDER.map((sev) =>
          scan.summary?.[sev] > 0 ? (
            <button
              key={sev}
              type="button"
              className={`summary-pill ${severityClass(sev)} ${filter === sev ? "summary-pill--active" : ""}`}
              onClick={() => setFilter(filter === sev ? "all" : sev)}
            >
              {scan.summary[sev]} {sev}
            </button>
          ) : null,
        )}
        <button
          type="button"
          className={`summary-pill ${filter === "all" ? "summary-pill--active" : ""}`}
          onClick={() => setFilter("all")}
        >
          All ({findings.length})
        </button>
      </div>

      {(assets.crawlStats || assets.crawledPages?.length > 0) && (
        <div className="discovered-assets">
          {assets.crawlStats && (
            <div className="discovered-assets__block">
              <h3 className="discovered-assets__title">Spider coverage</h3>
              <p className="discovered-assets__meta">
                {assets.crawlStats.pages} pages · {assets.crawlStats.forms} forms · engine: {assets.crawlStats.engine || "fetch"}
              </p>
            </div>
          )}
        </div>
      )}

      <div className="findings-list">
        {filtered.map((f) => (
          <FindingCard
            key={f.id + (f.pageUrl || "")}
            finding={f}
            siteId={siteId}
            scanId={scan.scanId}
            triage={triage}
            onTriage={handleTriage}
          />
        ))}
      </div>

      {scan.logs?.length > 0 && (
        <div className="scan-progress scan-progress--done" style={{ marginTop: 20 }}>
          <div className="scan-progress__head">
            <strong>Scan log</strong>
            <span className="scan-progress__elapsed">{scan.logs.length} entries · {Math.round((scan.durationMs || 0) / 1000)}s</span>
          </div>
          <ul className="scan-log-list scan-log-list--collapsed">
            {scan.logs.map((entry, i) => (
              <li key={`${entry.at}-${i}`} className={`scan-log scan-log--${entry.level}`}>
                <span className="scan-log__time">
                  {new Date(entry.at).toLocaleTimeString(undefined, { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                </span>
                <span className="scan-log__phase">{entry.phase}</span>
                <span className="scan-log__msg">{entry.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  );
}
