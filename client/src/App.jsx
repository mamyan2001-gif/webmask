import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./lib/api.js";
import { DEFAULT_TARGET_CONFIG, formatSummary } from "./lib/defaults.js";
import FirstRunScreen from "./components/FirstRunScreen.jsx";
import TargetScanPanel from "./components/TargetScanPanel.jsx";
import FindingsPanel from "./components/FindingsPanel.jsx";
import ScanHistoryPanel from "./components/ScanHistoryPanel.jsx";
import ScanComparePanel from "./components/ScanComparePanel.jsx";
import SiteFavicon from "./components/SiteFavicon.jsx";
import SidebarBrand from "./components/SidebarBrand.jsx";
import SidebarTargets from "./components/SidebarTargets.jsx";
import Dashboard from "./components/Dashboard.jsx";
import Toast from "./components/Toast.jsx";
import ConfirmDialog from "./components/ConfirmDialog.jsx";
import { useConfirm } from "./hooks/useConfirm.js";
import {
  IconLogo, IconPlus, IconShield, IconAlert, IconHome,
} from "./components/icons.jsx";

const TABS = [
  { id: "scan", label: "Scan", icon: IconShield },
  { id: "findings", label: "Findings", icon: IconAlert },
];

const FIRST_RUN_KEY = "webmask-first-run-done";

function readFirstRunDone() {
  try {
    return localStorage.getItem(FIRST_RUN_KEY) === "1";
  } catch {
    return false;
  }
}

function markFirstRunDone() {
  try {
    localStorage.setItem(FIRST_RUN_KEY, "1");
  } catch {
    /* ignore */
  }
}

const EMPTY_DASHBOARD = {
  stats: { targets: 0, scans: 0, findings: 0, critical: 0, high: 0 },
  onboarding: {
    depsInstalled: false,
    hasTarget: false,
    hasScan: false,
    hasCritical: false,
  },
  recentActivity: [],
};

export default function App() {
  const [sites, setSites] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);
  const [view, setView] = useState("dashboard");
  const [activeId, setActiveId] = useState(null);
  const [site, setSite] = useState(null);
  const [tab, setTab] = useState("scan");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [toastType, setToastType] = useState("success");
  const [activeScan, setActiveScan] = useState(null);
  const [compareScans, setCompareScans] = useState(null);
  const [setupStatus, setSetupStatus] = useState(null);
  const [apiOnline, setApiOnline] = useState(true);
  const [firstRunDone, setFirstRunDone] = useState(readFirstRunDone);
  const [installingDeps, setInstallingDeps] = useState(false);
  const [installError, setInstallError] = useState("");
  const [installLogs, setInstallLogs] = useState([]);
  const { confirm, dialog: confirmDialog, onConfirm: onConfirmDialog, onCancel: onCancelDialog } = useConfirm();
  const openContextRef = useRef(null);

  const notify = (msg, type = "success") => {
    setToast(msg);
    setToastType(type);
    if (type === "success") setTimeout(() => setToast(""), 4000);
  };

  const loadSites = useCallback(async () => {
    try {
      const data = await api.getSites();
      setSites(data.sites || []);
      return data.sites || [];
    } catch {
      return [];
    }
  }, []);

  const refreshDashboard = useCallback(async () => {
    try {
      const data = await api.getDashboard();
      setDashboardData(data);
      setError("");
      return data;
    } catch (e) {
      setError(e.message || "Could not load dashboard — is the API running on port 4000?");
      return null;
    }
  }, []);

  const refreshSetupStatus = useCallback(async () => {
    try {
      const status = await api.getSetupStatus();
      setSetupStatus(status);
      setApiOnline(true);
      return status;
    } catch {
      setApiOnline(false);
      return null;
    }
  }, []);

  const depsReady = setupStatus?.dependencies?.ready ?? false;
  const showFirstRun = !firstRunDone && (!apiOnline || !depsReady);

  useEffect(() => {
    Promise.allSettled([refreshSetupStatus(), loadSites(), refreshDashboard()])
      .finally(() => setLoading(false));
  }, [loadSites, refreshDashboard, refreshSetupStatus]);

  useEffect(() => {
    if (!loading && apiOnline && depsReady && !firstRunDone) {
      markFirstRunDone();
      setFirstRunDone(true);
    }
  }, [loading, apiOnline, depsReady, firstRunDone]);

  useEffect(() => {
    if (!activeId) {
      setSite(null);
      return undefined;
    }

    let cancelled = false;
    const context = openContextRef.current;
    openContextRef.current = null;

    (async () => {
      try {
        const data = await api.getSite(activeId);
        if (cancelled) return;
        setSite(data);

        if (context?.loadFindings) {
          const scanId = context.scanId || data.scans?.[0]?.scanId;
          if (scanId) {
            const full = await api.getScan(activeId, scanId);
            if (!cancelled) setActiveScan(full);
          }
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
      }
    })();

    return () => { cancelled = true; };
  }, [activeId]);

  function openSite(siteId, nextTab = "scan", scanId = null) {
    setError("");
    setActiveScan(null);
    setTab(nextTab);
    setView("site");
    openContextRef.current = nextTab === "findings"
      ? { loadFindings: true, scanId }
      : null;
    setActiveId(siteId);
  }

  function goDashboard() {
    setView("dashboard");
    refreshDashboard();
  }

  function finishFirstRun() {
    markFirstRunDone();
    setFirstRunDone(true);
  }

  async function handleInstallDeps() {
    setInstallingDeps(true);
    setInstallError("");
    setInstallLogs([]);
    try {
      const res = await api.installLocal();
      setInstallLogs(res.logs || []);
      await refreshSetupStatus();
      await refreshDashboard();
      notify("Dependencies installed");
      finishFirstRun();
    } catch (e) {
      setInstallError(e.message);
    } finally {
      setInstallingDeps(false);
    }
  }

  async function handleRetryConnection() {
    setLoading(true);
    await refreshSetupStatus();
    await refreshDashboard();
    setLoading(false);
  }

  async function handleCreate() {
    setError("");
    try {
      const created = await api.createSite({ name: "My Target", config: DEFAULT_TARGET_CONFIG });
      await loadSites();
      await refreshDashboard();
      openSite(created.id, "scan");
      notify("Target created — enter a URL to scan");
    } catch (e) {
      setError(e.message);
      notify(e.message, "error");
    }
  }

  async function handleSave() {
    if (!site) return;
    setSaving(true);
    setError("");
    try {
      const updated = await api.updateSite(site.id, { name: site.name, config: site.config });
      setSite(updated);
      await loadSites();
      notify("Saved");
    } catch (e) {
      setError(e.message);
      notify(e.message, "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleDeleteScan(scan) {
    if (!site) return;
    const ok = await confirm({
      title: "Delete this scan?",
      message: `Scan #${scan.scanNumber} and its full report will be removed permanently.`,
      detail: scan.targetUrl || site.config?.url || undefined,
      confirmLabel: "Delete scan",
      cancelLabel: "Keep scan",
    });
    if (!ok) return;
    try {
      const { site: updated } = await api.deleteScan(site.id, scan.scanId);
      setSite(updated);
      if (activeScan?.scanId === scan.scanId) setActiveScan(null);
      await loadSites();
      await refreshDashboard();
      notify(`Scan #${scan.scanNumber} removed`);
    } catch (e) {
      notify(e.message, "error");
    }
  }

  async function handleDeleteTarget(target) {
    const ok = await confirm({
      title: "Delete target?",
      message: `"${target.name}" and all scan reports will be removed permanently.`,
      detail: target.config?.url ? `URL: ${target.config.url}` : undefined,
      confirmLabel: "Delete target",
      cancelLabel: "Cancel",
    });
    if (!ok) return;
    await api.deleteSite(target.id);
    if (activeId === target.id) {
      setActiveId(null);
      setSite(null);
      setView("dashboard");
      setActiveScan(null);
    }
    await loadSites();
    await refreshDashboard();
    notify("Target removed");
  }

  async function handleDelete() {
    if (!site) return;
    await handleDeleteTarget(site);
  }

  async function handleSelectScan(scanMeta) {
    if (!site) return;
    const siteId = site.id;
    try {
      const full = await api.getScan(siteId, scanMeta.scanId);
      if (activeId !== siteId) return;
      setActiveScan(full);
      setTab("findings");
    } catch (e) {
      notify(e.message, "error");
    }
  }

  if (loading) {
    return (
      <div className="loader-screen">
        <div className="loader-screen__brand">
          <span className="loader-screen__logo-ring" aria-hidden="true" />
          <div className="loader-screen__logo"><IconLogo size={56} /></div>
          <p className="loader-screen__title">WebMask</p>
        </div>
        <span className="spinner" style={{ width: 24, height: 24 }} />
        <p className="loader-screen__hint">Initializing scanner…</p>
      </div>
    );
  }

  return (
    <>
      <Toast message={toast} type={toastType} onDismiss={() => setToast("")} />
      <ConfirmDialog
        open={!!confirmDialog}
        title={confirmDialog?.title}
        message={confirmDialog?.message}
        detail={confirmDialog?.detail}
        confirmLabel={confirmDialog?.confirmLabel}
        cancelLabel={confirmDialog?.cancelLabel}
        variant={confirmDialog?.variant}
        onConfirm={onConfirmDialog}
        onCancel={onCancelDialog}
      />

      <div className="app-shell">
        <aside className="sidebar">
          <SidebarBrand onHome={goDashboard} apiOnline={apiOnline} />

          <button
            className={`site-item ${view === "dashboard" ? "site-item--active" : ""}`}
            onClick={goDashboard}
          >
            <div>
              <div className="site-item__name"><IconHome /> Dashboard</div>
            </div>
          </button>

          <div className="sidebar__actions">
            <button className="btn-primary btn-primary--glow" onClick={handleCreate}>
              <IconPlus /> New target
            </button>
          </div>

          <SidebarTargets
            sites={sites}
            activeId={view === "site" ? activeId : null}
            onOpenSite={(id) => openSite(id, "scan")}
          />

          <footer className="sidebar-footer">
            <span className={`sidebar-footer__pill ${apiOnline ? "sidebar-footer__pill--ok" : "sidebar-footer__pill--warn"}`}>
              {apiOnline ? "Scanner ready" : "Start API on :4000"}
            </span>
            <span className="sidebar-footer__version">v1.0 · WebMask</span>
          </footer>
        </aside>

        <main className={`main ${view === "dashboard" ? "main--wide" : ""}`}>
          {view === "dashboard" && showFirstRun && (
            <FirstRunScreen
              apiOnline={apiOnline}
              depsReady={depsReady}
              depsChecks={setupStatus?.dependencies?.checks}
              installing={installingDeps}
              installError={installError}
              installLogs={installLogs}
              onInstall={handleInstallDeps}
              onRetryConnection={handleRetryConnection}
              onOpenSetup={finishFirstRun}
              onSkip={finishFirstRun}
            />
          )}

          {view === "dashboard" && !showFirstRun && (
            <>
              {error && (
                <div className="alert alert--error" style={{ marginBottom: 16 }}>
                  {error}
                  <button type="button" className="btn-secondary btn-sm" style={{ marginLeft: 12 }} onClick={() => refreshDashboard()}>
                    Retry
                  </button>
                </div>
              )}
              <Dashboard
                data={dashboardData ?? EMPTY_DASHBOARD}
                sites={sites}
                onCreateSite={handleCreate}
                onOpenSite={openSite}
                onDeleteSite={handleDeleteTarget}
              />
            </>
          )}

          {view === "site" && site && (
            <>
              {error && (
                <div className="alert alert--error" role="alert">
                  <span>{error}</span>
                  <button type="button" className="alert__dismiss" onClick={() => setError("")} aria-label="Dismiss">×</button>
                </div>
              )}

              <header className="page-header">
                <div className="page-header__top">
                  <div className="page-header__identity">
                    <SiteFavicon
                      url={site.config?.url}
                      faviconUrl={site.config?.faviconUrl}
                      size={40}
                      className="page-header__favicon"
                    />
                    <div>
                      <button type="button" className="btn-ghost" style={{ marginBottom: 8, paddingLeft: 0 }} onClick={goDashboard}>
                        ← Dashboard
                      </button>
                    <input
                      className="page-header__title"
                      value={site.name}
                      onChange={(e) => setSite({ ...site, name: e.target.value })}
                      aria-label="Target name"
                    />
                    <p className="page-header__meta">
                      {site.config?.url || "No URL set"} · {site.scanCount || 0} scan{(site.scanCount || 0) !== 1 ? "s" : ""}
                      {site.lastScan?.summary && (
                        <> · {formatSummary(site.lastScan.summary)}</>
                      )}
                    </p>
                    </div>
                  </div>
                  <div className="page-header__actions">
                    <button className="btn-secondary" onClick={handleSave} disabled={saving}>
                      {saving ? "Saving…" : "Save name"}
                    </button>
                    <button className="btn-danger" onClick={handleDelete}>Delete target</button>
                  </div>
                </div>
              </header>

              <nav className="tabs" role="tablist">
                {TABS.map(({ id, label, icon: Icon }) => (
                  <button
                    key={id}
                    role="tab"
                    aria-selected={tab === id}
                    className={`tab ${tab === id ? "tab--active" : ""}`}
                    onClick={() => setTab(id)}
                  >
                    <Icon /> {label}
                  </button>
                ))}
              </nav>

              {tab === "scan" && (
                <div className="tab-panel">
                  <TargetScanPanel
                    site={site}
                    onScanned={async (scan) => {
                      setActiveScan(scan);
                      const refreshed = await api.getSite(site.id);
                      setSite(refreshed);
                      await loadSites();
                      await refreshDashboard();
                      setTab("findings");
                      notify(`Scan #${scan.scanNumber} complete — ${formatSummary(scan.summary)}`);
                    }}
                  />
                  <ScanHistoryPanel
                    scans={site.scans}
                    activeScanId={activeScan?.scanId}
                    onSelectScan={handleSelectScan}
                    onDeleteScan={handleDeleteScan}
                    onCompare={(base, compare) => setCompareScans({ base, compare })}
                  />
                  {compareScans && (
                    <ScanComparePanel
                      siteId={site.id}
                      baseScan={compareScans.base}
                      compareScan={compareScans.compare}
                      onClose={() => setCompareScans(null)}
                    />
                  )}
                </div>
              )}

              {tab === "findings" && (
                <div className="tab-panel">
                  <FindingsPanel siteId={site.id} scan={activeScan} />
                  {!activeScan && site.scans?.[0] && (
                    <div style={{ marginTop: 16 }}>
                      <button type="button" className="btn-secondary btn-sm" onClick={() => handleSelectScan(site.scans[0])}>
                        Load latest scan
                      </button>
                    </div>
                  )}
                </div>
              )}

            </>
          )}
        </main>
      </div>
    </>
  );
}
