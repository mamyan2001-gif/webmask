import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api.js";
import { DEFAULT_AUTH_PROFILE } from "../lib/defaults.js";
import { mergeProfiles, getProfileMeta } from "../lib/scanProfiles.js";
import Panel from "./Panel.jsx";
import { IconShield } from "./icons.jsx";

function formatLogTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString(undefined, {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "—";
  }
}

function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function storedOpenApiSummary(spec) {
  if (!spec) return null;
  if (typeof spec === "string") {
    return spec.startsWith("http") ? `URL: ${spec}` : "Pasted JSON";
  }
  if (typeof spec === "object") {
    const title = spec.info?.title || "OpenAPI";
    const paths = Object.keys(spec.paths || {}).length;
    return `${title} · ${paths} endpoint${paths === 1 ? "" : "s"}`;
  }
  return null;
}

function ScanBtn({ label, hint, variant = "secondary", className = "", ...props }) {
  return (
    <button
      type="button"
      className={`scan-btn scan-btn--${variant}${className ? ` ${className}` : ""}`}
      {...props}
    >
      <span className="scan-btn__label">{label}</span>
      {hint && <span className="scan-btn__hint">{hint}</span>}
    </button>
  );
}

function OptionGroup({ title, hint, open, onToggle, children, disabled }) {
  return (
    <div className={`scan-option-group${open ? " scan-option-group--open" : ""}`}>
      <button
        type="button"
        className="scan-option-group__toggle"
        onClick={onToggle}
        aria-expanded={open}
        disabled={disabled}
      >
        <span className="scan-option-group__headline">
          <span className="scan-option-group__title">{title}</span>
          {hint && <span className="scan-option-group__hint">{hint}</span>}
        </span>
        <span className="scan-option-group__chevron" aria-hidden />
      </button>
      {open && <div className="scan-option-group__body">{children}</div>}
    </div>
  );
}

export default function TargetScanPanel({ site, onScanned }) {
  const [url, setUrl] = useState(site.config?.url || "");
  const [profile, setProfile] = useState(site.config?.scanOptions?.profile || "standard");
  const [profileList, setProfileList] = useState(() => mergeProfiles([]));
  const [authCookie, setAuthCookie] = useState(site.config?.authCookie || "");
  const [authBearer, setAuthBearer] = useState(site.config?.authBearer || "");
  const [authApiKey, setAuthApiKey] = useState(site.config?.authApiKey || "");
  const [authApiKeyHeader, setAuthApiKeyHeader] = useState(site.config?.authApiKeyHeader || "X-API-Key");
  const [seedUrlsText, setSeedUrlsText] = useState((site.config?.seedUrls || []).join("\n"));
  const [scopeAllowedHosts, setScopeAllowedHosts] = useState((site.config?.scopeRules?.allowedHosts || []).join("\n"));
  const [scopeDeniedPaths, setScopeDeniedPaths] = useState((site.config?.scopeRules?.deniedPaths || []).join("\n"));
  const [scanRolesJson, setScanRolesJson] = useState(
    site.config?.scanRoles?.length ? JSON.stringify(site.config.scanRoles, null, 2) : "",
  );
  const [authProfileJson, setAuthProfileJson] = useState(
    site.config?.authProfile ? JSON.stringify(site.config.authProfile, null, 2) : "",
  );
  const [openApiMode, setOpenApiMode] = useState(() => {
    const spec = site.config?.openApiSpec;
    if (typeof spec === "object" && spec !== null) return "stored";
    if (typeof spec === "string" && spec.startsWith("http")) return "url";
    if (typeof spec === "string") return "paste";
    return "url";
  });
  const [openApiUrl, setOpenApiUrl] = useState(
    typeof site.config?.openApiSpec === "string" && site.config.openApiSpec.startsWith("http")
      ? site.config.openApiSpec
      : "",
  );
  const [openApiPaste, setOpenApiPaste] = useState(
    typeof site.config?.openApiSpec === "string" && !site.config.openApiSpec.startsWith("http")
      ? site.config.openApiSpec
      : "",
  );
  const [openApiStored, setOpenApiStored] = useState(
    typeof site.config?.openApiSpec === "object" ? site.config.openApiSpec : null,
  );
  const [oastPublicUrl, setOastPublicUrl] = useState("");
  const [openAuth, setOpenAuth] = useState(Boolean(site.config?.authProfile?.steps?.length));
  const [openHeaders, setOpenHeaders] = useState(Boolean(site.config?.authBearer || site.config?.authApiKey));
  const [openSeeds, setOpenSeeds] = useState(Boolean(site.config?.seedUrls?.length));
  const [openScope, setOpenScope] = useState(Boolean(site.config?.scopeRules?.allowedHosts?.length || site.config?.scopeRules?.deniedPaths?.length));
  const [openRoles, setOpenRoles] = useState(Boolean(site.config?.scanRoles?.length));
  const [openOast, setOpenOast] = useState(false);
  const [openOpenApi, setOpenOpenApi] = useState(Boolean(site.config?.openApiSpec));
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [authError, setAuthError] = useState("");
  const [authSuccess, setAuthSuccess] = useState("");
  const [logs, setLogs] = useState([]);
  const [progress, setProgress] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [currentPhase, setCurrentPhase] = useState("");
  const logRef = useRef(null);
  const scanStartRef = useRef(0);
  const openApiFileRef = useRef(null);

  useEffect(() => {
    api.getProfiles()
      .then((d) => setProfileList(mergeProfiles(d.profiles)))
      .catch(() => setProfileList(mergeProfiles([])));
    api.getSettings().then((s) => setOastPublicUrl(s.oastPublicBaseUrl || "")).catch(() => {});
  }, []);

  useEffect(() => {
    const cfg = site.config || {};
    setUrl(cfg.url || "");
    setProfile(cfg.scanOptions?.profile || "standard");
    setAuthCookie(cfg.authCookie || "");
    setAuthBearer(cfg.authBearer || "");
    setAuthApiKey(cfg.authApiKey || "");
    setAuthApiKeyHeader(cfg.authApiKeyHeader || "X-API-Key");
    setSeedUrlsText((cfg.seedUrls || []).join("\n"));
    setScopeAllowedHosts((cfg.scopeRules?.allowedHosts || []).join("\n"));
    setScopeDeniedPaths((cfg.scopeRules?.deniedPaths || []).join("\n"));
    setScanRolesJson(cfg.scanRoles?.length ? JSON.stringify(cfg.scanRoles, null, 2) : "");
    setAuthProfileJson(cfg.authProfile ? JSON.stringify(cfg.authProfile, null, 2) : "");
    const spec = cfg.openApiSpec;
    if (typeof spec === "object" && spec !== null) {
      setOpenApiMode("stored");
      setOpenApiStored(spec);
      setOpenApiUrl("");
      setOpenApiPaste("");
    } else if (typeof spec === "string" && spec.startsWith("http")) {
      setOpenApiMode("url");
      setOpenApiUrl(spec);
      setOpenApiStored(null);
      setOpenApiPaste("");
    } else if (typeof spec === "string") {
      setOpenApiMode("paste");
      setOpenApiPaste(spec);
      setOpenApiStored(null);
      setOpenApiUrl("");
    } else {
      setOpenApiMode("url");
      setOpenApiUrl("");
      setOpenApiPaste("");
      setOpenApiStored(null);
    }
    setOpenAuth(Boolean(cfg.authProfile?.steps?.length));
    setOpenHeaders(Boolean(cfg.authBearer || cfg.authApiKey));
    setOpenSeeds(Boolean(cfg.seedUrls?.length));
    setOpenScope(Boolean(cfg.scopeRules?.allowedHosts?.length || cfg.scopeRules?.deniedPaths?.length));
    setOpenRoles(Boolean(cfg.scanRoles?.length));
    setOpenOpenApi(Boolean(spec));
    setError("");
    setAuthError("");
    setAuthSuccess("");
  }, [site.id]);

  useEffect(() => {
    if (!scanning) return undefined;
    scanStartRef.current = Date.now();
    const timer = setInterval(() => setElapsedMs(Date.now() - scanStartRef.current), 250);
    return () => clearInterval(timer);
  }, [scanning]);

  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [logs]);

  const activeProfile = profileList.find((p) => p.id === profile) || profileList[1];
  const profileMeta = activeProfile?.meta || getProfileMeta(profile);
  const isQuickScan = profile === "quick";

  useEffect(() => {
    if (isQuickScan) {
      setOpenAuth(false);
      setOpenOast(false);
      setOpenOpenApi(false);
      setAuthError("");
      setAuthSuccess("");
    }
  }, [isQuickScan]);

  useEffect(() => {
    setAuthError("");
    setAuthSuccess("");
  }, [authProfileJson]);

  function parseLines(text) {
    return text.split("\n").map((l) => l.trim()).filter(Boolean);
  }

  function buildScopeRules() {
    return {
      allowedHosts: parseLines(scopeAllowedHosts),
      deniedPaths: parseLines(scopeDeniedPaths),
      allowedPaths: [],
    };
  }

  function parseScanRoles() {
    if (!scanRolesJson.trim()) return [];
    return JSON.parse(scanRolesJson.trim());
  }

  function parseAuthProfile() {
    if (!authProfileJson.trim()) return null;
    return JSON.parse(authProfileJson);
  }

  function authProfileHasSteps(profile) {
    return Boolean(profile?.steps?.length);
  }

  let authTestReady = false;
  try {
    authTestReady = authProfileHasSteps(parseAuthProfile());
  } catch {
    authTestReady = false;
  }

  function resolveOpenApiSpecForScan() {
    if (openApiMode === "stored" && openApiStored) return openApiStored;
    if (openApiMode === "url" && openApiUrl.trim()) return openApiUrl.trim();
    if (openApiMode === "paste" && openApiPaste.trim()) {
      return JSON.parse(openApiPaste.trim());
    }
    return undefined;
  }

  async function handleSaveOastUrl() {
    setError("");
    try {
      await api.updateSettings({ oastPublicBaseUrl: oastPublicUrl.trim() });
      await api.getOastStatus();
    } catch (e) {
      setError(e.message);
    }
  }

  async function handleTestOast() {
    setError("");
    try {
      await api.getOastStatus();
    } catch (e) {
      setError(e.message);
    }
  }

  async function handleSaveOpenApi() {
    setError("");
    try {
      let spec;
      if (openApiMode === "url") {
        spec = openApiUrl.trim();
        if (!spec) throw new Error("Enter an OpenAPI URL");
      } else if (openApiMode === "paste") {
        spec = JSON.parse(openApiPaste.trim());
      } else if (openApiStored) {
        spec = openApiStored;
      } else {
        throw new Error("No OpenAPI spec to save");
      }
      await api.saveOpenApiSpec(site.id, spec);
      if (typeof spec === "object") setOpenApiStored(spec);
      setOpenApiMode(typeof spec === "string" && spec.startsWith("http") ? "url" : "stored");
    } catch (e) {
      setError(e.message);
    }
  }

  async function handleOpenApiFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setError("");
    try {
      const text = await file.text();
      JSON.parse(text);
      setOpenApiPaste(text);
      setOpenApiMode("paste");
      setOpenOpenApi(true);
    } catch {
      setError("Could not parse OpenAPI file as JSON");
    } finally {
      event.target.value = "";
    }
  }

  async function handleTestAuth() {
    setAuthError("");
    setAuthSuccess("");
    let authProfile;
    try {
      if (!authProfileJson.trim()) {
        setAuthError("Add login steps JSON first, or click Template.");
        return;
      }
      authProfile = parseAuthProfile();
      if (!authProfileHasSteps(authProfile)) {
        setAuthError("Auth profile needs at least one step.");
        return;
      }
      await api.testAuth(site.id, { authProfile });
      setAuthSuccess("Login flow verified.");
    } catch (e) {
      setAuthError(e.message);
    }
  }

  async function handleScan() {
    if (!url.trim()) {
      setError("Enter a target URL");
      return;
    }
    let authProfile = null;
    let openApiSpec;
    let scanRoles = [];
    try {
      if (!isQuickScan) {
        authProfile = authProfileJson.trim() ? parseAuthProfile() : null;
        openApiSpec = resolveOpenApiSpecForScan();
        scanRoles = parseScanRoles();
      }
    } catch {
      setError("Auth profile, scan roles, or OpenAPI JSON is invalid");
      return;
    }

    setScanning(true);
    setError("");
    setLogs([]);
    setProgress(0);
    setElapsedMs(0);
    setCurrentPhase("init");

    try {
      const result = await api.runScanStream(
        site.id,
        {
          url: url.trim(),
          ...(isQuickScan
            ? { scanOptions: { profile } }
            : {
                authCookie: authCookie.trim(),
                authBearer: authBearer.trim(),
                authApiKey: authApiKey.trim(),
                authApiKeyHeader: authApiKeyHeader.trim() || "X-API-Key",
                authProfile,
                openApiSpec,
                seedUrls: parseLines(seedUrlsText),
                scopeRules: buildScopeRules(),
                scanRoles,
                oastPublicBaseUrl: oastPublicUrl.trim() || undefined,
                scanOptions: { profile },
              }),
        },
        {
          onEvent: (event) => {
            if (event.type !== "log") return;
            setLogs((prev) => [...prev, event]);
            if (event.progress) {
              const { current, total } = event.progress;
              setProgress(total ? Math.round((current / total) * 100) : 0);
            }
            if (event.phase) setCurrentPhase(event.phase);
          },
        },
      );

      onScanned(result.scan);
      setProgress(100);
    } catch (e) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  }

  return (
    <Panel
      icon={<IconShield />}
      title="Run vulnerability scan"
      className="animate-in-delay-1"
    >
      <section className="scan-form-section">
        <div className="scan-form-section__head">
          <h3 className="scan-form-section__title">Target</h3>
        </div>
        <div className="field field--flush">
          <label htmlFor="scan-target-url">URL</label>
          <input
            id="scan-target-url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            spellCheck={false}
            disabled={scanning}
          />
        </div>
      </section>

      <section className="scan-form-section">
        <div className="scan-form-section__head">
          <h3 className="scan-form-section__title">Scan profile</h3>
        </div>

        <div className="scan-profiles" role="radiogroup" aria-label="Scan profile">
          {profileList.map((p) => (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={profile === p.id}
              className={`scan-profile-card scan-profile-card--${p.id}${profile === p.id ? " scan-profile-card--active" : ""}`}
              onClick={() => setProfile(p.id)}
              disabled={scanning}
            >
              <span className="scan-profile-card__top">
                <strong className="scan-profile-card__name">{p.label}</strong>
                <span className="scan-profile-card__duration">{p.meta.duration}</span>
              </span>
              <span className="scan-profile-card__desc">{p.meta.shortLabel}</span>
              <span className="scan-profile-card__intensity">{p.meta.intensity}</span>
            </button>
          ))}
        </div>
      </section>

      {!isQuickScan && (
        <section className="scan-form-section scan-form-section--options">
          <div className="scan-form-section__head">
            <h3 className="scan-form-section__title">Advanced options</h3>
          </div>

          <div className="scan-options-stack">
            <div className="scan-option-group scan-option-group--open scan-option-group--flat">
              <div className="scan-option-group__head-static">
                <span className="scan-option-group__headline">
                  <span className="scan-option-group__title">Session cookie</span>
                  <span className="scan-option-group__hint">Existing session</span>
                </span>
              </div>
              <div className="scan-option-group__body">
                <input
                  value={authCookie}
                  onChange={(e) => setAuthCookie(e.target.value)}
                  placeholder="session=abc123; Path=/"
                  spellCheck={false}
                  disabled={scanning}
                  aria-label="Session cookie"
                />
              </div>
            </div>

            <OptionGroup
              title="Auth headers"
              hint="Bearer / API key"
              open={openHeaders}
              onToggle={() => setOpenHeaders(!openHeaders)}
              disabled={scanning}
            >
              <input
                value={authBearer}
                onChange={(e) => setAuthBearer(e.target.value)}
                placeholder="Bearer eyJhbGciOi..."
                spellCheck={false}
                disabled={scanning}
                aria-label="Bearer token"
              />
              <div className="field-row" style={{ marginTop: 8 }}>
                <input
                  value={authApiKeyHeader}
                  onChange={(e) => setAuthApiKeyHeader(e.target.value)}
                  placeholder="X-API-Key"
                  spellCheck={false}
                  disabled={scanning}
                  aria-label="API key header name"
                />
                <input
                  value={authApiKey}
                  onChange={(e) => setAuthApiKey(e.target.value)}
                  placeholder="API key value"
                  spellCheck={false}
                  disabled={scanning}
                  aria-label="API key"
                />
              </div>
            </OptionGroup>

            <OptionGroup
              title="Multi-role scan"
              hint="Admin vs user"
              open={openRoles}
              onToggle={() => setOpenRoles(!openRoles)}
              disabled={scanning}
            >
              <textarea
                className="code-input code-input--flush"
                rows={6}
                value={scanRolesJson}
                onChange={(e) => setScanRolesJson(e.target.value)}
                placeholder={'[{"name":"admin","authCookie":"..."},{"name":"user","authCookie":"..."}]'}
                disabled={scanning}
                aria-label="Scan roles JSON"
              />
            </OptionGroup>

            <OptionGroup
              title="Seed URLs"
              hint="Spider start list"
              open={openSeeds}
              onToggle={() => setOpenSeeds(!openSeeds)}
              disabled={scanning}
            >
              <textarea
                className="code-input code-input--flush"
                rows={4}
                value={seedUrlsText}
                onChange={(e) => setSeedUrlsText(e.target.value)}
                placeholder={"/login\n/admin\n/api/docs"}
                disabled={scanning}
                aria-label="Seed URLs"
              />
            </OptionGroup>

            <OptionGroup
              title="Scope rules"
              hint="Stay in bounds"
              open={openScope}
              onToggle={() => setOpenScope(!openScope)}
              disabled={scanning}
            >
              <label>Allowed hosts (one per line)</label>
              <textarea
                className="code-input code-input--flush"
                rows={3}
                value={scopeAllowedHosts}
                onChange={(e) => setScopeAllowedHosts(e.target.value)}
                placeholder={"*.example.com\napi.example.com"}
                disabled={scanning}
              />
              <label style={{ marginTop: 8 }}>Denied paths</label>
              <textarea
                className="code-input code-input--flush"
                rows={3}
                value={scopeDeniedPaths}
                onChange={(e) => setScopeDeniedPaths(e.target.value)}
                placeholder={"/logout\n/external"}
                disabled={scanning}
              />
            </OptionGroup>

            <OptionGroup
              title="Login flow"
              hint="Playwright login"
              open={openAuth}
              onToggle={() => setOpenAuth(!openAuth)}
              disabled={scanning}
            >
              <textarea
                className="code-input code-input--flush"
                rows={8}
                value={authProfileJson}
                onChange={(e) => setAuthProfileJson(e.target.value)}
                placeholder={JSON.stringify(DEFAULT_AUTH_PROFILE, null, 2)}
                disabled={scanning}
                aria-label="Auth profile JSON"
              />
              {authError && (
                <div className="alert alert--error alert--inline" role="alert">
                  <span>{authError}</span>
                  <button type="button" className="alert__dismiss" onClick={() => setAuthError("")} aria-label="Dismiss">×</button>
                </div>
              )}
              {authSuccess && (
                <div className="alert alert--success alert--inline" role="status">{authSuccess}</div>
              )}
              <div className="scan-action-bar">
                <ScanBtn
                  label="Template"
                  hint="Load example"
                  onClick={() => setAuthProfileJson(JSON.stringify(DEFAULT_AUTH_PROFILE, null, 2))}
                  disabled={scanning}
                />
                <ScanBtn
                  label="Test"
                  hint="Verify login"
                  onClick={handleTestAuth}
                  disabled={scanning || !authTestReady}
                />
              </div>
            </OptionGroup>

            <OptionGroup
              title="OAST URL"
              hint="Blind callbacks"
              open={openOast}
              onToggle={() => setOpenOast(!openOast)}
              disabled={scanning}
            >
              <input
                value={oastPublicUrl}
                onChange={(e) => setOastPublicUrl(e.target.value)}
                placeholder="https://abc123.ngrok-free.app"
                spellCheck={false}
                disabled={scanning}
                aria-label="OAST public URL"
              />
              <div className="scan-action-bar">
                <ScanBtn label="Save" hint="Store URL" onClick={handleSaveOastUrl} disabled={scanning} />
                <ScanBtn label="Verify" hint="Check tunnel" onClick={handleTestOast} disabled={scanning} />
              </div>
            </OptionGroup>

            <OptionGroup
              title="OpenAPI"
              hint="API fuzzing"
              open={openOpenApi}
              onToggle={() => setOpenOpenApi(!openOpenApi)}
              disabled={scanning}
            >
              <div className="segmented-control segmented-control--wide" role="tablist" aria-label="OpenAPI input method">
                {[
                  { id: "url", label: "URL" },
                  { id: "paste", label: "JSON" },
                  ...(openApiStored ? [{ id: "stored", label: "Saved" }] : []),
                ].map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    role="tab"
                    aria-selected={openApiMode === mode.id}
                    className={`segmented-control__btn${openApiMode === mode.id ? " segmented-control__btn--active" : ""}`}
                    onClick={() => setOpenApiMode(mode.id)}
                    disabled={scanning}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>

              {openApiMode === "url" && (
                <input
                  className="scan-option-input"
                  value={openApiUrl}
                  onChange={(e) => setOpenApiUrl(e.target.value)}
                  placeholder="https://api.example.com/openapi.json"
                  spellCheck={false}
                  disabled={scanning}
                  aria-label="OpenAPI spec URL"
                />
              )}

              {openApiMode === "paste" && (
                <>
                  <textarea
                    className="code-input code-input--flush"
                    rows={6}
                    value={openApiPaste}
                    onChange={(e) => setOpenApiPaste(e.target.value)}
                    placeholder='{"openapi":"3.0.0","paths":{...}}'
                    disabled={scanning}
                    aria-label="OpenAPI JSON"
                  />
                  <input ref={openApiFileRef} type="file" accept=".json,application/json" hidden onChange={handleOpenApiFile} />
                  <div className="scan-action-bar scan-action-bar--single">
                    <ScanBtn
                      label="Upload"
                      hint="JSON file"
                      onClick={() => openApiFileRef.current?.click()}
                      disabled={scanning}
                    />
                  </div>
                </>
              )}

              {openApiMode === "stored" && openApiStored && (
                <div className="scan-saved-spec">{storedOpenApiSummary(openApiStored)}</div>
              )}

              <div className="scan-action-bar scan-action-bar--single">
                <ScanBtn label="Save" hint="On this target" onClick={handleSaveOpenApi} disabled={scanning} />
              </div>
            </OptionGroup>
          </div>
        </section>
      )}

      {error && (
        <div className="alert alert--error" role="alert">
          <span>{error}</span>
          <button type="button" className="alert__dismiss" onClick={() => setError("")} aria-label="Dismiss">×</button>
        </div>
      )}

      {scanning && (
        <div className="scan-progress">
          <div className="scan-progress__head">
            <span className="spinner" />
            <div className="scan-progress__status">
              <strong>{activeProfile?.label || profile} scan in progress</strong>
              {currentPhase && <span className="scan-progress__phase">{currentPhase}</span>}
            </div>
            <span className="scan-progress__elapsed">{formatElapsed(elapsedMs)}</span>
          </div>
          <div className="scan-progress__bar" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100}>
            <div className="scan-progress__fill" style={{ width: `${progress}%` }} />
          </div>
          <ul className="scan-log-list" ref={logRef}>
            {logs.map((entry, i) => (
              <li key={`${entry.at}-${i}`} className={`scan-log scan-log--${entry.level}`}>
                <span className="scan-log__time">{formatLogTime(entry.at)}</span>
                <span className="scan-log__phase">{entry.phase}</span>
                <span className="scan-log__msg">{entry.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {!scanning && logs.length > 0 && (
        <div className="scan-progress scan-progress--done">
          <div className="scan-progress__head">
            <strong>Scan log</strong>
            <span className="scan-progress__elapsed">{logs.length} entries</span>
          </div>
          <ul className="scan-log-list scan-log-list--collapsed" ref={logRef}>
            {logs.map((entry, i) => (
              <li key={`${entry.at}-${i}`} className={`scan-log scan-log--${entry.level}`}>
                <span className="scan-log__time">{formatLogTime(entry.at)}</span>
                <span className="scan-log__phase">{entry.phase}</span>
                <span className="scan-log__msg">{entry.message}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="scan-form-actions">
        {scanning ? (
          <button type="button" className="scan-btn scan-btn--primary scan-btn--run" disabled>
            <span className="scan-btn__label">
              <span className="spinner" />
              Scanning…
            </span>
            <span className="scan-btn__hint">{activeProfile?.label || profile} profile</span>
          </button>
        ) : (
          <ScanBtn
            variant="primary"
            className="scan-btn--run"
            label={`Run ${activeProfile?.label || profile} scan`}
            hint={`${profileMeta.duration} · ${profileMeta.runHint}`}
            onClick={handleScan}
          />
        )}
      </div>
    </Panel>
  );
}
