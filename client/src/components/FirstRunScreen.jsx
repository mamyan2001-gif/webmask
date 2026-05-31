import { IconLogo, IconCheck } from "./icons.jsx";

const BOOTSTRAP_COMMANDS = `Double-click (macOS):
  Install WebMask.command
  Start WebMask.command

Or from Terminal:
  npm run setup
  npm run start:app`;

export default function FirstRunScreen({
  apiOnline,
  depsReady,
  depsChecks = [],
  installing,
  installError,
  installLogs = [],
  onInstall,
  onRetryConnection,
  onSkip,
}) {
  const step = !apiOnline ? 0 : depsReady ? 2 : 1;

  return (
    <div className="first-run animate-in">
      <div className="first-run__hero">
        <IconLogo size={56} />
        <p className="first-run__eyebrow">WebMask Security Scanner</p>
        <h1 className="first-run__title">First-time setup</h1>
      </div>

      <ol className="first-run__steps">
        <li className={`first-run__step ${step > 0 ? "first-run__step--done" : step === 0 ? "first-run__step--active" : ""}`}>
          <span className="first-run__step-num">{step > 0 ? <IconCheck /> : "1"}</span>
          <div>
            <strong>Start the API server</strong>
          </div>
        </li>
        <li className={`first-run__step ${step > 1 ? "first-run__step--done" : step === 1 ? "first-run__step--active" : ""}`}>
          <span className="first-run__step-num">{step > 1 ? <IconCheck /> : "2"}</span>
          <div>
            <strong>Install dependencies</strong>
          </div>
        </li>
        <li className={`first-run__step ${step === 2 ? "first-run__step--active" : ""}`}>
          <span className="first-run__step-num">3</span>
          <div>
            <strong>Add a target &amp; scan</strong>
          </div>
        </li>
      </ol>

      <div className="first-run__panel">
        {!apiOnline && (
          <>
            <pre className="first-run__code">{BOOTSTRAP_COMMANDS}</pre>
            <div className="toolbar">
              <button type="button" className="btn-primary" onClick={onRetryConnection}>Retry connection</button>
              <button type="button" className="btn-ghost" onClick={onSkip}>Skip for now</button>
            </div>
          </>
        )}

        {apiOnline && !depsReady && (
          <>
            {depsChecks.length > 0 && (
              <ul className="first-run__checks">
                {depsChecks.map((c) => (
                  <li key={c.name} className={c.installed ? "first-run__check--ok" : ""}>
                    {c.installed ? <IconCheck /> : "○"} {c.name}
                  </li>
                ))}
              </ul>
            )}
            {installError && <div className="alert alert--error">{installError}</div>}
            {installLogs.length > 0 && (
              <ul className="log-list">{installLogs.map((l, i) => <li key={i}>{l}</li>)}</ul>
            )}
            <div className="toolbar">
              <button type="button" className="btn-primary" onClick={onInstall} disabled={installing}>
                {installing ? <><span className="spinner" />Installing…</> : "Install dependencies"}
              </button>
              <button type="button" className="btn-ghost" onClick={onSkip}>Skip for now</button>
            </div>
          </>
        )}

        {apiOnline && depsReady && (
          <button type="button" className="btn-primary" onClick={onSkip}>Go to dashboard</button>
        )}
      </div>
    </div>
  );
}
