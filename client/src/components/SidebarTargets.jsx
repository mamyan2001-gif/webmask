import SiteFavicon from "./SiteFavicon.jsx";
import { formatSummary } from "../lib/defaults.js";

export default function SidebarTargets({ sites, activeId, onOpenSite }) {
  if (!sites.length) {
    return (
      <div className="sidebar-targets sidebar-targets--empty">
        <p>No targets yet</p>
        <span>Create one to start scanning</span>
      </div>
    );
  }

  return (
    <div className="sidebar-targets">
      <p className="sidebar__label">Targets</p>
      <ul className="sidebar-targets__list" role="list">
        {sites.map((s) => {
          const active = activeId === s.id;
          const url = s.config?.url;
          return (
            <li key={s.id}>
              <button
                type="button"
                className={`sidebar-target ${active ? "sidebar-target--active" : ""}`}
                onClick={() => onOpenSite(s.id)}
                title={url || s.name}
              >
                <SiteFavicon url={url} faviconUrl={s.config?.faviconUrl} size={22} />
                <span className="sidebar-target__body">
                  <span className="sidebar-target__name">{s.name}</span>
                  <span className="sidebar-target__meta">
                    {url
                      ? url.replace(/^https?:\/\//, "").slice(0, 28)
                      : "No URL"}
                    {s.lastScan?.summary && (
                      <> · {formatSummary(s.lastScan.summary)}</>
                    )}
                  </span>
                </span>
                {(s.scanCount || 0) > 0 && (
                  <span className="sidebar-target__badge">{s.scanCount}</span>
                )}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
