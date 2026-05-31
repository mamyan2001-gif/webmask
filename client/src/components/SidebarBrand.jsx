import { IconLogo } from "./icons.jsx";

export default function SidebarBrand({ onHome, apiOnline, checkCount = 43 }) {
  return (
    <button
      type="button"
      className="sidebar-brand"
      onClick={onHome}
      aria-label="WebMask home — go to dashboard"
      title="Back to dashboard"
    >
      <span className="sidebar-brand__logo-wrap">
        <span className="sidebar-brand__logo-ring" aria-hidden="true" />
        <IconLogo size={48} className="sidebar-brand__logo" />
      </span>
      <span className="sidebar-brand__copy">
        <span className="sidebar-brand__title">WebMask</span>
        <span className="sidebar-brand__meta">
          <span className={`sidebar-brand__status ${apiOnline ? "sidebar-brand__status--online" : "sidebar-brand__status--offline"}`}>
            <span className="sidebar-brand__status-dot" aria-hidden="true" />
            {apiOnline ? "API online" : "API offline"}
          </span>
          <span className="sidebar-brand__divider" aria-hidden="true">·</span>
          <span className="sidebar-brand__checks">{checkCount}+ checks</span>
        </span>
      </span>
    </button>
  );
}
