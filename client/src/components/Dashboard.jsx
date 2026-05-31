import { useState } from "react";
import { ROADMAP_IDEAS } from "../lib/roadmap.js";
import { severityClass, formatSummary } from "../lib/defaults.js";
import { IconPlus, IconShield } from "./icons.jsx";
import SiteFavicon from "./SiteFavicon.jsx";

function StatCard({ label, value, sub, accent, danger }) {
  return (
    <div className={`dash-stat ${accent ? "dash-stat--accent" : ""} ${danger ? "dash-stat--danger" : ""}`}>
      <span className="dash-stat__value">{value}</span>
      <span className="dash-stat__label">{label}</span>
      {sub && <span className="dash-stat__sub">{sub}</span>}
    </div>
  );
}

function RoadmapCard({ idea, expanded, onToggle }) {
  return (
    <article
      className={`roadmap-card ${expanded ? "roadmap-card--open" : ""}`}
      onClick={onToggle}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onToggle()}
    >
      <div className="roadmap-card__head">
        <span className={`roadmap-tag roadmap-tag--${idea.complexity.toLowerCase().replace(/\s/g, "-")}`}>
          {idea.complexity}
        </span>
        <span className="roadmap-tag roadmap-tag--cat">{idea.category}</span>
      </div>
      <h3 className="roadmap-card__title">{idea.title}</h3>
      <p className="roadmap-card__summary">{idea.summary}</p>
      {expanded && (
        <div className="roadmap-card__detail">
          <p><strong>Effort:</strong> {idea.effort}</p>
          <p><strong>Stack:</strong> {idea.stack}</p>
          <ul className="roadmap-list">
            {idea.includes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
      <span className="roadmap-card__toggle">{expanded ? "Show less" : "Explore →"}</span>
    </article>
  );
}

export default function Dashboard({
  data,
  sites,
  onCreateSite,
  onOpenSite,
  onDeleteSite,
}) {
  const [expandedId, setExpandedId] = useState(null);
  const [roadmapFilter, setRoadmapFilter] = useState("all");

  const { stats, recentActivity = [] } = data;

  const categories = ["all", ...new Set(ROADMAP_IDEAS.map((i) => i.category))];
  const filteredIdeas = roadmapFilter === "all"
    ? ROADMAP_IDEAS
    : ROADMAP_IDEAS.filter((i) => i.category === roadmapFilter);

  return (
    <div className="dashboard">
      <header className="dash-hero animate-in">
        <div className="dash-hero__text">
          <p className="dash-hero__eyebrow">WebMask Security Scanner</p>
          <h1 className="dash-hero__title">
            {sites.length === 0 ? "Test websites for vulnerabilities" : "Security dashboard"}
          </h1>
        </div>
        <div className="dash-hero__actions">
          <button className="btn-primary" onClick={onCreateSite}><IconPlus /> New target</button>
        </div>
      </header>

      <div className="dash-stats animate-in-delay-1">
        <StatCard label="Targets" value={stats.targets ?? stats.sites ?? 0} />
        <StatCard label="Scans" value={stats.scans ?? 0} accent />
        <StatCard label="Findings" value={stats.findings ?? 0} />
        <StatCard label="Critical" value={stats.critical ?? 0} danger accent />
        <StatCard label="High" value={stats.high ?? 0} accent />
      </div>

      {recentActivity.length > 0 && (
        <section className="dash-panel animate-in-delay-3">
          <h2 className="dash-panel__title">Recent scans</h2>
          <div className="activity-list">
            {recentActivity.map((item) => (
              <div key={`${item.siteId}-${item.scanId}`} className="activity-row">
                <SiteFavicon url={item.targetUrl} faviconUrl={item.faviconUrl} size={28} />
                <div>
                  <strong>{item.siteName}</strong>
                  <span className="scan-url" style={{ marginLeft: 8 }}>{item.targetUrl}</span>
                  <p className="activity-row__meta">
                    {new Date(item.createdAt).toLocaleString()} · {formatSummary(item.summary)}
                  </p>
                </div>
                <button type="button" className="btn-secondary btn-sm" onClick={() => onOpenSite(item.siteId, "findings", item.scanId)}>
                  <IconShield /> View
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {sites.length > 0 && (
        <section className="dash-panel animate-in-delay-3">
          <h2 className="dash-panel__title">Your targets</h2>
          <div className="site-grid">
            {sites.map((s) => (
              <article key={s.id} className="site-card">
                <button
                  type="button"
                  className="site-card__close"
                  aria-label={`Remove ${s.name}`}
                  onClick={() => onDeleteSite(s)}
                >
                  ×
                </button>
                <button type="button" className="site-card__main" onClick={() => onOpenSite(s.id)}>
                  <div className="site-card__head">
                    <SiteFavicon url={s.config?.url} faviconUrl={s.config?.faviconUrl} size={32} />
                    <div>
                      <span className="site-card__name">{s.name}</span>
                      <span className="site-card__meta">{s.scanCount || 0} scan{(s.scanCount || 0) !== 1 ? "s" : ""}</span>
                    </div>
                  </div>
                  {s.lastScan?.summary?.critical > 0 && (
                    <span className={`site-card__live ${severityClass("critical")}`}>Critical</span>
                  )}
                </button>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="dash-panel dash-panel--roadmap animate-in-delay-3">
        <div className="dash-panel__head-row">
          <div>
            <h2 className="dash-panel__title">Advanced scanning roadmap</h2>
          </div>
          <div className="filter-pills">
            {categories.map((cat) => (
              <button
                key={cat}
                type="button"
                className={`filter-pill ${roadmapFilter === cat ? "filter-pill--active" : ""}`}
                onClick={() => setRoadmapFilter(cat)}
              >
                {cat === "all" ? "All" : cat}
              </button>
            ))}
          </div>
        </div>
        <div className="roadmap-grid">
          {filteredIdeas.map((idea) => (
            <RoadmapCard
              key={idea.id}
              idea={idea}
              expanded={expandedId === idea.id}
              onToggle={() => setExpandedId(expandedId === idea.id ? null : idea.id)}
            />
          ))}
        </div>
      </section>
    </div>
  );
}
