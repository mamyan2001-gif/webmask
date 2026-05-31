export default function Panel({ icon, title, subtitle, children, className = "", accent }) {
  return (
    <section className={`panel animate-in ${accent ? "panel--accent" : ""} ${className}`.trim()}>
      <header className="panel__header">
        {icon && <span className="panel__icon">{icon}</span>}
        <div>
          <h2 className="panel__title">{title}</h2>
          {subtitle && <p className="panel__subtitle">{subtitle}</p>}
        </div>
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}
