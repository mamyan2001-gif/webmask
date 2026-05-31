import logoSrc from "../../../icon/anonymus.png";

export function IconLogo({ size = 32, className = "" }) {
  return (
    <img
      src={logoSrc}
      alt=""
      width={size}
      height={size}
      className={`app-logo ${className}`.trim()}
      aria-hidden="true"
    />
  );
}

export function IconPlus() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 3v10M3 8h10" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
    </svg>
  );
}

export function IconServer() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <rect x="2" y="3" width="14" height="4" rx="1.5" stroke="currentColor" strokeWidth="1.4" />
      <rect x="2" y="11" width="14" height="4" rx="1.5" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="5" cy="5" r=".75" fill="currentColor" />
      <circle cx="5" cy="13" r=".75" fill="currentColor" />
    </svg>
  );
}

export function IconUpload() {
  return (
    <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M20 26V10m0 0l-6 6m6-6l6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M8 28v4h24v-4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

export function IconSpark() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 1l1.2 4.8L14 7l-4.8 1.2L8 13l-1.2-4.8L2 7l4.8-1.2L8 1z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round" />
    </svg>
  );
}

export function IconExternal() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
      <path d="M4 10L10 4M10 4H5.5M10 4v4.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function IconCheck() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M3 8.5l3.5 3.5 6.5-7" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function IconLayers() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M9 2L2 6l7 4 7-4-7-4z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M2 10l7 4 7-4M2 14l7 4 7-4" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}

export function IconCode() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M6 5L2 9l4 4M12 5l4 4-4 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function IconRocket() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M9 2s4 4 4 9a4 4 0 01-8 0c0-5 4-9 4-9z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <circle cx="9" cy="9" r="1.5" fill="currentColor" />
      <path d="M5 13l-2 2M13 13l2 2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  );
}

export function IconHome() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M3 8.5L9 3l6 5.5V15a1 1 0 01-1 1H5a1 1 0 01-1-1V8.5z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M7 16v-5h4v5" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  );
}

export function IconShield() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M9 2L3 5v4c0 3.5 2.5 6.5 6 7 3.5-.5 6-3.5 6-7V5l-6-3z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M7 9l1.5 1.5L11 8" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function IconAlert() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <path d="M9 2l7 12H2L9 2z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <path d="M9 7v3M9 13h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}
