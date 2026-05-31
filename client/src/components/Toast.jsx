export default function Toast({ message, type = "success", onDismiss }) {
  if (!message) return null;
  return (
    <div className={`toast toast--${type}`} role="status">
      <span>{message}</span>
      <button type="button" className="toast__close" onClick={onDismiss} aria-label="Dismiss">×</button>
    </div>
  );
}
