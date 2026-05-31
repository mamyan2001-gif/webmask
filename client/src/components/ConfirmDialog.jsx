import { useEffect, useRef } from "react";
import { IconAlert } from "./icons.jsx";

export default function ConfirmDialog({
  open,
  title,
  message,
  detail,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  variant = "danger",
  onConfirm,
  onCancel,
}) {
  const cancelRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;

    cancelRef.current?.focus();

    function onKeyDown(e) {
      if (e.key === "Escape") onCancel();
    }

    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div className="confirm-overlay" onClick={onCancel} role="presentation">
      <div
        className={`confirm-dialog confirm-dialog--${variant}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-desc"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="confirm-dialog__icon" aria-hidden="true">
          <IconAlert />
        </div>
        <div className="confirm-dialog__body">
          <h2 id="confirm-dialog-title" className="confirm-dialog__title">{title}</h2>
          <p id="confirm-dialog-desc" className="confirm-dialog__message">{message}</p>
          {detail && <p className="confirm-dialog__detail">{detail}</p>}
        </div>
        <div className="confirm-dialog__actions">
          <button ref={cancelRef} type="button" className="btn-secondary" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button type="button" className="btn-danger" onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
