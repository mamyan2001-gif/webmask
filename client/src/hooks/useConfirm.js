import { useCallback, useRef, useState } from "react";

const DEFAULTS = {
  title: "Are you sure?",
  message: "This action cannot be undone.",
  confirmLabel: "Confirm",
  cancelLabel: "Cancel",
  variant: "danger",
};

export function useConfirm() {
  const [dialog, setDialog] = useState(null);
  const resolveRef = useRef(null);

  const confirm = useCallback((options = {}) => {
    return new Promise((resolve) => {
      resolveRef.current = resolve;
      setDialog({ ...DEFAULTS, ...options });
    });
  }, []);

  const close = useCallback((result) => {
    resolveRef.current?.(result);
    resolveRef.current = null;
    setDialog(null);
  }, []);

  return {
    confirm,
    dialog,
    onConfirm: () => close(true),
    onCancel: () => close(false),
  };
}
