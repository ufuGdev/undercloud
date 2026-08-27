import { useEffect, useRef, type ReactNode } from "react";

export function ConfirmDialog({ title, children, confirmLabel, onConfirm, onCancel, disabled, destructive = false }: {
  title: string; children: ReactNode; confirmLabel: string; onConfirm: () => void; onCancel: () => void; disabled?: boolean; destructive?: boolean;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const onCancelRef = useRef(onCancel);
  onCancelRef.current = onCancel;
  useEffect(() => { cancelRef.current?.focus(); const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onCancelRef.current(); }; window.addEventListener("keydown", onKey); return () => window.removeEventListener("keydown", onKey); }, []);
  return <div className="dialog-backdrop" role="presentation"><section className="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title">
    <h2 id="dialog-title">{title}</h2><div className="dialog-body">{children}</div>
    <div className="dialog-actions"><button ref={cancelRef} className="button secondary" onClick={onCancel}>Cancel</button><button className={`button ${destructive ? "danger-button" : "primary"}`} disabled={disabled} onClick={onConfirm}>{confirmLabel}</button></div>
  </section></div>;
}
