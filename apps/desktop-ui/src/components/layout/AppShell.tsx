import { useEffect, type ReactNode } from "react";
import type { View } from "../../app/types";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";

export function AppShell({ view, vaultName, targetCount, vaults, currentPath, onSwitchVault, onNavigate, onLock, onDismissNotice, error, message, onUndo, children, initialization, onRetryInitialization }: {
  view: View;
  vaultName: string;
  targetCount: number;
  vaults?: { id: string; name: string; catalogPath: string }[];
  currentPath?: string;
  onSwitchVault?: (path: string) => void;
  onNavigate: (view: View) => void;
  onLock: () => void;
  onDismissNotice: () => void;
  error: string;
  message: string; onUndo?: () => void;
  children: ReactNode;
  initialization?: { state: "loading" | "failed"; detail: string; operationId: string } | null;
  onRetryInitialization?: () => void;
  }) {
  useEffect(() => {
    if (!error && !message) return;
    const timer = window.setTimeout(onDismissNotice, 3000);
    return () => window.clearTimeout(timer);
  }, [error, message, onDismissNotice]);

  return <div className="app-shell">
    <Sidebar view={view} onNavigate={onNavigate} />
    <main className="main-content"><TopBar vaultName={vaultName} onLock={onLock} vaults={vaults} currentPath={currentPath} onSwitchVault={onSwitchVault} />
    {initialization && <div className={`vault-initialization ${initialization.state === "failed" ? "failed" : ""}`} role={initialization.state === "failed" ? "alert" : "status"} aria-live="polite">
      {initialization.state === "loading" && <span className="loading-spinner" aria-hidden="true" />}
      <span>{initialization.detail}</span>
      {initialization.state === "failed" && <button className="button secondary" onClick={onRetryInitialization}>Retry</button>}
    </div>}{children}
    {(error || message) && <div className="toast-region" aria-live="polite" aria-atomic="true">
      {error && <div className="toast error" role="alert"><span>{error}</span><button className="notice-close" aria-label="Dismiss error" onClick={onDismissNotice}>×</button></div>}
      {message && <div className="toast success" role="status"><span>{message}</span>{onUndo && <button className="button text-button" onClick={onUndo}>Undo</button>}<button className="notice-close" aria-label="Dismiss message" onClick={onDismissNotice}>×</button></div>}
    </div>}
    </main>
  </div>;
}
