import type { ReactNode } from "react";
import { LockKeyhole } from "lucide-react";

export function TopBar({ vaultName, onLock, vaults = [], currentPath, onSwitchVault, children }: { vaultName: string; onLock: () => void; vaults?: { id: string; name: string; catalogPath: string }[]; currentPath?: string; onSwitchVault?: (path: string) => void; children?: ReactNode }) {
  return <><header className="topbar">
    <h2 className="vault-name">{vaultName ? `Vault - ${vaultName}` : "Vault"}</h2>
    <div className="topbar-actions">
      {vaults.length > 1 && <label className="vault-switcher"><span className="sr-only">Switch vault</span><select value={currentPath ?? ""} onChange={event => onSwitchVault?.(event.target.value)}>{vaults.map(vault => <option key={vault.id} value={vault.catalogPath}>{vault.name}</option>)}</select></label>}
      <button className="button secondary lock-button" onClick={onLock}><LockKeyhole size={16} aria-hidden="true" />Lock vault</button>
    </div>
  </header>{children}</>;
}
