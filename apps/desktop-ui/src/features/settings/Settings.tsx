import { useEffect, useState } from "react";
import { AUTOLOCK_CHANGED_EVENT, AUTOLOCK_KEY } from "../../app/types";
import { commands, type LoggingStatus } from "../../commands";
import { Page } from "../../components/ui/Page";
import { Select } from "../../components/ui/Select";

const VALID_MINUTES = ["0", "5", "15", "30"];

function storedAutolock(): string {
  const raw = localStorage.getItem(AUTOLOCK_KEY);
  return VALID_MINUTES.includes(raw ?? "") ? (raw as string) : "0";
}

export function Settings({ current, next, setCurrent, setNext, onChange, vaultName, onRenameVault, libraryRoot, vaultPath, onChooseLibrary, onOpenLibrary, onMoveVault, onResetLibrary, restoreMode, restoreDirectory, onRestoreModeChange, onChooseRestoreDirectory }: { current: string; next: string; setCurrent: (value: string) => void; setNext: (value: string) => void; onChange: () => void; vaultName: string; onRenameVault: (catalogPath: string, name: string) => Promise<void>; libraryRoot: string; vaultPath: string; onChooseLibrary: () => void; onOpenLibrary: () => void; onMoveVault: () => void; onResetLibrary: () => void; restoreMode: "ask" | "fixed"; restoreDirectory: string; onRestoreModeChange: (mode: "ask" | "fixed") => void; onChooseRestoreDirectory: () => void }) {
  const [autolock, setAutolock] = useState(storedAutolock);
  const [editedVaultName, setEditedVaultName] = useState(vaultName);
  const [logging, setLogging] = useState<LoggingStatus | null>(null);

  useEffect(() => { void commands.loggingStatus().then(setLogging).catch(() => undefined); }, []);

  const changeAutolock = (value: string) => {
    setAutolock(value);
    localStorage.setItem(AUTOLOCK_KEY, value);
    window.dispatchEvent(new Event(AUTOLOCK_CHANGED_EVENT));
  };
  const saveVaultName = async () => { if (vaultPath && editedVaultName.trim() && editedVaultName.trim() !== vaultName) await onRenameVault(vaultPath, editedVaultName.trim()); };

  return <Page title="Settings" subtitle="Manage your vault without exposing its internals.">
    <div className="form-card compact-form-card"><h2>Vault name</h2><label>Name<input value={editedVaultName} onChange={event => setEditedVaultName(event.target.value)} maxLength={80} /></label><button className="button primary" disabled={!vaultPath || !editedVaultName.trim() || editedVaultName.trim() === vaultName} onClick={() => void saveVaultName()}>Save name</button></div>
    <div className="form-card compact-form-card"><h2>Change vault password</h2><label>Current password<input type="password" value={current} onChange={event => setCurrent(event.target.value)} autoComplete="current-password" /></label><label>New password<input type="password" value={next} onChange={event => setNext(event.target.value)} autoComplete="new-password" /></label><button className="button primary" disabled={!current || !next} onClick={onChange}>Change password</button></div>
    <div className="form-card compact-form-card"><h2>Automatic lock</h2><p>Lock the vault after inactivity on this device.</p>
      <Select label="Lock after" value={autolock} onChange={changeAutolock} options={[{ value: "0", label: "Never" }, { value: "5", label: "After 5 minutes" }, { value: "15", label: "After 15 minutes" }, { value: "30", label: "After 30 minutes" }]} /><small>Uploads keep the vault awake while they run.</small>
    </div>
    <div className="form-card compact-form-card"><h2>Vault library location</h2><p className="path-value">{libraryRoot}</p><div className="quick-actions"><button className="button secondary" onClick={onChooseLibrary}>Choose folder</button><button className="button secondary" onClick={onOpenLibrary}>Open folder</button>{vaultPath && libraryRoot !== "Unavailable" && !vaultPath.startsWith(`${libraryRoot}/`) && <button className="button secondary" onClick={onMoveVault}>Move current vault here</button>}<button className="button text-button" onClick={onResetLibrary}>Reset to default</button></div></div>
    <div className="form-card compact-form-card"><h2>Restore location</h2><p>Choose where restored files should be saved.</p><Select label="Restore behavior" value={restoreMode} onChange={value => onRestoreModeChange(value as "ask" | "fixed")} options={[{ value: "ask", label: "Ask for a folder every time" }, { value: "fixed", label: "Always use the selected folder", disabled: !restoreDirectory }]} /><div className="quick-actions"><button className="button secondary" onClick={onChooseRestoreDirectory}>Choose restore folder</button>{restoreDirectory && <span className="path-value">{restoreDirectory}</span>}</div></div>
    <div className="form-card compact-form-card"><h2>Logs</h2><p>Application logs are saved continuously in the application data folder. A new file is used each day.</p>{logging?.warning && <small>{logging.warning}</small>}<div className="quick-actions"><button className="button secondary" onClick={() => void commands.openLogFolder()}>Open logs folder</button></div></div>
  </Page>;
}
