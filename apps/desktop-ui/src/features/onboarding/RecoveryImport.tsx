import type { PickKind } from "../../app/types";

export function RecoveryImport({ kitPath, catalogPath, passphrase, setPassphrase, onPick, onBack, onImport, error }: {
  kitPath: string;
  catalogPath: string;
  passphrase: string;
  setPassphrase: (value: string) => void;
  onPick: (kind: PickKind) => Promise<void>;
  onBack: () => void;
  onImport: () => void;
  error: string;
}) {
  return <div className="onboarding"><div className="onboarding-panel">
    <div className="brand"><span className="brand-mark">U</span><span>Undercloud</span></div>
    <div className="onboarding-content">
      <p className="eyebrow">Recovery</p>
      <h1>Restore a vault from a recovery kit</h1>
      <p className="lead">This creates a fresh catalog. Your original vault is not modified, and storage folders can be reconnected afterward.</p>
      <button className="button secondary" onClick={() => void onPick("kit")}>{kitPath ? "Change recovery kit" : "Choose recovery kit"}</button>
      <button className="button secondary" onClick={() => void onPick("newVault")}>{catalogPath ? "Change new vault location" : "Choose new vault location"}</button>
      <label>Recovery passphrase
        <input type="password" value={passphrase} onChange={event => setPassphrase(event.target.value)} autoComplete="current-password" />
      </label>
      <button className="button primary wide" disabled={!kitPath || !catalogPath || !passphrase} onClick={onImport}>Import recovery kit</button>
      <button className="button text-button" onClick={onBack}>Back</button>
      {error && <p className="inline-error" role="alert">{error}</p>}
    </div>
  </div></div>;
}
