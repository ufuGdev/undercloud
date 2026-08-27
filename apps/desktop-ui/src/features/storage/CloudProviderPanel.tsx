import { useState } from "react";
import type { CloudProviderInput } from "../../commands";
import { commands } from "../../commands";
import { safeError, safeErrorCode } from "../../app/types";
import { Select } from "../../components/ui/Select";

export function CloudProviderPanel() {
  const [provider, setProvider] = useState<CloudProviderInput>({ kind: "google_drive" });
  const [waiting, setWaiting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const connect = async () => {
    setWaiting(true); setError(""); setMessage("");
    try {
      await commands.authorizeCloudProvider(provider);
      window.dispatchEvent(new Event("undercloud-providers-changed"));
      setMessage("Provider connected and capability check completed.");
    } catch (reason) {
      const code = safeErrorCode(reason);
      setError(safeError(reason, code));
    } finally { setWaiting(false); }
  };

  return <div className="form-card compact-form-card">
    <h2>Connect a cloud provider</h2>
    <p className="notice-line">Undercloud requests access only to its private app folder; tokens stay in the system credential store.</p>
    <div className="connect-row">
      <Select label="Provider" value={provider.kind} onChange={value => setProvider({ kind: value as CloudProviderInput["kind"] })} options={[{ value: "google_drive", label: "Google Drive" }, { value: "onedrive", label: "OneDrive" }, { value: "dropbox", label: "Dropbox" }]} />
      {waiting ? <div role="status" className="connect-waiting"><span>Waiting for browser authorization…</span><button className="button secondary" onClick={() => { void commands.cancelAuthorization(); setWaiting(false); }}>Cancel</button></div> : <button className="button primary" onClick={() => void connect()}>Connect securely</button>}
    </div>
    {message && <p className="inline-success" role="status">{message}</p>}{error && <p className="inline-error" role="alert">{error}</p>}
  </div>;
}
