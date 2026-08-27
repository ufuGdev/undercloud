import { useEffect, useState } from "react";
import { commands, type RecoveryFreshness } from "../../commands";
import type { PickKind } from "../../app/types";
import { Page } from "../../components/ui/Page";

export function Recovery({ recoveryPath, passphrase, setPassphrase, onPick, onExport }: { recoveryPath: string; passphrase: string; setPassphrase: (value: string) => void; onPick: (kind: PickKind) => Promise<void>; onExport: () => void }) {
  const [freshness, setFreshness] = useState<RecoveryFreshness | null>(null);
  useEffect(() => { void commands.recoveryFreshness().then(setFreshness).catch(() => undefined); }, []);
  return <Page title="Recovery" subtitle="A recovery kit helps rebuild your encrypted catalog on a fresh device.">
    <div className="recovery-layout">
      <div className="info-banner recovery-note"><strong>The kit does not contain your file payloads.</strong><span>Keep it separate from your vault password and store it somewhere safe.</span></div>
      <div className="form-card compact-form-card recovery-form">
        <h2>Export a recovery kit</h2>
        <p className="notice-line">{freshness?.state === "current" ? `Your recovery kit matches the current vault${freshness.exported_at ? ` (exported ${new Date(Number(freshness.exported_at)).toLocaleString()})` : ""}.` : freshness?.state === "outdated" ? "Important vault changes occurred after the last export." : "No successful recovery kit export is recorded yet."}</p>
        <button className="button secondary" onClick={() => void onPick("newKit")}>{recoveryPath ? "Change kit location" : "Choose kit location"}</button>
        <label>Recovery passphrase<input type="password" value={passphrase} onChange={event => setPassphrase(event.target.value)} autoComplete="new-password" /></label>
        <button className="button primary" disabled={!recoveryPath || !passphrase} onClick={onExport}>Export encrypted kit</button>
      </div>
    </div>
  </Page>;
}
