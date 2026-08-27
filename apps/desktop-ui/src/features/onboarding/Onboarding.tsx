import { useState } from "react";
import type { Status } from "../../commands";
import type { OnboardingStep, PickKind } from "../../app/types";

export function Onboarding({ step, setStep, password, setPassword, vaultName, setVaultName, vaultPath, onPick, onCreate, onOpen, initialMode = "create", onUnlock, onRecover, status, error, message, vaults = [], onSelectVault }: {
  step: OnboardingStep;
  setStep: (step: OnboardingStep | null) => void;
  password: string;
  setPassword: (value: string) => void;
  vaultName: string;
  setVaultName: (value: string) => void;
  vaultPath: string;
  onPick: (kind: PickKind) => Promise<void>;
  onCreate: () => Promise<void>;
  onOpen: () => Promise<void>;
  initialMode?: "create" | "open";
  onUnlock: () => Promise<void>;
  onRecover: () => void;
  status: Status;
  error: string;
  message: string;
  vaults?: { id: string; name: string; catalogPath: string }[];
  onSelectVault: (path: string) => void;
}) {
  const [confirm, setConfirm] = useState("");
  const [mode, setMode] = useState<"create" | "open">(initialMode);
  const selectedVault = vaults.find(vault => vault.catalogPath === vaultPath);

  return <div className="onboarding"><div className="onboarding-panel">
    <div className="brand"><span className="brand-mark">U</span><span>Undercloud</span></div>
    <div className="stepper">{["welcome", "vault", "storage", "policy", "finish"].map((value, index) =>
      <span className={value === step ? "step active" : "step"} key={value}>{index + 1}</span>)}</div>

    {step === "welcome" && <div className="onboarding-content">
      <p className="onboarding-intro">Create a private vault or open one from your Undercloud library.</p>
      <div className="callout-info"><span className="callout-info-icon" aria-hidden="true">i</span><span>If you lose both your vault password and recovery kit, your files cannot be recovered.</span></div>
      <div className="onboarding-actions">
        <button className="button primary" onClick={() => { setMode("create"); setStep("vault"); }}>Create a new vault</button>
        <button className="button secondary" onClick={() => { setMode("open"); setStep("vault"); }}>Open an existing vault</button>
      </div>
      <button className="button text-button" onClick={onRecover}>Recover from a recovery kit</button>
    </div>}

    {step === "vault" && <div className="onboarding-content">
      <p className="eyebrow">Step 1 of 3</p><h1>{mode === "create" ? "Create your vault" : "Open your vault"}</h1>
      {mode === "open" && vaults.length > 0 && <div className="form-card vault-list"><h3>Vaults in your library</h3>{vaults.map(vault => <button className={vault.catalogPath === vaultPath ? "vault-list-row selected" : "vault-list-row"} aria-pressed={vault.catalogPath === vaultPath} key={vault.id} onClick={() => onSelectVault(vault.catalogPath)}><span className="vault-list-check">{vault.catalogPath === vaultPath ? "✓" : ""}</span><span>{vault.name}</span></button>)}</div>}
      {mode === "create" && <>
        <label>Vault name<input value={vaultName} onChange={event => setVaultName(event.target.value)} maxLength={80} autoFocus /></label>
        <label>Vault password
          <input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password" />
          <small>Use at least 8 characters. A longer unique passphrase is stronger.</small>
        </label>
        <label>Confirm password
          <input type="password" value={confirm} onChange={event => setConfirm(event.target.value)} autoComplete="new-password" />
        </label>
        <button className="button primary wide" disabled={!vaultName.trim() || !password || password !== confirm} onClick={() => void onCreate()}>Create vault</button>
      </>}
      {mode === "open" && <>
        {selectedVault ? <label>Vault password
          <input autoFocus type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="current-password" />
        </label> : <p className="selected-file">Select a vault to enter its password.</p>}
        <button className="button primary wide" disabled={!vaultPath || !password} onClick={() => void onOpen()}>Open vault</button>
      </>}
      <button className="button text-button" onClick={() => setStep("welcome")}>Back</button>
      {error && <p className="inline-error" role="alert">{error}</p>}
    </div>}

    {step === "storage" && <div className="onboarding-content">
      <p className="eyebrow">Step 2 of 3</p><h1>Connect storage when you’re ready</h1>
      <p className="lead">Two independent storage targets are needed before a file can become protected. You can do this now or later.</p>
      <div className="provider-choice"><div><strong>Google Drive, OneDrive, or Dropbox</strong><span>Connect cloud accounts through OAuth; files are encrypted locally before upload.</span></div></div>
      <p className="selected-file">You can connect cloud storage from the Storage page after setup.</p>
      <button className="button primary wide" onClick={() => setStep("policy")}>Continue</button><button className="button text-button" onClick={() => setStep("policy")}>Skip for now</button>
    </div>}

    {step === "policy" && <div className="onboarding-content">
      <p className="eyebrow">Step 3 of 3</p><h1>Encrypted from the first copy</h1>
      <p className="lead">One connected target already keeps every file encrypted and private. Connect a second for mirror protection — if one target goes offline, you can still restore and repair from the other.</p>
      <div className="policy-card"><strong>Protection policy</strong><span>1 target: encrypted, single copy · 2 targets: Mirror 2×, verified</span></div>
      <button className="button primary wide" onClick={() => setStep("finish")}>Review setup</button>
    </div>}

    {step === "finish" && <div className="onboarding-content">
      <div className="success-icon">✓</div><h1>Your vault is ready</h1>
      <p className="lead">Connect storage from the dashboard, then upload your first file. It will remain private from the storage provider.</p>
      <button className="button primary wide" onClick={() => setStep(null)}>Go to dashboard</button>
    </div>}
  </div></div>;
}
