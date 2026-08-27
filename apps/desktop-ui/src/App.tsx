import { AppShell } from "./components/layout/AppShell";
import { Dashboard } from "./features/dashboard/Dashboard";
import { Activity } from "./features/activity/Activity";
import { Files } from "./features/files/Files";
import { Help } from "./features/help/Help";
import { Onboarding } from "./features/onboarding/Onboarding";
import { RecoveryImport } from "./features/onboarding/RecoveryImport";
import { UnlockCard } from "./features/onboarding/UnlockCard";
import { Recovery } from "./features/recovery/Recovery";
import { Settings } from "./features/settings/Settings";
import { Storage } from "./features/storage/Storage";
import { Trash } from "./features/trash/Trash";
import type { PickKind, View } from "./app/types";
import { useVaultApp } from "./hooks/useVaultApp";
import { commands } from "./commands";

export { clearSensitiveInputs, healthLabel, healthTone, protectedCapacity, safeError } from "./app/types";

export default function App() {
  const app = useVaultApp();

  const createRecoveryImport = () => <RecoveryImport
    kitPath={app.recoveryPath}
    catalogPath={app.vaultPath}
    passphrase={app.recoveryPassphrase}
    setPassphrase={app.setRecoveryPassphrase}
    onPick={app.pick}
    onBack={() => app.setRecoveryImport(false)}
    onImport={() => void app.run(async () => {
      if (!app.recoveryPath || !app.vaultPath || !app.recoveryPassphrase) throw new Error("Choose the kit, a new vault location, and a passphrase.");
      app.setStatus(await commands.importKit(app.recoveryPath, app.vaultPath, app.recoveryPassphrase));
      app.clearSecrets(); app.setRecoveryImport(false); app.setOnboarding(null); app.setMessage("Recovery imported. Reconnect storage to restore files.");
    })}
    error={app.error}
  />;

  if (app.recoveryImport) return createRecoveryImport();
  if (app.onboarding && !app.unlocked) return <Onboarding
    step={app.onboarding}
    setStep={app.setOnboarding}
    password={app.password}
    setPassword={app.setPassword}
    vaultName={app.vaultName}
    setVaultName={app.setVaultName}
    vaultPath={app.vaultPath}
    onPick={app.pick}
    onCreate={app.createVault}
    onOpen={app.openVault}
    initialMode={app.vaultPath ? "open" : "create"}
    onUnlock={app.unlock}
    onRecover={app.createRecoveryImport}
    status={app.status}
    error={app.error}
    message={app.message}
    vaults={app.library?.vaults}
    onSelectVault={app.setVaultPath}
  />;

  return <AppShell view={app.view} vaultName={app.library?.vaults.find(vault => vault.catalogPath === app.vaultPath)?.name ?? "Vault"} targetCount={app.targets.length} vaults={app.library?.vaults} currentPath={app.vaultPath} onSwitchVault={path => void app.switchVault(path)} onNavigate={app.setView} onLock={() => void app.lock()} onDismissNotice={app.clearFeedback} error={app.error} message={app.message} onUndo={app.undoFileId ? () => void app.run(async () => { await commands.restoreFromTrash(app.undoFileId!); app.setUndoFileId(null); await app.refresh(); app.setMessage("File restored from Trash."); }) : undefined} initialization={app.initialization} onRetryInitialization={() => void app.retryInitialization()}>
    {!app.unlocked && <UnlockCard password={app.password} setPassword={app.setPassword} onUnlock={() => void app.unlock()} onOpen={() => app.setOnboarding("vault")} />}
    {app.unlocked && <CurrentPage app={app} />}
  </AppShell>;
}

function CurrentPage({ app }: { app: ReturnType<typeof useVaultApp> }) {
  const moveToTrash = (file: import("./commands").FileSummary, retention: 30 | 60 | 90 | null) => void app.run(async () => { const challenge = await commands.prepareFileDeletion(file.logical_file_id, "trash", retention); await commands.confirmFileDeletion(challenge.challengeId, challenge.expectedConfirmation); app.setUndoFileId(file.logical_file_id); await app.refresh(); app.setMessage("Moved to Trash. You can restore it from Trash."); });
  const restoreTrash = (fileId: string) => void app.run(async () => { await commands.restoreFromTrash(fileId); await app.refresh(); app.setMessage("File restored from Trash."); });
  const runUpload = () => void app.run(async () => {
    if (!app.sourcePath || !app.logicalName) throw new Error("Choose a file first.");
    const idempotencyKey = app.uploadKeyId || crypto.randomUUID();
    app.setProgress(null);
    await commands.upload(app.sourcePath, app.logicalName, idempotencyKey);
    await app.refresh(); app.setSourcePath(""); app.setLogicalName(""); app.setUploadKeyId(""); app.setMessage("Upload complete.");
  });

  const runRestore = (file: import("./commands").FileSummary) => void app.run(async () => {
    const destination = app.restoreMode === "fixed"
      ? app.restoreDirectory
      : (await commands.pickFolder()).path;
    if (!destination) throw new Error("Choose a restore folder first.");
    await commands.restore(file.file_version_id!, destination, file.name); app.setMessage("Restore complete.");
  });

  const runRepair = (file: import("./commands").FileSummary) => app.run(async () => {
    if (!file.file_version_id) throw new Error("This file has no current version to repair.");
    await commands.repair(file.file_version_id);
    await app.refresh(); app.setMessage("Repair complete.");
  });

  switch (app.view) {
    case "dashboard": return <Dashboard files={app.files} counts={app.counts} providers={app.providers} onNavigate={app.setView} onUpload={() => app.setView("files")} loading={app.initialization?.state === "loading"} />;
    case "files": return <Files files={app.files} sourcePath={app.sourcePath} logicalName={app.logicalName} setLogicalName={app.setLogicalName} progress={app.progress} onPick={app.pick} onRefresh={() => void app.run(app.refresh)} onUpload={runUpload} onRestore={runRestore} onRepair={runRepair} onVerify={async file => { if (!file.file_version_id) return; await app.run(async () => { await commands.health(file.file_version_id!); await app.refresh(); app.setMessage("Verification complete."); }); }} onVerifyAll={async () => { await app.run(async () => { const summary = await commands.verifyAll(); await app.refresh(); app.setMessage(`${summary.files_protected} protected, ${summary.files_degraded} degraded, ${summary.files_at_risk} at risk.`); }); }} onDropFiles={async paths => { if (!app.unlocked) return; await app.run(async () => { for (const path of [...new Set(paths)]) { const name = path.split(/[\\/]/).pop(); if (name) await commands.upload(path, name, crypto.randomUUID()); } await app.refresh(); app.setMessage("Dropped files uploaded."); }); }} onMoveToTrash={moveToTrash} onCancel={() => void commands.cancelUpload()} restoreMode={app.restoreMode} restoreDirectory={app.restoreDirectory} />;
    case "trash": return <Trash items={app.trash} onRefresh={() => void app.run(app.refresh)} onRestore={restoreTrash} onPrepare={(fileId, mode, retention) => commands.prepareFileDeletion(fileId, mode, retention)} onConfirm={(challenge, text) => void app.run(async () => { await commands.confirmFileDeletion(challenge.challengeId, text); await app.refresh(); app.setMessage("Permanent deletion requested. Provider cleanup may continue in the background."); })} onEmptyTrash={() => void app.run(async () => { for (const item of app.trash) { const challenge = await commands.prepareFileDeletion(item.file.logical_file_id, "permanent", null); await commands.confirmFileDeletion(challenge.challengeId, challenge.expectedConfirmation); } await app.refresh(); app.setMessage("Trash emptied. Provider cleanup may continue in the background."); })} />;
    case "storage": return <Storage targets={app.targets} providers={app.providers} onRename={(id, name) => void app.run(async () => { await commands.renameProvider(id, name); await app.refresh(); })} onRemove={id => void app.run(async () => { if (window.confirm("Remove this storage target? Files may become degraded.")) { await commands.removeProvider(id); await app.refresh(); } })} />;
    case "activity": return <Activity />;
    case "recovery": return <Recovery recoveryPath={app.recoveryPath} passphrase={app.recoveryPassphrase} setPassphrase={app.setRecoveryPassphrase} onPick={app.pick} onExport={() => void app.run(async () => { if (!app.recoveryPath) throw new Error("Choose a kit destination first."); await commands.exportKit(app.recoveryPath, app.recoveryPassphrase); app.clearSecrets(); app.setMessage("Recovery kit exported."); })} />;
    case "settings": return <Settings current={app.currentPassword} next={app.newPassword} setCurrent={app.setCurrentPassword} setNext={app.setNewPassword} onChange={() => void app.run(async () => { await commands.changePassword(app.currentPassword, app.newPassword); app.clearSecrets(); app.setMessage("Password changed."); })} vaultName={app.library?.vaults.find(vault => vault.catalogPath === app.vaultPath)?.name ?? ""} onRenameVault={app.renameVault} libraryRoot={app.library?.root ?? "Unavailable"} vaultPath={app.vaultPath} onChooseLibrary={() => void app.chooseVaultLibrary()} onOpenLibrary={() => void app.run(app.openVaultLibrary)} onMoveVault={() => void app.run(async () => { await app.moveVaultToLibrary(); app.setMessage("Vault moved to the library."); })} onResetLibrary={() => void app.resetVaultLibrary()} restoreMode={app.restoreMode} restoreDirectory={app.restoreDirectory} onRestoreModeChange={app.setRestoreMode} onChooseRestoreDirectory={() => void app.chooseRestoreDirectory()} />;
    case "help": return <Help />;
  }
}

export type { PickKind, View };
