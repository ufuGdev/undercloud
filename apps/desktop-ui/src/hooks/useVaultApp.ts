import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import type { CloudProviderInput, FileSummary, LibraryInfo, ProviderSummary, Status, TrashFile, UploadProgress, VaultInitializationEvent } from "../commands";
import { commands } from "../commands";
import type { OnboardingStep, PickKind, View } from "../app/types";
import { clearSensitiveInputs, safeError, safeErrorCode } from "../app/types";
import { useAutoLock } from "./useAutoLock";

const LAST_VAULT_PATH_KEY = "undercloud.lastVaultPath";
const RESTORE_MODE_KEY = "undercloud.restoreMode";
const RESTORE_DIRECTORY_KEY = "undercloud.restoreDirectory";

function rememberedVaultPath(): string {
  if (typeof window === "undefined") return "";
  return window.localStorage.getItem(LAST_VAULT_PATH_KEY) ?? "";
}

function rememberedRestoreMode(): "ask" | "fixed" {
  if (typeof window === "undefined") return "ask";
  return window.localStorage.getItem(RESTORE_MODE_KEY) === "fixed" && window.localStorage.getItem(RESTORE_DIRECTORY_KEY) ? "fixed" : "ask";
}

export function useVaultApp() {
  const [status, setStatus] = useState<Status>({ state: "locked", vault_id: null });
  const [view, setViewState] = useState<View>("dashboard");
  const setView = useCallback((next: View) => {
    setViewState(next);
    void commands.pageView(next);
  }, []);
  const [vaultPath, setVaultPathState] = useState(rememberedVaultPath);
  const [onboarding, setOnboarding] = useState<OnboardingStep | null>(() =>
    rememberedVaultPath() ? null : "welcome"
  );
  const [recoveryImport, setRecoveryImport] = useState(false);
  const [files, setFiles] = useState<FileSummary[]>([]);
  const [trash, setTrash] = useState<TrashFile[]>([]);
  const [undoFileId, setUndoFileId] = useState<string | null>(null);
  const [targets, setTargets] = useState<string[]>([]);
  const [providers, setProviders] = useState<ProviderSummary[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [password, setPassword] = useState("");
  const [vaultName, setVaultName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [recoveryPassphrase, setRecoveryPassphrase] = useState("");
  const [recoveryPath, setRecoveryPath] = useState("");
  const [sourcePath, setSourcePath] = useState("");
  const [logicalName, setLogicalName] = useState("");
  const [restoreMode, setRestoreModeState] = useState<"ask" | "fixed">(rememberedRestoreMode);
  const [restoreDirectory, setRestoreDirectory] = useState(() => typeof window === "undefined" ? "" : window.localStorage.getItem(RESTORE_DIRECTORY_KEY) ?? "");
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [uploadKeyId, setUploadKeyId] = useState("");
  const [library, setLibrary] = useState<LibraryInfo | null>(null);
  const [initialization, setInitialization] = useState<{ state: "loading" | "failed"; stage: string; detail: string; operationId: string; error?: string } | null>(null);
  const openedPathRef = useRef<string | null>(null);

  const refresh = useCallback(async () => {
    setFiles(await commands.listFiles());
    setTrash(await commands.listTrash());
    setTargets(await commands.targetIds());
    setProviders(await commands.providerSummaries());
  }, []);

  const clearSecrets = useCallback(() => {
    const empty = clearSensitiveInputs();
    setPassword(empty.password);
    setCurrentPassword(empty.currentPassword);
    setNewPassword(empty.newPassword);
    setRecoveryPassphrase(empty.recoveryPassphrase);
  }, []);


  const setVaultPath = useCallback((path: string) => {
    setVaultPathState(path);
    if (typeof window !== "undefined" && path) {
      window.localStorage.setItem(LAST_VAULT_PATH_KEY, path);
    }
  }, []);

  const setRestoreMode = useCallback((mode: "ask" | "fixed") => {
    setRestoreModeState(mode);
    if (typeof window !== "undefined") window.localStorage.setItem(RESTORE_MODE_KEY, mode);
  }, []);

  const chooseRestoreDirectory = useCallback(async () => {
    const result = await commands.pickFolder();
    if (!result.path) return;
    setRestoreDirectory(result.path);
    if (typeof window !== "undefined") window.localStorage.setItem(RESTORE_DIRECTORY_KEY, result.path);
    setRestoreMode("fixed");
  }, [setRestoreMode]);

  const run = useCallback(async (action: () => Promise<void>) => {
    setError("");
    setMessage("");
    try { await action(); } catch (reason) { const code = safeErrorCode(reason); setError(safeError(reason, code)); setInitialization(previous => previous ? { ...previous, state: "failed", detail: "Vault initialization failed. Retry from here or check Logs in Settings." } : previous); } finally { clearSecrets(); }
  }, [clearSecrets]);

  const clearFeedback = useCallback(() => { setError(""); setMessage(""); }, []);

  const pick = useCallback(async (kind: PickKind) => {
    const result = kind === "folder"
      ? await commands.pickFolder()
      : await commands.pickFile(kind === "newKit" || kind === "newVault");
    if (!result.path) return;
    if (kind === "source") {
      setSourcePath(result.path);
      setLogicalName(result.path.split(/[\\/]/).pop() ?? "");
      setUploadKeyId(crypto.randomUUID());
    } else if (kind === "kit" || kind === "newKit") setRecoveryPath(result.path);
    else setVaultPath(result.path);
  }, []);

  const lock = useCallback(async () => {
    await run(async () => {
      setStatus(await commands.lockVault());
      openedPathRef.current = vaultPath;
      setFiles([]); setTrash([]); setMessage("Vault locked.");
    });
  }, [run, vaultPath]);

  const autoLock = useCallback(() => { void lock(); }, [lock]);
  useAutoLock(status, progress?.bytes_processed ?? null, autoLock);

  useEffect(() => {
    void run(async () => {
      const next = await commands.status();
      setStatus(next);
      if (next.state === "unlocked") { setOnboarding(null); await refresh(); }
    });
  }, [refresh, run]);

  useEffect(() => {
    void commands.vaultLibraryInfo().then(setLibrary).catch(() => undefined);
    const unlisten = listen<VaultInitializationEvent>("vault-initialization", event => {
      const next = event.payload;
      if (next.stage === "ready") return;
      setInitialization({ state: next.stage === "failed" ? "failed" : "loading", stage: next.stage, detail: next.detail, operationId: next.operationId, error: next.error ?? undefined });
    });
    return () => { void unlisten.then(stop => stop()); };
  }, []);

  useEffect(() => {
    const unlisten = listen<UploadProgress>("upload-progress", event => setProgress(event.payload));
    return () => { void unlisten.then(stop => stop()); };
  }, []);

  useEffect(() => {
    const onProvidersChanged = () => void refresh();
    window.addEventListener("undercloud-providers-changed", onProvidersChanged);
    return () => window.removeEventListener("undercloud-providers-changed", onProvidersChanged);
  }, [refresh]);

  const counts = useMemo(() => files.reduce((acc, file) => {
    // Bucket by the health value alone: `health_current: false` only means "from the last durable
    // observation, not re-verified this instant" (see HealthBadge's "Last known" treatment) -- it
    // must not itself inflate the attention count, or every file counts as at-risk forever, since
    // list_files always serves the cached (non-live) health path.
    if (file.health === "healthy") acc.healthy++;
    else if (file.health === "degraded") acc.degraded++;
    else if (file.health === "at_risk" || file.health === "provider_unavailable" || file.health === "health_check_timeout") acc.risk++;
    else if (file.health === "unrecoverable") acc.unavailable++;
    return acc;
  }, { healthy: 0, degraded: 0, risk: 0, unavailable: 0 }), [files]);

  const createVault = useCallback(async () => run(async () => {
    setStatus(await commands.createVault(vaultPath, password, vaultName));
    if (vaultPath) setVaultPath(vaultPath);
    clearSecrets(); setOnboarding(null); setMessage("Your vault is ready. Connect storage to protect uploads.");
  }), [clearSecrets, password, run, setVaultPath, vaultName, vaultPath]);

  const openVault = useCallback(async () => run(async () => {
    if (!vaultPath || !password) throw new Error("Choose a vault and enter its password.");
    setVaultPath(vaultPath);
    setInitialization({ state: "loading", stage: "opening_catalog", detail: "Opening encrypted catalog", operationId: crypto.randomUUID() });
    await commands.openVault(vaultPath);
    openedPathRef.current = vaultPath;
    setStatus(await commands.unlockVault(password));
    await refresh();
    setInitialization(null);
    setOnboarding(null); setView("dashboard"); setMessage("Vault unlocked.");
  }), [password, refresh, run, setVaultPath, vaultPath]);

  const unlock = useCallback(async () => run(async () => {
    setInitialization({ state: "loading", stage: "opening_catalog", detail: "Opening encrypted catalog", operationId: crypto.randomUUID() });
    if (vaultPath && openedPathRef.current !== vaultPath) {
      await commands.openVault(vaultPath);
      openedPathRef.current = vaultPath;
    }
    setStatus(await commands.unlockVault(password));
    clearSecrets(); await refresh(); setInitialization(null); setOnboarding(null); setView("dashboard"); setMessage("Vault unlocked.");
  }), [clearSecrets, password, refresh, run, vaultPath]);

  const retryInitialization = useCallback(async () => {
    try { await refresh(); setInitialization(null); }
    catch { setInitialization(previous => previous ? { ...previous, state: "failed", detail: "Vault is still unavailable. Retry or check Logs in Settings." } : null); }
  }, [refresh]);

  const chooseVaultLibrary = useCallback(async () => {
    const result = await commands.pickFolder();
    if (result.path) setLibrary(await commands.setVaultLibraryLocation(result.path));
  }, []);
  const resetVaultLibrary = useCallback(async () => setLibrary(await commands.resetVaultLibraryLocation()), []);
  const openVaultLibrary = useCallback(async () => { await commands.openVaultLibraryFolder(); }, []);
  const moveVaultToLibrary = useCallback(async () => {
    if (!vaultPath) throw new Error("Choose a vault first.");
    const next = await commands.lockVault();
    setStatus(next);
    const movedPath = await commands.moveVaultToLibrary(vaultPath);
    setVaultPath(movedPath);
    setFiles([]); setTrash([]);
  }, [setVaultPath, vaultPath]);
  const renameVault = useCallback(async (catalogPath: string, name: string) => {
    setLibrary(await commands.renameVault(catalogPath, name));
  }, []);
  const switchVault = useCallback(async (path: string) => {
    if (!path || path === vaultPath) return;
    await run(async () => {
      if (status.state === "unlocked") await commands.lockVault();
      setStatus({ state: "locked", vault_id: null });
      setFiles([]); setTrash([]); setTargets([]); setProviders([]);
      openedPathRef.current = null;
      setVaultPath(path);
      setOnboarding("vault");
      setView("dashboard");
      setMessage("Vault selected. Enter its password to unlock it.");
    });
  }, [run, setVaultPath, status.state, vaultPath]);

  const createRecoveryImport = useCallback(() => setRecoveryImport(true), []);

  return {
    status, setStatus, view, setView, onboarding, setOnboarding, recoveryImport, setRecoveryImport,
    files, trash, targets, providers, counts, message, setMessage, error, vaultPath, setVaultPath, password, setPassword, vaultName, setVaultName, undoFileId, setUndoFileId,
    currentPassword, setCurrentPassword, newPassword, setNewPassword, recoveryPassphrase,
    setRecoveryPassphrase, recoveryPath, setRecoveryPath, sourcePath, setSourcePath, logicalName,
    setLogicalName, restoreMode, restoreDirectory, setRestoreMode, chooseRestoreDirectory,
    progress, setProgress, uploadKeyId, setUploadKeyId, clearFeedback, clearSecrets, run, pick,
    refresh, lock, createVault, openVault, unlock, createRecoveryImport, unlocked: status.state === "unlocked", library, initialization,
    retryInitialization, chooseVaultLibrary, resetVaultLibrary, openVaultLibrary, moveVaultToLibrary, renameVault, switchVault,
  };
}
