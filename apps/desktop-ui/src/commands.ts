import { invoke } from "@tauri-apps/api/core";

type BackendError = { code?: string; message?: string; incident_id?: string; retryable?: boolean };
const rawInvoke = invoke;
let activeUploadOperationId: string | null = null;
async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const operationId = typeof args?.operationId === "string" ? args.operationId : crypto.randomUUID();
  const payload = { ...(args ?? {}), operationId };
  try {
    const result = await rawInvoke<T>(command, payload);
    return result;
  }
  catch (reason) {
    const error = reason as BackendError;
    throw reason;
  }
}

export type Health = "healthy" | "degraded" | "at_risk" | "unrecoverable" | "provider_unavailable" | "health_check_timeout";
export type FileSummary = {
  logical_file_id: string;
  name: string;
  mime: string | null;
  file_version_id: string | null;
  size_bytes?: number | null;
  health: Health | null;
  health_current?: boolean;
  verified_copies?: number;
  required_copies?: number;
  last_verified_at?: string | null;
};
export type ProtectionTarget = { provider_name: string; provider_kind: string; connected: boolean; state: "complete" | "partial" | "missing" | "corrupt" | "verifying" | "unavailable"; verified_objects: number; expected_objects: number; repair_possible: boolean; last_verified_at: string | null };
export type ProtectionMap = { file_version_id: string; verified_copies: number; required_copies: number; last_verified_at: string | null; targets: ProtectionTarget[] };
export type TrashFile = { file: FileSummary; deletionId: string; state: string; purgeAfter: string | null; retryClassification: string | null; replicaCount: number };
export type FileDeletionChallenge = { challengeId: string; fileId: string; mode: "trash" | "permanent"; displayName: string; state: string; currentVersionId: string | null; expectedConfirmation: string; expiresAtUnixMs: number; operationId: string; replicaCount: number };
export type Status = { state: "locked" | "unlocked"; vault_id: string | null };
export type UploadProgress = { bytes_processed: number; total_bytes: number | null };
export type PickerResult = { path: string | null };
export type ProviderSummary = { id: string; kind: string; display_name: string; connected: boolean; health: "healthy" | "degraded" | "unavailable"; used_bytes: number | null; total_bytes: number | null; quota_known: boolean };
export type ActivityEvent = { id: string; operation_id: string; event_type: string; status: string; related_file_id: string | null; related_target_id: string | null; display_metadata: string; started_at: string; completed_at: string | null; transferred_bytes: number | null; error_code: string | null; retry_classification: string | null };
export type ActivityPage = { events: ActivityEvent[]; next_cursor: string | null };
export type CloudProviderInput = { kind: "google_drive" | "onedrive" | "dropbox" };
export type LoggingStatus = { directory: string; level: string; persistent: boolean; warning: string | null; application_version: string; build_profile: string };
export type RecoveryFreshness = { generation: number; exported_generation: number | null; exported_at: string | null; state: "never_created" | "current" | "outdated" };
export type VerifyAllSummary = { files_protected: number; files_degraded: number; files_at_risk: number; files_unrecoverable: number; failed: number };
export type VaultEntry = { id: string; name: string; catalogPath: string };
export type LibraryInfo = { root: string; vaults: VaultEntry[] };
export type VaultInitializationEvent = { stage: string; detail: string; operationId: string; providerIndex: number | null; providerTotal: number | null; error: string | null };

export const commands = {
  createVault: (catalogPath: string, password: string, name: string) => call<Status>("create_vault", { catalogPath, password, name }),
  openVault: (catalogPath: string) => call<Status>("open_vault", { catalogPath }),
  unlockVault: (password: string) => call<Status>("unlock_vault", { password }),
  lockVault: () => call<Status>("lock_vault"),
  status: () => call<Status>("vault_status"),
  vaultLibraryInfo: () => call<LibraryInfo>("vault_library_info"),
  setVaultLibraryLocation: (root: string) => call<LibraryInfo>("set_vault_library_location", { root }),
  resetVaultLibraryLocation: () => call<LibraryInfo>("reset_vault_library_location"),
  openVaultLibraryFolder: () => call<void>("open_vault_library_folder"),
  moveVaultToLibrary: (sourcePath: string) => call<string>("move_vault_to_library", { sourcePath }),
  renameVault: (catalogPath: string, name: string) => call<LibraryInfo>("rename_vault", { catalogPath, name }),
  pickFile: (save = false) => call<PickerResult>("pick_file", { save }),
  pickFolder: () => call<PickerResult>("pick_folder"),
  targetIds: () => call<string[]>("storage_target_ids"),
  providerSummaries: () => call<ProviderSummary[]>("provider_summaries"),
  addProvider: (root: string) => call<string>("add_local_provider", { root }),
  removeProvider: (target: string) => call<void>("remove_provider", { target }),
  renameProvider: (target: string, displayName: string) => call<void>("rename_provider", { target, displayName }),
  activityEvents: (filters: { cursor?: string; pageSize?: number; eventType?: string; status?: string; startedAfter?: string; startedBefore?: string } = {}) => call<ActivityPage>("activity_events", filters),
  authorizeCloudProvider: (input: CloudProviderInput) => call<string>("authorize_cloud_provider", { input }),
  cancelAuthorization: () => call<void>("cancel_authorization"),
  removeCloudProvider: (target: string, revoke = true) => call<void>("remove_cloud_provider", { target, revoke }),
  listFiles: () => call<FileSummary[]>("list_files"),
  protectionMap: (fileVersionId: string) => call<ProtectionMap>("protection_map", { fileVersionId }),
  listTrash: () => call<TrashFile[]>("list_trash"),
  prepareFileDeletion: (fileId: string, mode: "trash" | "permanent", retentionDays: 30 | 60 | 90 | null) => call<FileDeletionChallenge>("prepare_file_deletion", { fileId, mode, retentionDays }),
  confirmFileDeletion: (challengeId: string, confirmationText: string) => call<boolean>("confirm_file_deletion", { challengeId, confirmationText }),
  restoreFromTrash: (fileId: string) => call<void>("restore_from_trash", { fileId }),
  upload: (sourcePath: string, logicalName: string, idempotencyKey: string) =>
    (activeUploadOperationId = crypto.randomUUID(), call<void>("upload_file", { sourcePath, logicalName, idempotencyKey, operationId: activeUploadOperationId }).finally(() => { activeUploadOperationId = null; })),
  restore: (fileVersionId: string, destinationDir: string, fileName: string) => call<void>("restore_file", { fileVersionId, destinationDir, fileName }),
  cancelRestore: () => call<void>("cancel_restore"),
  cancelUpload: () => activeUploadOperationId ? call<void>("cancel_upload", { operationId: activeUploadOperationId }) : Promise.resolve(),
  health: (fileVersionId: string) => call<Health>("file_health", { fileVersionId }),
  verifyAll: () => call<VerifyAllSummary>("verify_all"),
  repair: (fileVersionId: string) => call<Health>("repair_file", { fileVersionId }),
  changePassword: (currentPassword: string, newPassword: string) => call<void>("change_password", { currentPassword, newPassword }),
  exportKit: (destination: string, passphrase: string) => call<void>("export_recovery_kit", { destination, passphrase }),
  importKit: (kitPath: string, catalogPath: string, passphrase: string) => call<Status>("import_recovery_kit", { kitPath, catalogPath, passphrase }),
  recoveryFreshness: () => call<RecoveryFreshness>("recovery_freshness"),
  loggingStatus: () => call<LoggingStatus>("logging_status"),
  openLogFolder: () => call<void>("open_log_folder"),
  pageView: (page: string) => call<void>("page_view", { page }),
};
