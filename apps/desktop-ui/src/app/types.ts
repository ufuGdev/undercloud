import type { ReactNode } from "react";
import type { Health, Status } from "../commands";

export type View = "dashboard" | "files" | "trash" | "storage" | "activity" | "recovery" | "settings" | "help";
export type OnboardingStep = "welcome" | "vault" | "storage" | "policy" | "finish";
export type PickKind = "vault" | "newVault" | "folder" | "source" | "destination" | "kit" | "newKit";
export type Counts = { healthy: number; degraded: number; risk: number; unavailable: number };
export type PageProps = { title: string; subtitle: string; children: ReactNode };

export const healthLabel: Record<Health, string> = {
  healthy: "Protected",
  degraded: "Degraded",
  at_risk: "At risk",
  unrecoverable: "Unavailable",
  provider_unavailable: "Provider unavailable",
  health_check_timeout: "Health check timed out",
};

export const healthTone: Record<Health, string> = {
  healthy: "good",
  degraded: "warn",
  at_risk: "danger",
  unrecoverable: "danger",
  provider_unavailable: "muted",
  health_check_timeout: "muted",
};

export function clearSensitiveInputs() {
  return { password: "", currentPassword: "", newPassword: "", recoveryPassphrase: "" };
}

export function protectedCapacity(freeBytes: number[]): number | null {
  return freeBytes.length < 1 ? null : Math.min(...freeBytes);
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 MB";
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`;
  if (bytes >= 1e9) return `${Math.round(bytes / 1e9)} GB`;
  return `${Math.max(1, Math.round(bytes / 1e6))} MB`;
}

export function safeError(error: unknown, code: string = safeErrorCode(error)): string {
  const messages: Record<string, string> = {
    authentication_failed: "That password was not accepted. Your vault is still locked.",
    locked: "Unlock the vault to continue.",
    destination_exists: "That destination already exists.",
    duplicate_provider: "That storage target is already connected.",
    invalid_transition: "This file’s state changed. Refresh and try again.",
    unsupported_recovery_version: "This recovery kit version is not supported.",
    stale_recovery_snapshot: "This recovery kit is out of date. Export a newer kit and try again.",
    invalid_recovery_kit: "This recovery kit is invalid or damaged.",
    recovery_destination_exists: "Choose a new, empty vault location for recovery.",
    provider_unavailable: "Connect another storage account to repair this file.",
    source_unavailable: "The selected file is no longer available.",
    invalid_provider_configuration: "Check the storage settings and try again.",
    credential_store_unavailable: "The system credential store is unavailable.",
    provider_not_configured: "This provider is not configured in this build.",
    provider_authentication_required: "Provider authorization expired or was revoked. Reconnect the provider.",
    provider_permission_denied: "Permission was denied or the browser callback was rejected.",
    provider_temporarily_unavailable: "Authorization could not complete. Check the browser callback and try again.",
    provider_request_rejected: "The storage provider rejected that request. This isn't a browser or authorization problem — retrying as-is likely won't help.",
    oauth_invalid_grant: "Google rejected the one-time authorization code. Start a new connection attempt.",
    oauth_invalid_client: "The configured Google OAuth application was rejected. Check the build configuration.",
    oauth_unauthorized_client: "This OAuth application is not allowed to use the desktop authorization flow.",
    oauth_invalid_request: "Google rejected the authorization request. Start a new connection attempt.",
    oauth_redirect_uri_mismatch: "Google rejected the callback address during token exchange. Rebuild and start a fresh connection attempt.",
    oauth_pkce_rejected: "Google rejected the PKCE verification. Rebuild the application and start a fresh connection attempt.",
    oauth_code_rejected: "Google rejected the authorization code. Start a fresh connection attempt without reusing the browser page.",
    oauth_client_id_rejected: "Google rejected the OAuth client identifier during token exchange. Check the configured build ID.",
    oauth_policy_blocked: "Google blocked this application during policy validation. The OAuth registration or requested use must be reviewed with Google.",
    oauth_rejected: "Google rejected the token exchange. Check the OAuth application configuration.",
    oauth_response_invalid: "Google returned an invalid token response. Check the OAuth application configuration.",
    oauth_endpoint_unreachable: "Undercloud could not reach Google’s token service. Check the network connection and try again.",
    provider_health_check_failed: "Authorization succeeded, but Undercloud could not verify Google Drive access.",
  provider_error: "The storage provider could not complete that operation.",
  provider_object_missing: "A required encrypted object is missing from storage.",
  provider_integrity_mismatch: "A stored encrypted object failed integrity verification.",
  provider_invalid_locator: "A stored object reference is invalid.",
  provider_io_error: "The local storage could not read or write an object.",
    catalog_error: "Undercloud could not complete this action. Try again.",
    format_error: "The encrypted file format was not accepted.",
    chunking_error: "The file could not be prepared for upload.",
    io_error: "The local file operation could not be completed.",
    unrecoverable: "This file cannot currently be restored from the available storage.",
    vault_not_found: "No vault exists at that location. Choose a different vault or create a new one.",
    invalid_file_name: "This file's stored name isn't safe to restore as-is. Rename it and try again.",
  };
  const base = messages[code] ?? "Undercloud could not complete that operation.";
  return base;
}

export function safeErrorCode(error: unknown): string {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : "unknown";
}

export function safeErrorMessage(error: unknown): string | undefined {
  return error instanceof Error && error.message ? error.message : undefined;
}

export function safeErrorDetail(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("detail" in error)) return undefined;
  const detail = (error as { detail: unknown }).detail;
  return typeof detail === "string" ? detail : undefined;
}

export function safeErrorIncidentId(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("incident_id" in error)) return undefined;
  const value = (error as { incident_id: unknown }).incident_id;
  return typeof value === "string" && value.length < 80 ? value : undefined;
}

export type VaultState = {
  status: Status;
  unlocked: boolean;
};

export const AUTOLOCK_KEY = "undercloud.autolockMinutes";
export const AUTOLOCK_CHANGED_EVENT = "undercloud-autolock-changed";
