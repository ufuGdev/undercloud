import { describe, expect, it } from "vitest";
import { clearSensitiveInputs, healthLabel, protectedCapacity, safeError } from "./app/types";
import { primaryNavigation, secondaryNavigation } from "./app/navigation";
import { HealthBadge } from "./components/ui/Badge";

describe("health presentation", () => {
  it("uses text labels for every health state", () => {
    expect(Object.keys(healthLabel)).toHaveLength(6);
    expect(healthLabel.degraded).toBe("Degraded");
    expect(healthLabel.provider_unavailable).toBe("Provider unavailable");
  });

  it("does not call a catalogued file not uploaded when health is pending", () => {
    const element = HealthBadge({ file: { logical_file_id: "file", name: "report", mime: null, file_version_id: "version", health: null } });
    expect(JSON.stringify(element)).toContain("Health pending");
  });
});

describe("secret input handling", () => {
  it("clears every submitted secret field", () => {
    expect(clearSensitiveInputs()).toEqual({ password: "", currentPassword: "", newPassword: "", recoveryPassphrase: "" });
  });
});

describe("capacity presentation", () => {
  it("uses the limiting target for two-copy protection", () => {
    expect(protectedCapacity([100, 60])).toBe(60);
  });

  it("reports a single connected target's own capacity", () => {
    expect(protectedCapacity([100])).toBe(100);
  });

  it("reports nothing with no connected targets", () => {
    expect(protectedCapacity([])).toBeNull();
  });
});

describe("error presentation", () => {
  it("translates a known backend code to its friendly message", () => {
    expect(safeError({ code: "locked" })).toBe("Unlock the vault to continue.");
  });

  it("does not expose raw backend text or internal identifiers", () => {
    const rendered = safeError({ code: "catalog_error", message: "prepare_file_deletion failed (invalid_transition) Diagnostic ID: 123e4567-e89b-12d3-a456-426614174000" });
    expect(rendered).not.toMatch(/Diagnostic ID|invalid_transition|123e4567-e89b-12d3-a456-426614174000|unknown/);
    expect(rendered).toBe("Undercloud could not complete this action. Try again.");
  });

  it("maps repair and deletion failures to actionable messages", () => {
    expect(safeError({ code: "provider_unavailable" })).toBe("Connect another storage account to repair this file.");
    expect(safeError({ code: "provider_authentication_required" })).toContain("Reconnect");
    expect(safeError({ code: "invalid_transition" })).toContain("Refresh");
  });

  it("falls back to a generic message only when nothing else is available", () => {
    expect(safeError("not an error object")).toBe("Undercloud could not complete that operation.");
  });
});

describe("application navigation", () => {
  it("exposes the primary and secondary product screens", () => {
    expect(primaryNavigation.map(item => item.key)).toEqual(["dashboard", "files", "storage", "activity", "trash"]);
    expect(secondaryNavigation.map(item => item.key)).toEqual(["settings", "recovery", "help"]);
  });
});
