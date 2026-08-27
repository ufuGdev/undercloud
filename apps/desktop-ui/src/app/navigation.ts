import type { View } from "./types";

export const primaryNavigation: Array<{ key: View; icon: string; label: string }> = [
  { key: "dashboard", icon: "dashboard", label: "Dashboard" },
  { key: "files", icon: "files", label: "Files" },
  { key: "storage", icon: "storage", label: "Storage" },
  { key: "activity", icon: "activity", label: "Activity" },
  { key: "trash", icon: "trash", label: "Trash" },
];

export const secondaryNavigation: Array<{ key: View; icon: string; label: string }> = [
  { key: "settings", icon: "settings", label: "Settings" },
  { key: "recovery", icon: "recovery", label: "Recovery" },
  { key: "help", icon: "help", label: "Help" },
];
