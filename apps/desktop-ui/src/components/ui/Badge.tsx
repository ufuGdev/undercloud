import type { FileSummary } from "../../commands";
import { CircleDashed, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { healthLabel, healthTone } from "../../app/types";

export function HealthBadge({ file }: { file: FileSummary }) {
  const label = file.health ? healthLabel[file.health] : file.file_version_id ? "Health pending" : "Not uploaded";
  const Icon = !file.health || file.health === "provider_unavailable" || file.health === "health_check_timeout"
    ? CircleDashed
    : file.health === "healthy"
      ? ShieldCheck
      : file.health === "unrecoverable"
        ? ShieldX
        : ShieldAlert;
  const tone = file.health ? healthTone[file.health] : "muted";
  const title = file.health && file.health_current === false
    ? `Last durable observation: ${label}. Run a health check to verify it.`
    : label;
  return <span className={`file-health-icon ${tone}`} title={title} aria-label={title} role="status"><Icon size={17} aria-hidden="true" /></span>;
}

export function Badge({ tone, children }: { tone: string; children: React.ReactNode }) {
  return <span className={`badge ${tone}`}><span aria-hidden="true">●</span> {children}</span>;
}
