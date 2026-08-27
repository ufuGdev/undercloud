import { AlertTriangle, CheckCircle2, Cloud, Download, History, ShieldCheck, Upload, Wrench } from "lucide-react";
import type { FileSummary, ProviderSummary } from "../../commands";
import type { Counts, View } from "../../app/types";
import { formatBytes } from "../../app/types";
import { HealthBadge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { Page } from "../../components/ui/Page";
import type { ReactNode } from "react";

export function Dashboard({ files, counts, providers, onNavigate, onUpload, loading }: {
  files: FileSummary[]; counts: Counts; providers: ProviderSummary[]; onNavigate: (view: View) => void; onUpload: () => void; loading?: boolean;
}) {
  const totalBytes = files.reduce((sum, file) => sum + (file.size_bytes ?? 0), 0);
  const knownBytes = files.every(file => file.size_bytes !== null && file.size_bytes !== undefined);
  const needsAttention = counts.degraded + counts.risk + counts.unavailable;
  const connected = providers.filter(provider => provider.connected).length;
  const protection = loading ? "Vault is still loading" : needsAttention ? "Files need attention" : connected === 0 ? "Storage account disconnected" : "All files protected";
  const protectionTone = loading ? "loading" : needsAttention || connected === 0 ? "attention" : "protected";

  return <Page title="Dashboard" subtitle="Protection status at a glance.">
    <section className={`protection-hero ${protectionTone}`} aria-live="polite">
      {loading ? <span className="loading-spinner" aria-hidden="true" /> : protectionTone === "protected" ? <CheckCircle2 aria-hidden="true" /> : <AlertTriangle aria-hidden="true" />}
      <div><p className="eyebrow">Protection status</p><h2>{protection}</h2><p>{loading ? "Preparing your catalog and storage accounts." : `${counts.healthy} of ${files.length} files have verified protection.`}</p></div>
      {!loading && <span className="last-checked">Last checked from durable catalog state</span>}
    </section>
    <div className="metric-grid protection-metrics">
      <Metric label="Protected files" value={`${counts.healthy} / ${files.length}`} icon={<ShieldCheck />} />
      <Metric label="Needs attention" value={needsAttention} tone={needsAttention ? "warn" : ""} icon={<AlertTriangle />} />
      <Metric label="Protected data" value={knownBytes ? formatBytes(totalBytes) : "Unavailable"} hint={knownBytes ? "Logical plaintext size" : "File size is not fully known"} icon={<Cloud />} />
      <Metric label="Recovery kit" value="Not checked" hint="Open Recovery to review" icon={<Download />} />
    </div>
    {needsAttention > 0 && <section className="dashboard-section"><div className="section-heading"><div><h3>Needs attention</h3><p>Review these items to keep protection resilient.</p></div></div><div className="attention-list"><button className="attention-item" onClick={() => onNavigate("files")}><AlertTriangle size={18} /><span><strong>{needsAttention} files or storage accounts need attention</strong><small>Review files and repair missing copies.</small></span><Wrench size={17} /></button></div></section>}
    <section className="dashboard-section"><div className="section-heading"><div><h3>Storage accounts</h3><p>{connected} connected account{connected === 1 ? "" : "s"}.</p></div><button className="button text-button" onClick={() => onNavigate("storage")}>Manage storage →</button></div>{providers.length ? <div className="account-grid">{providers.map(provider => <AccountCard key={provider.id} provider={provider} />)}</div> : <EmptyState title="No storage connected" body="Connect Google Drive, OneDrive, or Dropbox to protect files." />}</section>
    <section className="dashboard-section"><div className="section-heading"><div><h3>Recent activity</h3><p>Recent durable operations will appear here.</p></div><button className="button text-button" onClick={() => onNavigate("activity")}>View all activity →</button></div><div className="recent-placeholder"><History size={18} /> Activity history is available on the Activity page.</div></section>
    {!loading && files.length === 0 && <div className="dashboard-next"><Upload size={19} /><span><strong>Start protecting a file</strong><small>Upload a file to create your first encrypted copies.</small></span><button className="button primary" onClick={onUpload}>Upload file</button></div>}
  </Page>;
}

function AccountCard({ provider }: { provider: ProviderSummary }) {
  const name = provider.display_name;
  const kind = provider.kind === "google_drive" ? "Google Drive" : provider.kind === "onedrive" ? "OneDrive" : "Dropbox";
  const state = provider.connected ? provider.health === "healthy" ? "Connected" : "Attention" : "Offline";
  const capacity = provider.quota_known && provider.total_bytes !== null ? `${formatBytes(Math.max(0, provider.total_bytes - (provider.used_bytes ?? 0)))} available` : "Capacity not reported";
  return <div className="account-card"><div className="account-icon"><Cloud size={20} /></div><div className="account-copy"><strong>{name}</strong><span>{kind}</span><small>{capacity}</small></div><span className={`badge ${state === "Connected" ? "good" : "warn"}`}>{state}</span></div>;
}

function Metric({ label, value, tone = "", hint, icon }: { label: string; value: number | string; tone?: string; hint?: string; icon: ReactNode }) {
  return <div className={`metric ${tone}`}><div className="metric-icon">{icon}</div><span>{label}</span><strong>{value}</strong>{hint && <em>{hint}</em>}</div>;
}
