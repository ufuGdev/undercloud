import type { ProviderSummary } from "../../commands";
import { DataTable, type DataTableColumn } from "../../components/ui/DataTable";
import { EmptyState } from "../../components/ui/EmptyState";
import { Page } from "../../components/ui/Page";
import { formatBytes } from "../../app/types";
import { CloudProviderPanel } from "./CloudProviderPanel";

type Row = { id: string; provider: ProviderSummary | undefined };
const COLUMNS: DataTableColumn<Row>[] = [
  { key: "name", label: "Account", width: "minmax(0,1.6fr)" },
  { key: "kind", label: "Provider", width: "minmax(0,1fr)" },
  { key: "status", label: "Status", width: "110px" },
  { key: "usage", label: "Usage", width: "150px" },
];

function providerLabel(kind: string | undefined) {
  if (kind === "google_drive") return "Google Drive";
  if (kind === "onedrive") return "OneDrive";
  if (kind === "dropbox") return "Dropbox";
  return kind ? kind.replaceAll("_", " ").replace(/\b\w/g, character => character.toUpperCase()) : "Cloud provider";
}

function usageLabel(provider: ProviderSummary | undefined) {
  if (!provider || provider.used_bytes == null) return "Unavailable";
  const used = formatBytes(provider.used_bytes);
  return provider.quota_known && provider.total_bytes != null
    ? `${used} / ${formatBytes(provider.total_bytes)}`
    : used;
}

export function Storage({ targets, providers, onRemove, onRename }: {
  targets: string[];
  providers: ProviderSummary[];
  onRemove: (id: string) => void;
  onRename: (id: string, name: string) => void;
}) {
  const rows: Row[] = targets.map((id, index) => ({ id, provider: providers.find(item => item.id === id) ?? providers[index] }));
  return <Page title="Storage" subtitle="Connected providers receive encrypted objects only.">
    <CloudProviderPanel />
    <h2 className="section-title">Registered providers <span className="count">{rows.length}</span></h2>
    {rows.length === 0 ? <EmptyState title="No providers registered" body="Connect storage before relying on protected copies." /> : <DataTable
      columns={COLUMNS}
      rows={rows}
      rowKey={row => row.id}
      renderCell={(row, key) => key === "name"
        ? (row.provider?.display_name ?? "Storage account")
        : key === "kind"
          ? providerLabel(row.provider?.kind)
          : key === "status"
            ? <span className={`badge ${row.provider?.connected ? "good" : "warn"}`}>{row.provider?.connected ? "Connected" : "Offline"}</span>
            : <span title={usageLabel(row.provider)}>{usageLabel(row.provider)}</span>}
      actions={row => <>
        <button className="button small" onClick={() => { const name = window.prompt("Account name", row.provider?.display_name ?? ""); if (name?.trim()) void onRename(row.id, name.trim()); }}>Rename</button>
        <button className="button small" onClick={() => onRemove(row.id)}>Remove</button>
      </>}
    />}
  </Page>;
}
