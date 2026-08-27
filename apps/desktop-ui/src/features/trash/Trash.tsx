import { useState } from "react";
import { Trash2 } from "lucide-react";
import type { FileDeletionChallenge, TrashFile } from "../../commands";
import { formatBytes } from "../../app/types";
import { ConfirmDialog } from "../../components/ui/ConfirmDialog";
import { DataTable, type DataTableColumn } from "../../components/ui/DataTable";
import { EmptyState } from "../../components/ui/EmptyState";
import { Page } from "../../components/ui/Page";

const COLUMNS: DataTableColumn<TrashFile>[] = [
  { key: "name", label: "Name", width: "minmax(0,2fr)" },
  { key: "size", label: "Size", width: "110px" },
  { key: "status", label: "Status", width: "minmax(130px,1fr)" },
];

export function Trash({ items, onRefresh, onRestore, onPrepare, onConfirm, onEmptyTrash }: {
  items: TrashFile[]; onRefresh: () => void; onRestore: (fileId: string) => void;
  onPrepare: (fileId: string, mode: "permanent", retention: null) => Promise<FileDeletionChallenge>;
  onConfirm: (challenge: FileDeletionChallenge, text: string) => void;
  onEmptyTrash: () => void;
}) {
  const [challenge, setChallenge] = useState<FileDeletionChallenge | null>(null);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [emptying, setEmptying] = useState(false);
  const [emptyText, setEmptyText] = useState("");
  const startDelete = async (item: TrashFile) => {
    setTyped("");
    setError(null);
    try {
      setChallenge(await onPrepare(item.file.logical_file_id, "permanent", null));
    } catch {
      onRefresh();
      setError("This file changed state. Refresh Trash and try again.");
    }
  };
  return <Page title="Trash" subtitle="Trashed files remain recoverable until you permanently delete them.">
    <div className="toolbar trash-toolbar"><button className="button secondary" onClick={onRefresh}>Refresh</button><button className="button empty-trash-button" disabled={items.length === 0} onClick={() => { setEmptyText(""); setEmptying(true); }}><Trash2 size={15} aria-hidden="true" />Empty trash</button></div>
    {error && <p role="alert" className="error-text">{error}</p>}
    {items.length === 0 ? <EmptyState title="Trash is empty" body="Files moved to Trash will remain here until restored or permanently deleted." /> : <DataTable
      columns={COLUMNS}
      rows={items}
      rowKey={item => item.file.logical_file_id}
      renderCell={(item, key) => key === "name" ? item.file.name : key === "size" ? formatBytes(item.file.size_bytes ?? 0) : statusText(item)}
      actions={item => <>
        <button className="button small" onClick={() => onRestore(item.file.logical_file_id)}>Restore</button>
        <button className="button small danger-button" onClick={() => void startDelete(item)}>Delete</button>
      </>}
    />}
    {challenge && <ConfirmDialog title="Delete permanently?" confirmLabel="Delete permanently" destructive disabled={typed !== challenge.expectedConfirmation} onCancel={() => setChallenge(null)} onConfirm={() => { onConfirm(challenge, typed); setChallenge(null); }}>
      <p><strong>{challenge.displayName}</strong> and all of its versions will be deleted from Undercloud and connected storage providers. This cannot be undone.</p><label>Type the exact filename: <input value={typed} onChange={event => setTyped(event.target.value)} aria-label="Exact filename confirmation" /></label>
    </ConfirmDialog>}
    {emptying && <ConfirmDialog title="Empty trash?" confirmLabel="Empty trash" destructive disabled={emptyText !== "EMPTY"} onCancel={() => setEmptying(false)} onConfirm={() => { onEmptyTrash(); setEmptying(false); }}>
      <p>All files in Trash will be permanently deleted and cannot be restored.</p><label><span>Type <strong>EMPTY</strong> to continue</span><input value={emptyText} onChange={event => setEmptyText(event.target.value)} aria-label="Empty trash confirmation" /></label>
    </ConfirmDialog>}
  </Page>;
}

function statusText(item: TrashFile) { if (item.retryClassification === "reauthorization_required") return "Reauthorization required"; if (item.retryClassification === "permission_required") return "Permission required"; if (item.retryClassification === "retry_scheduled") return "Retry scheduled"; if (item.state === "delete_incomplete") return "Deletion incomplete"; if (item.purgeAfter) { const days = Math.ceil((Number(item.purgeAfter) - Date.now()) / 86_400_000); return days > 0 ? `Deleted in ${days} day${days === 1 ? "" : "s"}` : "Deletion due"; } return "In Trash"; }
