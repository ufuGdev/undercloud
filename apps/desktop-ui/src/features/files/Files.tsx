import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { Archive, Download, File as FileIcon, FileText, Film, Image as ImageIcon, Info, Music, Trash2, Wrench } from "lucide-react";
import { commands, type FileSummary, type ProtectionMap, type UploadProgress } from "../../commands";
import type { PickKind } from "../../app/types";
import { formatBytes, healthLabel } from "../../app/types";
import { HealthBadge } from "../../components/ui/Badge";
import { EmptyState } from "../../components/ui/EmptyState";
import { Page } from "../../components/ui/Page";
import { ConfirmDialog } from "../../components/ui/ConfirmDialog";
import { Select } from "../../components/ui/Select";

type Category = "image" | "video" | "audio" | "document" | "archive" | "other";

const IMAGE_EXTENSIONS = new Set(["jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "heic", "tiff", "avif"]);
const VIDEO_EXTENSIONS = new Set(["mp4", "mov", "mkv", "avi", "webm", "m4v", "wmv"]);
const AUDIO_EXTENSIONS = new Set(["mp3", "wav", "flac", "aac", "ogg", "m4a", "wma"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "bz2", "xz"]);
const DOCUMENT_EXTENSIONS = new Set(["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv", "rtf", "odt"]);

function categorize(file: FileSummary): Category {
  const mime = file.mime ?? "";
  if (mime.startsWith("image/")) return "image";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  if (mime === "application/pdf" || mime.startsWith("text/") || mime.includes("document") || mime.includes("spreadsheet") || mime.includes("presentation")) return "document";
  if (mime.includes("zip") || mime.includes("compressed") || mime.includes("archive")) return "archive";
  const ext = file.name.includes(".") ? file.name.split(".").pop()!.toLowerCase() : "";
  if (IMAGE_EXTENSIONS.has(ext)) return "image";
  if (VIDEO_EXTENSIONS.has(ext)) return "video";
  if (AUDIO_EXTENSIONS.has(ext)) return "audio";
  if (ARCHIVE_EXTENSIONS.has(ext)) return "archive";
  if (DOCUMENT_EXTENSIONS.has(ext)) return "document";
  return "other";
}

const CATEGORY_LABELS: Record<Category, string> = { image: "Image", video: "Video", audio: "Audio", document: "Document", archive: "Archive", other: "File" };

function fileTypeLabel(file: FileSummary) {
  if (file.mime) return file.mime;
  const extension = file.name.includes(".") ? file.name.split(".").pop()?.toLowerCase() : undefined;
  return extension ? `${CATEGORY_LABELS[categorize(file)]} (.${extension})` : CATEGORY_LABELS[categorize(file)];
}

function fileSizeLabel(bytes: number | null | undefined) {
  if (bytes == null) return "Unknown";
  const exact = new Intl.NumberFormat("en-US").format(bytes);
  if (bytes < 1_000) return `${bytes} B (${exact} bytes)`;
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(2)} KB (${exact} bytes)`;
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB (${exact} bytes)`;
  if (bytes < 1_000_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB (${exact} bytes)`;
  return `${(bytes / 1_000_000_000_000).toFixed(2)} TB (${exact} bytes)`;
}

const CATEGORY_ORDER: Category[] = ["image", "video", "audio", "document", "archive", "other"];
const CATEGORY_LABEL: Record<Category, string> = { image: "Images", video: "Video", audio: "Audio", document: "Documents", archive: "Archives", other: "Other" };
const CATEGORY_ICON: Record<Category, typeof FileIcon> = { image: ImageIcon, video: Film, audio: Music, document: FileText, archive: Archive, other: FileIcon };

export function Files({ files, sourcePath, logicalName, setLogicalName, progress, onPick, onRefresh, onUpload, onRestore, onRepair, onVerify, onVerifyAll, onDropFiles, onCancel, restoreMode, restoreDirectory, onMoveToTrash }: {
  files: FileSummary[];
  sourcePath: string;
  logicalName: string;
  setLogicalName: (value: string) => void;
  progress: UploadProgress | null;
  onPick: (kind: PickKind) => Promise<void>;
  onRefresh: () => void;
  onUpload: () => void;
  onRestore: (file: FileSummary) => void;
  onRepair: (file: FileSummary) => Promise<void>;
  onCancel: () => void;
  restoreMode: "ask" | "fixed";
  restoreDirectory: string;
  onMoveToTrash: (file: FileSummary, retention: 30 | 60 | 90 | null) => void;
  onVerify: (file: FileSummary) => Promise<void>;
  onVerifyAll: () => Promise<void>;
  onDropFiles: (paths: string[]) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Category | "all">("all");
  const [pending, setPending] = useState<FileSummary | null>(null);
  const [details, setDetails] = useState<FileSummary | null>(null);
  const [repairing, setRepairing] = useState<string | null>(null);
  const [retention, setRetention] = useState<30 | 60 | 90 | null>(30);
  const [dragging, setDragging] = useState(false);
  useEffect(() => {
    const unlisten = listen<{ paths?: string[] }>("tauri://drag-drop", event => {
      setDragging(false);
      const paths = [...new Set((event.payload.paths ?? []).filter(path => path.toLowerCase().split(/[\\/]/).pop()?.length))];
      if (paths.length) void onDropFiles(paths);
    });
    const over = listen("tauri://drag-over", () => setDragging(true));
    const leave = listen("tauri://drag-leave", () => setDragging(false));
    return () => { void unlisten.then(stop => stop()); void over.then(stop => stop()); void leave.then(stop => stop()); };
  }, [onDropFiles]);
  const visibleFiles = files
    .filter(file => file.name.toLocaleLowerCase().includes(query.toLocaleLowerCase()))
    .filter(file => category === "all" || categorize(file) === category);

  return <Page title="Files" subtitle="Your encrypted files, organized simply.">
    {dragging && <div className="drop-overlay" role="status">Drop files to encrypt and upload</div>}
    <div className="toolbar"><button className="button primary" onClick={() => void onPick("source")}>＋ Choose files</button><button className="button secondary" onClick={onRefresh}>Refresh</button><button className="button secondary" onClick={() => void onVerifyAll()} disabled={!files.length}>Verify all</button><input className="search" placeholder="Search files" aria-label="Search files" value={query} onChange={event => setQuery(event.target.value)} /></div>
    {sourcePath && <div className="upload-drawer"><strong>Ready to upload</strong><span className="selected-file">A file is selected</span><label>File name<input value={logicalName} onChange={event => setLogicalName(event.target.value)} /></label><button className="button primary" onClick={onUpload}>Upload securely</button>{progress && <div className="upload-progress"><progress max={progress.total_bytes ?? undefined} value={progress.bytes_processed} /> <span>{formatBytes(progress.bytes_processed)}{progress.total_bytes ? ` of ${formatBytes(progress.total_bytes)}` : ""}</span><button className="button text-button" onClick={onCancel}>Cancel</button></div>}</div>}
    <div className="restore-settings"><span>Restore destination: {restoreMode === "fixed" && restoreDirectory ? restoreDirectory : "Ask when restoring"}</span></div>
    {files.length > 0 && <div className="file-filters" role="group" aria-label="Filter by file type">
      <button className={`file-filter-chip ${category === "all" ? "active" : ""}`} onClick={() => setCategory("all")}>All</button>
      {CATEGORY_ORDER.map(value => <button key={value} className={`file-filter-chip ${category === value ? "active" : ""}`} onClick={() => setCategory(value)}>{CATEGORY_LABEL[value]}</button>)}
    </div>}
    {files.length === 0 ? <EmptyState title="Your files will appear here" body="Choose a file to encrypt and upload it to your connected storage." /> : visibleFiles.length === 0 ? <EmptyState title="No matching files" body="Try another search or filter." /> : <FileGrid files={visibleFiles} onDetails={setDetails} onRestore={onRestore} onRepair={async file => { if (repairing) return; setRepairing(file.logical_file_id); try { await onRepair(file); } finally { setRepairing(null); } }} onVerify={onVerify} repairing={repairing} onTrash={setPending} />}
    {pending && <ConfirmDialog title="Move to Trash?" confirmLabel="Move to Trash" onCancel={() => setPending(null)} onConfirm={() => { onMoveToTrash(pending, retention); setPending(null); }}><p><strong>{pending.name}</strong> will leave Files and remain recoverable in Trash.</p><Select label="Automatic purge" value={retention?.toString() ?? "never"} options={[{ value: "30", label: "After 30 days" }, { value: "60", label: "After 60 days" }, { value: "90", label: "After 90 days" }, { value: "never", label: "Never automatically purge" }]} onChange={value => setRetention(value === "never" ? null : Number(value) as 30 | 60 | 90)} /></ConfirmDialog>}
    {details && <FileDetailsDialog file={details} onClose={() => setDetails(null)} onVerify={() => onVerify(details)} />}
  </Page>;
}

function FileGrid({ files, onDetails, onRestore, onRepair, onVerify, repairing, onTrash }: { files: FileSummary[]; onDetails: (file: FileSummary) => void; onRestore: (file: FileSummary) => void; onRepair: (file: FileSummary) => Promise<void>; onVerify: (file: FileSummary) => Promise<void>; repairing: string | null; onTrash: (file: FileSummary) => void }) {
  return <div className="file-grid">
    {files.map(file => {
      const Icon = CATEGORY_ICON[categorize(file)];
      return <div className="file-card" key={file.logical_file_id}>
        <div className="file-card-icon"><Icon aria-hidden="true" /></div>
        <div className="file-card-body">
          <strong className="file-card-name" title={file.name}>{file.name}</strong>
          <HealthBadge file={file} />
        </div>
        <div className="file-card-actions">
          <button className="icon-button action-info" title="Details" aria-label={`Details for ${file.name}`} onClick={() => onDetails(file)}><Info size={15} /></button>
          {file.file_version_id && <button className="icon-button action-restore" title="Restore" aria-label={`Restore ${file.name}`} onClick={() => onRestore(file)}><Download size={15} /></button>}
          {file.file_version_id && <button className="icon-button action-repair" title={repairing === file.logical_file_id ? "Repairing…" : "Repair"} aria-label={`Repair ${file.name}`} disabled={repairing !== null} onClick={() => void onRepair(file)}><Wrench size={15} /></button>}
          <button className="icon-button action-trash" title="Move to Trash" aria-label={`Move ${file.name} to Trash`} onClick={() => onTrash(file)}><Trash2 size={15} /></button>
        </div>
      </div>;
    })}
  </div>;
}

function FileDetailsDialog({ file, onClose, onVerify }: { file: FileSummary; onClose: () => void; onVerify: () => Promise<void> }) {
  const protection = file.health ? `${healthLabel[file.health]}${file.health_current === false ? " (last known)" : ""}` : file.file_version_id ? "Health pending" : "Not uploaded";
  const [map, setMap] = useState<ProtectionMap | null>(null);
  const [verifying, setVerifying] = useState(false);
  useEffect(() => { if (file.file_version_id) void commands.protectionMap(file.file_version_id).then(setMap).catch(() => undefined); }, [file.file_version_id]);
  const verify = async () => { if (verifying) return; setVerifying(true); try { await onVerify(); if (file.file_version_id) setMap(await commands.protectionMap(file.file_version_id)); } finally { setVerifying(false); } };
  return <div className="dialog-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="dialog file-details-dialog" role="dialog" aria-modal="true" aria-labelledby="file-details-title">
      <h2 id="file-details-title">File details</h2>
      <dl className="file-details-grid">
        <dt>Name</dt><dd title={file.name}>{file.name}</dd>
        <dt>Type</dt><dd>{fileTypeLabel(file)}</dd>
        <dt>Size</dt><dd>{fileSizeLabel(file.size_bytes)}</dd>
        <dt>Protection</dt><dd>{protection}{file.file_version_id && <><br />{file.verified_copies} of {file.required_copies} verified copies</>}</dd>
        <dt>Last verified</dt><dd>{file.last_verified_at ? new Date(Number(file.last_verified_at)).toLocaleString() : "Not verified yet"}</dd>
      </dl>
      {map && <div className="protection-map" aria-label="Protection map">{map.targets.map((target, index) => <div className="protection-map-row" key={`${target.provider_kind}-${index}`}><span><strong>{target.provider_name}</strong><small>{target.provider_kind.replaceAll("_", " ")}</small></span><span className={`badge ${target.state === "complete" ? "good" : target.state === "partial" || target.state === "verifying" ? "warn" : "danger"}`}>{target.state}</span></div>)}</div>}
      <div className="dialog-actions"><button className="button secondary" onClick={onClose}>Close</button>{file.file_version_id && <button className="button primary" disabled={verifying} onClick={() => void verify()}>{verifying ? "Verifying…" : "Verify now"}</button>}</div>
    </section>
  </div>;
}
