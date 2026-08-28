import { useEffect, useMemo, useRef, useState } from "react";
import { commands, type ActivityEvent } from "../../commands";
import { DataTable, type DataTableColumn } from "../../components/ui/DataTable";
import { EmptyState } from "../../components/ui/EmptyState";
import { Page } from "../../components/ui/Page";

const ACTIVITY_PAGE_SIZE = 10;

type GroupedRow = { key: string; operation: string; item: string; status: string; startedAt: string; completedAt: string | null };

function groupByOperation(events: ActivityEvent[]): GroupedRow[] {
  const byOperation = new Map<string, ActivityEvent[]>();
  for (const event of events) {
    const bucket = byOperation.get(event.operation_id) ?? [];
    bucket.push(event);
    byOperation.set(event.operation_id, bucket);
  }
  const rows: GroupedRow[] = [];
  for (const [operationId, bucket] of byOperation) {
    const started = bucket.find(event => event.status === "started") ?? bucket[0];
    const terminal = bucket.filter(event => event.status === "completed" || event.status === "failed" || event.status === "cancelled").sort((a, b) => Number(b.completed_at ?? b.started_at) - Number(a.completed_at ?? a.started_at))[0];
    rows.push({
      key: operationId,
      operation: started.display_metadata || `${started.event_type} operation`,
      item: started.event_type,
      status: terminal?.status ?? started.status,
      startedAt: started.started_at,
      completedAt: terminal?.completed_at ?? null,
    });
  }
  return rows.sort((a, b) => Number(b.startedAt) - Number(a.startedAt));
}

function mergeEvents(current: ActivityEvent[], incoming: ActivityEvent[]): ActivityEvent[] {
  const byId = new Map(current.map(event => [event.id, event]));
  for (const event of incoming) byId.set(event.id, event);
  return [...byId.values()];
}

const COLUMNS: DataTableColumn<GroupedRow>[] = [
  { key: "operation", label: "Operation", width: "minmax(0,1.6fr)" },
  { key: "item", label: "Type", width: "minmax(0,1fr)" },
  { key: "status", label: "Status", width: "110px" },
  { key: "timestamp", label: "Timestamp", width: "170px" },
];

export function Activity() {
  const [events, setEvents] = useState<ActivityEvent[]>([]); const [cursor, setCursor] = useState<string | null>(null); const [loading, setLoading] = useState(false); const [status, setStatus] = useState("");
  const loadingRef = useRef(false);
  const load = async (next?: string) => { if (loadingRef.current) return; loadingRef.current = true; setLoading(true); try { const page = await commands.activityEvents({ cursor: next, pageSize: ACTIVITY_PAGE_SIZE }); setEvents(current => next ? mergeEvents(current, page.events) : mergeEvents([], page.events)); setCursor(page.next_cursor); setStatus(""); } catch { setStatus("Activity history is temporarily unavailable."); } finally { loadingRef.current = false; setLoading(false); } };
  useEffect(() => { void load(); }, []);
  const rows = useMemo(() => groupByOperation(events), [events]);
  return <Page title="Activity" subtitle="Durable vault operations and history.">
    {status && <p className="notice error" role="alert">{status}</p>}
    {rows.length === 0 && !loading ? <EmptyState title="No activity yet" body="Completed and failed operations will appear here." /> : <DataTable
      columns={COLUMNS}
      rows={rows}
      rowKey={row => row.key}
      renderCell={(row, key) => key === "operation" ? row.operation : key === "item" ? row.item : key === "status" ? <span className={`badge ${row.status === "completed" ? "good" : row.status === "failed" ? "danger" : "muted"}`}>{row.status}</span> : new Date(Number(row.startedAt)).toLocaleString()}
    />}
    {cursor && <button className="button secondary" disabled={loading} onClick={() => void load(cursor)}>{loading ? "Loading…" : "Load more"}</button>}
  </Page>;
}
