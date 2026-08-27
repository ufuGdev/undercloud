export type DataTableColumn<T> = { key: string; label: string; width?: string };

export function DataTable<T>({ columns, rows, rowKey, renderCell, actions }: {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  renderCell: (row: T, key: string) => React.ReactNode;
  actions?: (row: T) => React.ReactNode;
}) {
  const templateColumns = columns.map(column => column.width ?? "1fr").join(" ") + (actions ? " auto" : "");
  return <div className="data-table" role="table">
    <div className="data-table-row data-table-head" role="row" style={{ gridTemplateColumns: templateColumns }}>
      {columns.map(column => <span role="columnheader" className="data-table-cell" key={column.key}>{column.label}</span>)}
      {actions && <span className="data-table-action-header" role="columnheader">Actions</span>}
    </div>
    {rows.map(row => <div className="data-table-row" role="row" key={rowKey(row)} style={{ gridTemplateColumns: templateColumns }}>
      {columns.map(column => {
        const content = renderCell(row, column.key);
        return <span role="cell" className="data-table-cell" key={column.key} title={typeof content === "string" ? String(content) : undefined}>{content}</span>;
      })}
      {actions && <span role="cell" className="data-table-actions">{actions(row)}</span>}
    </div>)}
  </div>;
}
