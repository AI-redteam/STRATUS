import React, { useState, useMemo } from 'react';

export interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
  keyField?: string;
}

export function DataTable<T extends Record<string, any>>({
  columns, data, onRowClick, emptyMessage = 'No data', keyField = 'uuid',
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);

  const sorted = useMemo(() => {
    if (!sortKey) return data;
    return [...data].sort((a, b) => {
      const va = a[sortKey] ?? '';
      const vb = b[sortKey] ?? '';
      const cmp = String(va).localeCompare(String(vb));
      return sortAsc ? cmp : -cmp;
    });
  }, [data, sortKey, sortAsc]);

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortAsc(!sortAsc);
    } else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  if (!data || data.length === 0) {
    return (
      <div className="text-center py-12 text-stratus-muted text-sm">
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm text-left">
        <thead>
          <tr className="border-b border-stratus-border">
            {columns.map(col => (
              <th
                key={col.key}
                className={`px-4 py-3 text-xs font-medium uppercase text-stratus-muted ${
                  col.sortable !== false ? 'cursor-pointer hover:text-stratus-text' : ''
                }`}
                style={col.width ? { width: col.width } : undefined}
                onClick={() => col.sortable !== false && handleSort(col.key)}
              >
                {col.header}
                {sortKey === col.key && (
                  <span className="ml-1">{sortAsc ? '\u2191' : '\u2193'}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr
              key={row[keyField] ?? i}
              className={`border-b border-stratus-border/50 ${
                onRowClick ? 'cursor-pointer hover:bg-stratus-surface/80' : ''
              }`}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map(col => (
                <td key={col.key} className="px-4 py-3">
                  {col.render ? col.render(row) : String(row[col.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
