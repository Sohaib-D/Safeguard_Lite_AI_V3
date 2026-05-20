import { ReactNode } from "react";
import { cn } from "../../lib/utils";

interface Column<T> {
  header: string;
  accessorKey?: keyof T;
  cell?: (item: T, rowIndex: number) => ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  className?: string;
  emptyMessage?: string;
}

export function DataTable<T>({ data, columns, className, emptyMessage = "No data available." }: DataTableProps<T>) {
  if (!data || data.length === 0) {
    return (
      <div className={cn("p-8 text-center text-text-secondary bg-bg-secondary rounded-xl border border-border-subtle", className)}>
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className={cn("overflow-x-auto rounded-xl border border-border-subtle bg-bg-secondary", className)}>
      <table className="w-full text-sm text-left text-text-primary">
        <thead className="text-xs uppercase bg-bg-tertiary text-text-secondary border-b border-border-subtle">
          <tr>
            {columns.map((col, i) => (
              <th key={i} className={cn("px-6 py-4 font-medium tracking-wider whitespace-nowrap", col.className)}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((item, rowIndex) => (
            <tr key={rowIndex} className="border-b border-border-subtle hover:bg-bg-tertiary/30 transition-colors">
              {columns.map((col, colIndex) => (
                <td key={colIndex} className={cn("px-6 py-4 whitespace-nowrap", col.className)}>
                  {col.cell ? col.cell(item, rowIndex) : (col.accessorKey ? String(item[col.accessorKey] ?? '') : null)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
