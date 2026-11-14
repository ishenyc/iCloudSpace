import { type ReactNode } from 'react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui'
import { useWindowTable } from './use-window-table'
export type TableColumn = { key: string; label: ReactNode; render?: (row: any) => ReactNode; width?: number | string }
const defaultRowKey = (row: any) => row.id
export function VirtualTable({ rows, columns, rowKey = defaultRowKey, rowHeight = 64, isRowSelected }: { rows: any[]; columns: TableColumn[]; rowKey?: (row: any) => string | number; rowHeight?: number; isRowSelected?: (row: any) => boolean }) {
  const { body, virtualized, virtualizer, items, paddingTop: top, paddingBottom: bottom } = useWindowTable({ rows, rowKey, rowHeight })
  const minWidth = Math.max(680, columns.reduce((total, column) => total + (typeof column.width === 'number' ? column.width : typeof column.width === 'string' && column.width.endsWith('px') ? Number.parseFloat(column.width) : 140), 0))
  return <div className="table-wrap virtual-table" role="region" aria-label="数据列表，可横向滚动" tabIndex={0}>
    <Table className="data-table" containerClassName="overflow-visible" aria-rowcount={rows.length + 1} style={{ minWidth }}>
      <colgroup>{columns.map(column => <col key={column.key} style={{ width: column.width }} />)}</colgroup>
      <TableHeader><TableRow>{columns.map(c => <TableHead key={c.key} scope="col" style={{ width: c.width }}>{c.label}</TableHead>)}</TableRow></TableHeader>
      <TableBody ref={body}>
        {top > 0 && <TableRow aria-hidden="true"><TableCell colSpan={columns.length} style={{ height: top, padding: 0, border: 0 }} /></TableRow>}
        {items.map(item => <TableRow key={item.key} ref={virtualized ? virtualizer.measureElement : undefined} data-index={item.index} aria-rowindex={item.index + 2} aria-selected={isRowSelected?.(rows[item.index])} data-state={isRowSelected?.(rows[item.index]) ? 'selected' : undefined} style={{ height: rowHeight }}>{columns.map(c => <TableCell key={c.key}>{c.render ? c.render(rows[item.index]) : rows[item.index][c.key]}</TableCell>)}</TableRow>)}
        {bottom > 0 && <TableRow aria-hidden="true"><TableCell colSpan={columns.length} style={{ height: bottom, padding: 0, border: 0 }} /></TableRow>}
      </TableBody>
    </Table>
  </div>
}
