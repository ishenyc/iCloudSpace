import type { ReactNode } from 'react'
import { Inbox, LoaderCircle } from 'lucide-react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui'
import { Skeleton } from './ui/skeleton'
import { cn } from '../lib/utils'

type PlaceholderColumn = { key?: string; label: ReactNode; width?: number | string }

/** Skeletons follow data columns; empty/error states fit the visible table width. */
export function TablePlaceholder({ columns, loading = false, title = '暂无数据', description, action, rows = 5, rowHeight = 64, label = '正在加载列表', className }: {
  columns: PlaceholderColumn[]; loading?: boolean; title?: string; description?: ReactNode; action?: ReactNode; rows?: number; rowHeight?: number; label?: string; className?: string
}) {
  const minWidth = Math.max(680, columns.reduce((total, column) => total + (typeof column.width === 'number' ? column.width : typeof column.width === 'string' && column.width.endsWith('px') ? Number.parseFloat(column.width) : 140), 0))
  return <div className={cn('table-wrap relative', !loading && 'table-empty', className)} aria-busy={loading}>
    <Table className="data-table" containerClassName="overflow-visible" style={{ minWidth: loading ? minWidth : 0, tableLayout: loading ? 'fixed' : 'auto' }}>
      <colgroup>{columns.map((column, index) => <col key={column.key ?? index} style={{ width: loading ? column.width : undefined }} />)}</colgroup>
      <TableHeader><TableRow>{columns.map((column, index) => <TableHead key={column.key ?? index} scope="col" style={{ width: loading ? column.width : undefined }}>{column.label}</TableHead>)}</TableRow></TableHeader>
      <TableBody>
        {loading ? Array.from({ length: rows }, (_, index) => <TableRow key={index} aria-hidden="true" className="hover:bg-transparent" style={{ height: rowHeight }}>{columns.map((column, cell) => <TableCell key={column.key ?? cell}><Skeleton className={cn('h-2 motion-reduce:animate-none', cell === 0 ? 'w-3/4' : cell % 2 ? 'w-2/3' : 'w-1/2')} />{cell === 0 && <Skeleton className="mt-2 h-1.5 w-1/2 opacity-50 motion-reduce:animate-none" />}</TableCell>)}</TableRow>)
          : <TableRow className="hover:bg-transparent"><TableCell colSpan={columns.length} className="!whitespace-normal !px-6 !py-12 text-center"><div data-slot="table-empty-content" className="mx-auto flex min-w-0 max-w-md flex-col items-center gap-3"><span className="flex size-10 items-center justify-center rounded-xl border border-border bg-muted/40 text-muted-foreground"><Inbox size={18} strokeWidth={1.5} /></span><div className="space-y-1"><h3 className="text-sm font-medium">{title}</h3>{description && <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>}</div>{action}</div></TableCell></TableRow>}
      </TableBody>
    </Table>
    {loading && <div role="status" className="absolute inset-x-0 flex justify-center pointer-events-none" style={{ top: 'min(40%, 160px)' }}><span className="inline-flex items-center gap-2 rounded-full border border-border bg-card/95 px-3 py-1.5 text-[11px] text-muted-foreground shadow-sm"><LoaderCircle className="size-3 motion-safe:animate-spin" />{label}</span></div>}
  </div>
}
