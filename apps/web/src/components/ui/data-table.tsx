import type { MouseEvent, ReactNode } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { toneSolid, type Tone } from '@/lib/tones'
import { Button } from './button'
import { EmptyState, ErrorState, Skeleton } from './feedback'

export interface Column<T> {
  key: string
  header: ReactNode
  cell: (row: T) => ReactNode
  align?: 'left' | 'right'
  /** The cell that opens the row (rendered as a button) when onRowOpen is set. Defaults to the first column. */
  primary?: boolean
  className?: string
  /** Hide on narrow screens. */
  hideOnMobile?: boolean
}

/**
 * The one table used across the app: header always present, built-in
 * loading / error / empty states, keyboard-reachable row opening and an
 * optional severity rail per row.
 */
export function DataTable<T>({ columns, rows, getRowId, onRowOpen, rowLabel, rowTone, loading, error, onRetry, empty, caption, dense, className }: {
  columns: Column<T>[]
  rows: T[] | undefined
  getRowId: (row: T) => string
  onRowOpen?: (row: T) => void
  /** Accessible name of the open-row button (defaults to the primary cell's text). */
  rowLabel?: (row: T) => string
  rowTone?: (row: T) => Tone | undefined
  loading?: boolean
  error?: unknown
  onRetry?: () => void
  empty?: ReactNode
  caption?: string
  dense?: boolean
  className?: string
}) {
  const primaryKey = (columns.find((c) => c.primary) ?? columns[0]).key
  if (error && !rows?.length) return <ErrorState error={error} onRetry={onRetry} />
  if (loading && !rows?.length) return <Skeleton rows={4} />
  if (!rows?.length) return typeof empty === 'string' || !empty ? <EmptyState title={empty ?? 'Nothing to show.'} /> : <>{empty}</>

  const open = (row: T) => (e: MouseEvent) => {
    // Clicks on links, buttons and inputs inside the row keep their own behaviour.
    if ((e.target as HTMLElement).closest('a,button,input,select,textarea,label')) return
    onRowOpen?.(row)
  }
  const pad = dense ? 'px-3 py-1.5' : 'px-3 py-2.5'
  return (
    <div className={cn('-mx-5 overflow-x-auto', className)}>
      <table className="table w-full border-collapse text-[13px]">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-border">
            {columns.map((c) => (
              <th key={c.key} scope="col" className={cn('whitespace-nowrap px-3 py-2 text-left text-[11.5px] font-medium uppercase tracking-wide text-fg-subtle first:pl-5 last:pr-5',
                c.align === 'right' && 'text-right', c.hideOnMobile && 'max-md:hidden')}>{c.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const tone = rowTone?.(row)
            return (
              <tr key={getRowId(row)} onClick={onRowOpen ? open(row) : undefined}
                className={cn('border-b border-border/60 transition-colors last:border-b-0', onRowOpen && 'clickable cursor-pointer hover:bg-surface-2/70')}>
                {columns.map((c) => (
                  <td key={c.key} className={cn(pad, 'relative align-middle first:pl-5 last:pr-5', c.align === 'right' && 'text-right tabular-nums', c.hideOnMobile && 'max-md:hidden', c.className)}>
                    {c.key === columns[0].key && tone && <span className={cn('absolute inset-y-2 left-0 w-[3px] rounded-r-full', toneSolid[tone])} aria-hidden />}
                    {onRowOpen && c.key === primaryKey ? (
                      <button type="button" onClick={() => onRowOpen(row)} aria-label={rowLabel?.(row)}
                        className="rounded-sm text-left font-medium text-fg underline-offset-4 hover:text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                        {c.cell(row)}
                      </button>
                    ) : c.cell(row)}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** Cursor pagination: "load more" for feeds, previous/next for browsable lists. */
export function Pager({ mode, hasNext, onNext, hasPrev, onPrev, loading, count }: {
  mode: 'more' | 'pages'
  hasNext: boolean
  onNext: () => void
  hasPrev?: boolean
  onPrev?: () => void
  loading?: boolean
  count?: number
}) {
  if (!hasNext && !hasPrev) return count !== undefined ? <p className="m-0 mt-3 text-xs text-fg-subtle">{count} shown</p> : null
  return (
    <div className="pager mt-3 flex items-center justify-between gap-2">
      <span className="text-xs text-fg-subtle">{count !== undefined && `${count} shown`}</span>
      {mode === 'more' ? (
        hasNext && <Button size="sm" onClick={onNext} loading={loading}>Load more</Button>
      ) : (
        <div className="flex gap-2">
          <Button size="sm" onClick={onPrev} disabled={!hasPrev || loading}><ChevronLeft />Previous page</Button>
          <Button size="sm" onClick={onNext} disabled={!hasNext} loading={loading}>Next page<ChevronRight /></Button>
        </div>
      )}
    </div>
  )
}
