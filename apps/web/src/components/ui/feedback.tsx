import type { ReactNode } from 'react'
import { AlertOctagon, AlertTriangle, CheckCircle2, Info, RefreshCw } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ApiError, describeError } from '@/client'
import { Button } from './button'

/** Placeholder rows while content loads, so the layout does not jump. */
export function Skeleton({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div role="status" aria-label="Loading" className={cn('space-y-2.5 py-1', className)}>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-3.5 animate-shimmer rounded bg-[linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2))] bg-[length:200%_100%]"
          style={{ width: `${92 - ((i * 17) % 35)}%` }} />
      ))}
    </div>
  )
}

/** Explains why there is nothing to show and, where possible, what to do next. */
export function EmptyState({ icon, title, children, action, className }: {
  icon?: ReactNode; title: ReactNode; children?: ReactNode; action?: ReactNode; className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border px-6 py-8 text-center', className)}>
      {icon && <span className="text-fg-subtle [&_svg]:size-6" aria-hidden>{icon}</span>}
      <p className="m-0 font-medium">{title}</p>
      {children && <p className="m-0 max-w-md text-[13px] text-fg-muted">{children}</p>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

/** A specific failure with a recovery path. Renders nothing without an error. */
export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  if (!error) return null
  return (
    <div role="alert" className={cn('error flex items-start gap-2.5 rounded-md border border-danger/30 bg-danger/8 px-3.5 py-2.5 text-[13px] text-danger', className)}>
      <AlertOctagon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1">
        {describeError(error)}
        <Details error={error} />
      </div>
      {onRetry && <Button size="sm" variant="ghost" onClick={onRetry}><RefreshCw />Retry</Button>}
    </div>
  )
}

/** Per-field problems the API returned (validation issues, bad CSV rows). */
function Details({ error }: { error: unknown }) {
  if (!(error instanceof ApiError) || !Array.isArray(error.details) || error.details.length === 0) return null
  const shown = error.details.slice(0, 8)
  const line = (d: unknown) => {
    if (d && typeof d === 'object') {
      const o = d as Record<string, unknown>
      const where = o.path ?? o.row ?? o.line ?? ''
      const what = o.message ?? o.error ?? JSON.stringify(o)
      return where !== '' ? `${String(where)}: ${String(what)}` : String(what)
    }
    return String(d)
  }
  return (
    <ul className="m-0 mt-1.5 list-disc space-y-0.5 pl-4 text-[12.5px] text-fg-muted">
      {shown.map((d, i) => <li key={i} className="break-words">{line(d)}</li>)}
      {error.details.length > shown.length && <li>and {error.details.length - shown.length} more</li>}
    </ul>
  )
}

const CALLOUT = {
  info: { cls: 'border-info/30 bg-info/8 text-fg', icon: <Info className="text-info" /> },
  warning: { cls: 'border-warning/30 bg-warning/8 text-fg', icon: <AlertTriangle className="text-warning" /> },
  danger: { cls: 'border-danger/30 bg-danger/8 text-fg', icon: <AlertOctagon className="text-danger" /> },
  success: { cls: 'border-success/30 bg-success/8 text-fg', icon: <CheckCircle2 className="text-success" /> },
}

/** A short notice inside a page (context, limitation, outcome). */
export function Callout({ tone = 'info', title, children, className }: {
  tone?: keyof typeof CALLOUT; title?: ReactNode; children?: ReactNode; className?: string
}) {
  const c = CALLOUT[tone]
  return (
    <div className={cn('notice flex items-start gap-2.5 rounded-md border px-3.5 py-2.5 text-[13px]', c.cls, className)}>
      <span className="mt-0.5 [&_svg]:size-4" aria-hidden>{c.icon}</span>
      <div className="min-w-0">
        {title && <p className="m-0 font-medium">{title}</p>}
        {children && <div className={cn('text-fg-muted', title && 'mt-0.5')}>{children}</div>}
      </div>
    </div>
  )
}
