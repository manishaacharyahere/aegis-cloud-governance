import type { ReactNode } from 'react'
import { ArrowUpRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import { toneSolid, toneText, type Tone } from '@/lib/tones'
import { AnimatedNumber } from './animated-number'

/**
 * A KPI tile. tone="auto" means: neutral at zero, otherwise the given
 * autoTone, so "0 internet-reachable" never looks alarming. A thin rail on
 * the left carries the tone (the AEGIS signal rail).
 */
export function StatCard({ label, value, tone = 'neutral', autoTone, hint, icon, onOpen, loading, format }: {
  label: string
  value: number | string | null | undefined
  tone?: Tone | 'auto'
  autoTone?: Tone
  hint?: ReactNode
  icon?: ReactNode
  onOpen?: () => void
  loading?: boolean
  format?: (n: number) => string
}) {
  const t: Tone = tone === 'auto' ? (typeof value === 'number' && value > 0 ? autoTone ?? 'warning' : 'neutral') : tone
  const body = (
    <>
      <span className={cn('absolute inset-y-3 left-0 w-[3px] rounded-r-full', t === 'neutral' ? 'bg-border-strong' : toneSolid[t])} aria-hidden />
      <div className="flex items-center justify-between gap-2 text-[12.5px] text-fg-muted">
        <span className="stat-label flex items-center gap-1.5 [&_svg]:size-3.5">{icon}{label}</span>
        {onOpen && <ArrowUpRight className="size-3.5 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />}
      </div>
      <div className={cn('stat-value mt-1.5 text-[26px] font-semibold leading-8 tracking-tight', t !== 'neutral' && toneText[t])}>
        {loading ? <span className="inline-block h-7 w-16 animate-shimmer rounded bg-[linear-gradient(90deg,var(--surface-2),var(--surface-3),var(--surface-2))] bg-[length:200%_100%]" />
          : typeof value === 'number' ? <AnimatedNumber value={value} format={format} /> : (value ?? '—')}
      </div>
      {hint && <div className="mt-1 text-xs text-fg-subtle">{hint}</div>}
    </>
  )
  const cls = 'stat group relative block w-full overflow-hidden rounded-lg border border-border bg-surface px-4 py-3.5 text-left shadow-card'
  return onOpen ? (
    <button type="button" onClick={onOpen} className={cn(cls, 'transition-colors hover:border-border-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring')}>{body}</button>
  ) : <div className={cls}>{body}</div>
}

export function StatGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('stats grid grid-cols-[repeat(auto-fit,minmax(170px,1fr))] gap-3', className)}>{children}</div>
}
