import { useId, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import { cn } from '@/lib/utils'
import { niceTicks } from '@/lib/ticks'

/*
 * Single-series charts. Following the dataviz method: one hue (the accent),
 * thin marks (bars <= 12px with a 4px rounded data-end, 2px lines over a 10%
 * wash), hairline recessive grid, values in text colours, a crosshair tooltip
 * that keyboard focus reaches too, and a table view so nothing is gated on
 * hover. A single series needs no legend: the card title names it.
 */

const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 })

/** Horizontal bars for "how much per category", largest first; every value is labelled. */
export function BarList({ items, format, label }: {
  items: { key: string; value: number; note?: string }[]
  format: (n: number) => string
  label: string
}) {
  const max = Math.max(0, ...items.map((i) => i.value))
  return (
    <ul className="bars m-0 list-none space-y-1.5 p-0" aria-label={label}>
      {items.map((it) => {
        const w = max > 0 ? (it.value / max) * 100 : 0
        return (
          <li key={it.key} className="bar-row group grid grid-cols-[minmax(90px,180px)_1fr_auto] items-center gap-3 rounded-md px-1 py-1 text-[13px] hover:bg-surface-2/60">
            <span className="truncate text-fg-muted" title={it.key}>{it.key || '(none)'}</span>
            <span className="relative h-2.5 rounded-r bg-surface-3/50">
              <span className="absolute inset-y-0 left-0 rounded-r-[4px] bg-accent transition-[width] duration-500 ease-out" style={{ width: `${w}%` }} />
            </span>
            <span className="whitespace-nowrap text-right tabular-nums">{format(it.value)}{it.note && <span className="ml-1.5 text-fg-subtle">{it.note}</span>}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** A line + area chart over time with a crosshair tooltip and a table view. */
export function AreaChart({ points, format, label, height = 180 }: {
  points: { x: string; y: number }[]
  format: (n: number) => string
  label: string
  height?: number
}) {
  const [active, setActive] = useState<number | null>(null)
  const ref = useRef<SVGSVGElement>(null)
  const gradId = useId()
  const W = 640
  const pad = { l: 44, r: 12, t: 12, b: 24 }
  const ticks = useMemo(() => niceTicks(Math.max(0, ...points.map((p) => p.y))), [points])
  const top = ticks[ticks.length - 1] || 1
  const x = (i: number) => pad.l + (points.length <= 1 ? 0 : (i / (points.length - 1)) * (W - pad.l - pad.r))
  const y = (v: number) => pad.t + (1 - v / top) * (height - pad.t - pad.b)
  if (points.length === 0) return null

  const line = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.y).toFixed(1)}`).join(' ')
  const area = `${line} L${x(points.length - 1).toFixed(1)},${y(0)} L${x(0).toFixed(1)},${y(0)} Z`
  const labelEvery = Math.max(1, Math.ceil(points.length / 6))

  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const r = ref.current?.getBoundingClientRect()
    if (!r) return
    const px = ((e.clientX - r.left) / r.width) * W
    const i = Math.round(((px - pad.l) / (W - pad.l - pad.r)) * (points.length - 1))
    setActive(Math.min(points.length - 1, Math.max(0, i)))
  }
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    e.preventDefault()
    setActive((a) => Math.min(points.length - 1, Math.max(0, (a ?? (e.key === 'ArrowRight' ? -1 : points.length)) + (e.key === 'ArrowRight' ? 1 : -1))))
  }
  const a = active === null ? null : points[active]
  const last = points[points.length - 1]

  return (
    <figure className="m-0">
      <div className="relative">
        <svg ref={ref} viewBox={`0 0 ${W} ${height}`} className="block h-auto w-full touch-none select-none overflow-visible focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          role="img" aria-label={`${label}. Use the left and right arrow keys to read values.`} tabIndex={0}
          onPointerMove={onMove} onPointerLeave={() => setActive(null)} onKeyDown={onKey} onBlur={() => setActive(null)}>
          <defs>
            <linearGradient id={gradId} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.18" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} stroke="var(--border)" strokeWidth="1" />
              <text x={pad.l - 8} y={y(t)} textAnchor="end" dominantBaseline="middle" fill="var(--fg-subtle)" fontSize="11">{compact.format(t)}</text>
            </g>
          ))}
          {points.map((p, i) => (i % labelEvery === 0 || i === points.length - 1) && (
            <text key={p.x} x={x(i)} y={height - 6} textAnchor={i === 0 ? 'start' : i === points.length - 1 ? 'end' : 'middle'} fill="var(--fg-subtle)" fontSize="11">{p.x.slice(5)}</text>
          ))}
          <path d={area} fill={`url(#${gradId})`} />
          <path d={line} fill="none" stroke="var(--accent)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          <circle cx={x(points.length - 1)} cy={y(last.y)} r="4" fill="var(--accent)" stroke="var(--surface)" strokeWidth="2" />
          {a && active !== null && (
            <g>
              <line x1={x(active)} x2={x(active)} y1={pad.t} y2={y(0)} stroke="var(--fg-subtle)" strokeWidth="1" />
              <circle cx={x(active)} cy={y(a.y)} r="4.5" fill="var(--accent)" stroke="var(--surface)" strokeWidth="2" />
            </g>
          )}
        </svg>
        {a && active !== null && (
          <div role="status" className="pointer-events-none absolute top-1 rounded-md border border-border bg-surface px-2.5 py-1.5 text-xs shadow-card"
            style={{ left: `${(x(active) / W) * 100}%`, transform: `translateX(${active > points.length / 2 ? '-105%' : '5%'})` }}>
            <div className="font-semibold tabular-nums">{format(a.y)}</div>
            <div className="text-fg-subtle">{a.x}</div>
          </div>
        )}
      </div>
      <details className="mt-2 text-xs text-fg-muted">
        <summary className="cursor-pointer select-none hover:text-fg">Show as table</summary>
        <div className="mt-2 max-h-56 overflow-auto rounded-md border border-border">
          <table className={cn('w-full text-left text-[12.5px]')}>
            <thead className="sticky top-0 bg-surface-2"><tr><th className="px-3 py-1.5 font-medium">Date</th><th className="px-3 py-1.5 text-right font-medium">Value</th></tr></thead>
            <tbody>{points.map((p) => <tr key={p.x} className="border-t border-border/60"><td className="px-3 py-1">{p.x}</td><td className="px-3 py-1 text-right tabular-nums">{format(p.y)}</td></tr>)}</tbody>
          </table>
        </div>
      </details>
    </figure>
  )
}

/** A thin proportion meter, e.g. passing / total controls. */
export function Meter({ value, max, tone = 'accent', label }: { value: number; max: number; tone?: 'accent' | 'success' | 'warning' | 'danger'; label: string }) {
  const pctv = max > 0 ? Math.min(100, (value / max) * 100) : 0
  const color = { accent: 'bg-accent', success: 'bg-success', warning: 'bg-warning', danger: 'bg-danger' }[tone]
  return (
    <div role="meter" aria-label={label} aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
      <div className={cn('h-full rounded-full transition-[width] duration-500 ease-out', color)} style={{ width: `${pctv}%` }} />
    </div>
  )
}
