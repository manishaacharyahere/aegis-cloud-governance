import { Component, type ErrorInfo, type ReactNode } from 'react'
import { motion } from 'motion/react'
import { ArrowLeft, Monitor, Moon, Sun } from 'lucide-react'
import { cn } from '@/lib/utils'
import { spring } from '@/lib/motion'
import { Button } from './button'
import { StatusBadge } from './badge'

/** A segmented control (tabs that filter one view); the indicator glides between options. */
export function Segmented<T extends string>({ value, onChange, options, label, className }: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode }[]
  label: string
  className?: string
}) {
  return (
    <div role="radiogroup" aria-label={label} className={cn('inline-flex rounded-md border border-border bg-surface-2 p-0.5', className)}>
      {options.map((o) => {
        const on = o.value === value
        return (
          <button key={o.value} type="button" role="radio" aria-checked={on} onClick={() => onChange(o.value)}
            className={cn('relative rounded px-2.5 py-1 text-[12.5px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              on ? 'text-fg' : 'text-fg-muted hover:text-fg')}>
            {on && <motion.span layoutId={`seg-${label}`} transition={spring.moderate} className="absolute inset-0 rounded bg-surface-3 shadow-sm" />}
            <span className="relative">{o.label}</span>
          </button>
        )
      })}
    </div>
  )
}

/** "← Back to …" for detail views. */
export function BackLink({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <Button variant="ghost" size="sm" className="-ml-2 self-start" onClick={onClick}>
      <ArrowLeft />{children}
    </Button>
  )
}

/** A sub-heading inside a card. */
export function SectionTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-2 mt-5 flex items-center justify-between gap-2 first:mt-0">
      <h3 className="m-0 text-[11.5px] font-semibold uppercase tracking-wide text-fg-subtle">{children}</h3>
      {actions}
    </div>
  )
}

const fmt = (v: unknown) => (v === undefined || v === null ? '—' : typeof v === 'string' ? v : JSON.stringify(v))

/** Before → after for a list of changed paths (drift, remediation simulation). */
export function DiffList({ changes, max = 50 }: { changes: { path: string; before: unknown; after: unknown }[]; max?: number }) {
  if (changes.length === 0) return <p className="m-0 text-[13px] text-fg-muted">No field changes.</p>
  return (
    <div className="overflow-hidden rounded-md border border-border font-mono text-[12px]">
      {changes.slice(0, max).map((c) => (
        <div key={c.path} className="grid grid-cols-1 gap-x-3 border-b border-border/60 px-3 py-1.5 last:border-b-0 sm:grid-cols-[minmax(180px,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
          <span className="break-all text-fg-muted">{c.path}</span>
          <span className="truncate text-danger/90 line-through decoration-danger/40" title={fmt(c.before)}>{fmt(c.before)}</span>
          <span className="truncate text-success" title={fmt(c.after)}>{fmt(c.after)}</span>
        </div>
      ))}
      {changes.length > max && <div className="px-3 py-1.5 text-fg-subtle">and {changes.length - max} more</div>}
    </div>
  )
}

/** A vertical list of decisions or events, newest last. */
export function Timeline({ items, empty }: {
  items: { key: string; status: string; title: ReactNode; meta?: ReactNode; body?: ReactNode }[]
  empty: ReactNode
}) {
  if (items.length === 0) return <p className="m-0 text-[13px] text-fg-muted">{empty}</p>
  return (
    <ol className="timeline m-0 list-none space-y-3 border-l border-border p-0 pl-4">
      {items.map((it) => (
        <li key={it.key} className="relative">
          <span className="absolute -left-[21.5px] top-1.5 size-2.5 rounded-full border-2 border-surface bg-border-strong" aria-hidden />
          <div className="flex flex-wrap items-center gap-2 text-[13px]"><StatusBadge value={it.status} /> {it.title}</div>
          {it.meta && <div className="mt-0.5 text-xs text-fg-subtle">{it.meta}</div>}
          {it.body && <div className="mt-1 text-[13px] text-fg-muted">{it.body}</div>}
        </li>
      ))}
    </ol>
  )
}

export type ThemeChoice = 'system' | 'light' | 'dark'

/** Cycles system → light → dark. */
export function ThemeToggle({ value, onChange }: { value: ThemeChoice; onChange: (t: ThemeChoice) => void }) {
  const next: Record<ThemeChoice, ThemeChoice> = { system: 'light', light: 'dark', dark: 'system' }
  const icon = { system: <Monitor />, light: <Sun />, dark: <Moon /> }[value]
  return (
    <Button variant="ghost" size="icon" onClick={() => onChange(next[value])} aria-label={`Theme: ${value}. Switch to ${next[value]}.`} title={`Theme: ${value}`}>
      {icon}
    </Button>
  )
}

/** Catches render errors in a page so one broken page never blanks the app. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null }
  static getDerivedStateFromError(error: Error) {
    return { error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('page crashed', error, info.componentStack)
  }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <section role="alert" className="rounded-lg border border-danger/30 bg-surface p-6">
        <h2 className="m-0 text-base font-semibold">This page failed to render</h2>
        <p className="mt-1 text-[13px] text-danger">{this.state.error.message}</p>
        <Button className="mt-3" onClick={() => this.setState({ error: null })}>Try again</Button>
      </section>
    )
  }
}
