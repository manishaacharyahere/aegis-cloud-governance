import type { ReactNode } from 'react'
import { describeError } from './client'

export function Panel({ title, actions, children }: { title?: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      {(title || actions) && (
        <div className="panel-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

const TONES: Record<string, string> = {
  critical: 'bad', high: 'bad', fail: 'bad', failing: 'bad', blocked: 'bad', rejected: 'bad', verification_failed: 'bad',
  stale: 'warn', medium: 'warn', partial: 'warn', pending_approval: 'warn', requested: 'warn', open: 'warn', excepted: 'warn',
  partially_accepted: 'warn', unreviewed: 'warn',
  low: 'neutral', not_configured: 'neutral', released: 'info', approved: 'info', accepted: 'ok', implemented: 'ok',
  pass: 'ok', passing: 'ok', passed: 'ok', disruptive: 'warn', unowned: 'warn', verified: 'ok', succeeded: 'ok', reviewed: 'ok',
}

export function Badge({ value }: { value: string }) {
  return <span className={`badge badge-${TONES[value] ?? 'neutral'}`}>{value.replace(/_/g, ' ')}</span>
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null
  return (
    <p className="error" role="alert">
      {describeError(error)}
    </p>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="muted">{children}</p>
}

export function Stat({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className={`stat ${tone ? 'stat-' + tone : ''}`}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
