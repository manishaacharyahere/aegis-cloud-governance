import { Component, createContext, useCallback, useContext, useState, type ErrorInfo, type ReactNode } from 'react'
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
  partially_accepted: 'warn', unreviewed: 'warn', blocking: 'bad', destructive: 'bad', active: 'ok', superseded: 'neutral',
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

/** Placeholder rows while a list loads, so the layout does not jump. */
export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" />)}
    </div>
  )
}

/** Catches render errors in a page so one broken page does not blank the app. */
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
      <section className="panel" role="alert">
        <h2>This page failed to render</h2>
        <p className="error">{this.state.error.message}</p>
        <button onClick={() => this.setState({ error: null })}>Try again</button>
      </section>
    )
  }
}

type Toast = { id: number; text: string; tone: 'ok' | 'bad' }
const ToastContext = createContext<(text: string, tone?: 'ok' | 'bad') => void>(() => {})

/** Provides useToast(); messages disappear after five seconds. */
export function Toasts({ children }: { children: ReactNode }) {
  const [list, setList] = useState<Toast[]>([])
  const push = useCallback((text: string, tone: 'ok' | 'bad' = 'ok') => {
    const id = Date.now() + Math.random()
    setList((l) => [...l.slice(-3), { id, text, tone }])
    window.setTimeout(() => setList((l) => l.filter((t) => t.id !== id)), 5000)
  }, [])
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {list.map((t) => <div key={t.id} className={`toast toast-${t.tone}`}>{t.text}</div>)}
      </div>
    </ToastContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastContext)
}

/** A button that asks for confirmation inline before an irreversible action. */
export function ConfirmButton({ label, confirm, onConfirm, disabled, primary }: {
  label: string; confirm: string; onConfirm: () => void; disabled?: boolean; primary?: boolean
}) {
  const [asking, setAsking] = useState(false)
  if (!asking) return <button className={primary ? 'primary' : undefined} disabled={disabled} onClick={() => setAsking(true)}>{label}</button>
  return (
    <span className="confirm" role="group" aria-label={confirm}>
      <span className="small">{confirm}</span>
      <button className={primary ? 'primary' : 'danger'} disabled={disabled} onClick={() => { setAsking(false); onConfirm() }}>Yes, {label.toLowerCase()}</button>
      <button className="link" onClick={() => setAsking(false)}>Cancel</button>
    </span>
  )
}

/** Props that make a table row open something by mouse or keyboard (Enter). */
// eslint-disable-next-line react-refresh/only-export-components
export function rowLink(open: () => void) {
  return {
    className: 'clickable',
    tabIndex: 0,
    role: 'link',
    onClick: open,
    onKeyDown: (e: { key: string; preventDefault: () => void }) => {
      if (e.key === 'Enter') {
        e.preventDefault()
        open()
      }
    },
  }
}
