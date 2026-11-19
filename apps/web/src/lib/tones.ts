// One source of truth for how a status or severity looks. Components never
// hard-code colours for domain values; they ask toneOf().

export type Tone = 'danger' | 'high' | 'warning' | 'success' | 'info' | 'accent' | 'neutral'

/** Severities from most to least severe (findings, drift, risk bands). */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const

const TONES: Record<string, Tone> = {
  // severity
  critical: 'danger', high: 'high', medium: 'warning', low: 'info', info: 'neutral', unknown: 'neutral',
  // results
  fail: 'danger', failing: 'danger', blocked: 'danger', blocking: 'danger', destructive: 'danger',
  verification_failed: 'danger', rejected: 'danger', failed: 'danger', dead: 'danger', unreachable: 'danger', revoked: 'neutral',
  pass: 'success', passing: 'success', passed: 'success', verified: 'success', succeeded: 'success',
  accepted: 'success', implemented: 'success', active: 'success', reviewed: 'success', ok: 'success', ready: 'success',
  partial: 'warning', stale: 'warning', pending_approval: 'warning', requested: 'warning', open: 'warning',
  excepted: 'warning', partially_accepted: 'warning', unreviewed: 'warning', unowned: 'warning',
  disruptive: 'warning', expiring: 'warning', not_ready: 'warning', degraded: 'warning',
  approved: 'info', released: 'info', queued: 'neutral', running: 'accent',
  superseded: 'neutral', dismissed: 'neutral', expired: 'neutral', no_evidence: 'neutral', not_configured: 'neutral',
}

export function toneOf(value: string): Tone {
  return TONES[value] ?? 'neutral'
}

/** "pending_approval" -> "pending approval". */
export function humanize(value: string): string {
  return value.replace(/_/g, ' ')
}

/** Tailwind classes per tone: soft background, text and border. */
export const toneClasses: Record<Tone, string> = {
  danger: 'bg-danger/12 text-danger border-danger/30',
  high: 'bg-high/12 text-high border-high/30',
  warning: 'bg-warning/12 text-warning border-warning/30',
  success: 'bg-success/12 text-success border-success/30',
  info: 'bg-info/12 text-info border-info/30',
  accent: 'bg-accent-soft text-accent border-accent/30',
  neutral: 'bg-surface-3/60 text-fg-muted border-border',
}

/** Solid colour per tone, for dots, bars and the severity rail. */
export const toneSolid: Record<Tone, string> = {
  danger: 'bg-danger', high: 'bg-high', warning: 'bg-warning', success: 'bg-success',
  info: 'bg-info', accent: 'bg-accent', neutral: 'bg-fg-subtle',
}

export const toneText: Record<Tone, string> = {
  danger: 'text-danger', high: 'text-high', warning: 'text-warning', success: 'text-success',
  info: 'text-info', accent: 'text-accent', neutral: 'text-fg-muted',
}

/** Rank for sorting by severity (unknown values sort last). */
export function severityRank(s: string): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(s)
  return i === -1 ? SEVERITY_ORDER.length : i
}

/** The row rail for a severity: only critical and high get one, so the rail
 * marks what needs attention first. */
export function severityRail(severity: string | undefined): Tone | undefined {
  return severity === 'critical' || severity === 'high' ? toneOf(severity) : undefined
}
