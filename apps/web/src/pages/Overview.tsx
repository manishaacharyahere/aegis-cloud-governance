import { BadgeDollarSign, Globe2, ShieldAlert, ShieldCheck, Wrench } from 'lucide-react'
import { ApiError } from '../client'
import type { PageProps } from '../nav'
import type { AuditEvent, Coverage, Paged, Recommendation, Remediation, RiskRun } from '../types'
import { Button, Card, DataTable, EmptyState, Meter, Mono, StatCard, StatGrid, StatusBadge } from '@/components/ui'
import { ago, useLoad, usdCompact } from '../hooks'

/** 404 means "nothing yet"; every other failure is a real error the user must see. */
const orNull = async <T,>(p: Promise<T>): Promise<T | null> => {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}

export default function Overview({ api, go }: PageProps) {
  const cov = useLoad(() => api<Coverage>('GET', '/api/v1/compliance/coverage?framework=aegis-baseline-1'), [api])
  const risk = useLoad(() => orNull(api<RiskRun>('GET', '/api/v1/risk/assessments/latest?limit=6')), [api])
  const recs = useLoad(() => api<{ items: Recommendation[] }>('GET', '/api/v1/recommendations?status=open'), [api])
  const rems = useLoad(() => api<Paged<Remediation>>('GET', '/api/v1/remediations?status=pending_approval&limit=100'), [api])
  const audit = useLoad(() => api<{ items: AuditEvent[] }>('GET', '/api/v1/audit/events?limit=8'), [api])

  const savings = (recs.data?.items ?? []).reduce((s, r) => s + r.projected_monthly_savings, 0)
  const bands = risk.data?.summary.by_band ?? {}
  const failing = cov.data?.summary.failing ?? 0
  const total = cov.data?.summary.total ?? 0
  const pending = rems.data ? `${rems.data.items.length}${rems.data.next_cursor ? '+' : ''}` : undefined

  return (
    <div className="space-y-5">
      <StatGrid>
        <StatCard label="Failing baseline controls" icon={<ShieldCheck />} loading={cov.loading && !cov.data}
          value={cov.data ? failing : undefined} tone="auto" autoTone="danger"
          hint={cov.data && <><span className="tabular-nums">{total - failing} of {total}</span> passing<Meter value={total - failing} max={total} tone={failing ? 'warning' : 'success'} label="Controls passing" /></>}
          onOpen={() => go('compliance')} />
        <StatCard label="High and critical risks" icon={<ShieldAlert />} loading={risk.loading && risk.data === null && !risk.error}
          value={risk.data ? (bands.critical ?? 0) + (bands.high ?? 0) : risk.data === null ? '—' : undefined} tone="auto" autoTone="high"
          hint={risk.data ? `${bands.critical ?? 0} critical · assessed ${ago(risk.data.created_at)}` : 'No assessment yet'} onOpen={() => go('risk')} />
        <StatCard label="Internet-reachable sensitive data" icon={<Globe2 />} value={risk.data?.summary.internet_reachable_sensitive_targets ?? (risk.data === null ? '—' : undefined)}
          tone="auto" autoTone="danger" hint="Attack paths from the internet" onOpen={() => go('risk')} />
        <StatCard label="Open savings / month" icon={<BadgeDollarSign />} loading={recs.loading && !recs.data}
          value={recs.data ? usdCompact(savings) : undefined} tone={savings > 0 ? 'success' : 'neutral'}
          hint={recs.data && `${recs.data.items.length} recommendations`} onOpen={() => go('cost')} />
        <StatCard label="Awaiting approval" icon={<Wrench />} loading={rems.loading && !rems.data} value={pending}
          tone={rems.data?.items.length ? 'warning' : 'neutral'} hint="Remediations pending a decision" onOpen={() => go('remediation', { status: 'pending_approval' })} />
      </StatGrid>

      <div className="grid gap-5 xl:grid-cols-[3fr_2fr]">
        <Card title="Top risks" description="Failing findings with the highest contextual risk."
          actions={<Button size="sm" variant="ghost" onClick={() => go('risk')}>All risks</Button>}>
          {risk.data === null && !risk.loading ? (
            <EmptyState icon={<ShieldAlert />} title="No risk assessment yet" action={<Button size="sm" onClick={() => go('risk')}>Go to Risk</Button>}>
              Evaluate compliance, then run an assessment to rank findings.
            </EmptyState>
          ) : (
            <DataTable rows={risk.data?.assessments} loading={risk.loading} error={risk.error} onRetry={risk.reload}
              getRowId={(a) => a.rule_id + a.subject} rowTone={(a) => (a.band === 'critical' ? 'danger' : a.band === 'high' ? 'high' : undefined)}
              columns={[
                { key: 'band', header: 'Band', cell: (a) => <StatusBadge value={a.band} /> },
                { key: 'subject', header: 'Resource', cell: (a) => <Mono value={a.subject} copy={false} max={40} /> },
                { key: 'rule', header: 'Rule', cell: (a) => <span className="text-fg-muted">{a.rule_id}</span>, hideOnMobile: true },
                { key: 'score', header: 'Score', align: 'right', cell: (a) => a.score.toFixed(1) },
                { key: 'go', header: <span className="sr-only">Actions</span>, align: 'right', cell: (a) => <Button size="sm" variant="ghost" onClick={() => go('investigate', { resource: a.subject, run: '1' })}>Investigate</Button> },
              ]} />
          )}
        </Card>

        <Card title="Recent activity" description="From the hash-chained audit log.">
          <DataTable rows={audit.data?.items} loading={audit.loading} error={audit.error} onRetry={audit.reload} dense
            getRowId={(e) => String(e.seq)} empty="No audit events yet."
            columns={[
              { key: 'action', header: 'Action', cell: (e) => <><div className="font-medium">{e.action}</div><div className="text-xs text-fg-subtle">{e.actor}</div></> },
              { key: 'outcome', header: 'Outcome', cell: (e) => <StatusBadge value={e.outcome === 'success' ? 'succeeded' : e.outcome} /> },
              { key: 'when', header: 'When', align: 'right', cell: (e) => <span className="whitespace-nowrap text-xs text-fg-subtle" title={e.occurred_at}>{ago(e.occurred_at)}</span> },
            ]} />
        </Card>
      </div>
    </div>
  )
}
