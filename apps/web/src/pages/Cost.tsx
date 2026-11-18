import { useState } from 'react'
import { BadgeDollarSign, Lightbulb, LineChart, Sparkles, TrendingUp } from 'lucide-react'
import { ApiError } from '../client'
import { can, patchParams, type PageProps } from '../nav'
import type { CostSummary, MLResult, Recommendation } from '../types'
import {
  AreaChart, BarList, Button, Callout, Card, ConfirmAction, DataTable, EmptyState, ErrorState, Mono, Pager, Select, Skeleton,
  StatCard, StatGrid, StatusBadge, useToast,
} from '@/components/ui'
import { ago, pct, useAction, useLoad, usd, usdCompact, when } from '../hooks'

const orNull = async <T,>(p: Promise<T>): Promise<T | null> => {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}

const GROUPS = ['team', 'service', 'environment', 'account', 'allocation_method']

export default function Cost({ api, me, go, params }: PageProps) {
  const [now] = useState(() => Date.now()) // read once per visit, not on every render
  const groupBy = params.get('group_by') || 'team'
  const sum = useLoad(() => orNull(api<CostSummary>('GET', `/api/v1/cost/summary?group_by=${groupBy}`)), [api, groupBy])
  const anomalies = useLoad(() => orNull(api<MLResult>('GET', '/api/v1/cost/anomalies')), [api])
  const forecast = useLoad(() => orNull(api<MLResult>('GET', '/api/v1/cost/forecast?entity=total')), [api])
  const fcPoints = (forecast.data?.points ?? []).map((p) => ({ x: String(p.date), y: Number(p.predicted_usd ?? 0) }))
  const fcTotal = fcPoints.reduce((s, p) => s + p.y, 0)
  const recent = [...(anomalies.data?.points ?? [])].sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 12)
  const stale = anomalies.data && now - new Date(anomalies.data.created_at).getTime() > 2 * 86400_000

  return (
    <div className="space-y-5">
      {sum.loading && !sum.data ? <Skeleton rows={2} /> : sum.data === null ? (
        <EmptyState icon={<BadgeDollarSign />} title="No cost data imported yet">Import a CUR-style CSV with <code className="font-mono">POST /api/v1/cost/import</code>.</EmptyState>
      ) : sum.data && (
        <StatGrid>
          <StatCard label="Total spend" icon={<BadgeDollarSign />} value={usdCompact(sum.data.total_usd)} hint={`${sum.data.from} → ${sum.data.to}`} />
          <StatCard label="Forecast, next 30 days" icon={<TrendingUp />} value={forecast.data ? usdCompact(fcTotal) : '—'} hint={forecast.data?.model} />
          <StatCard label="Anomalous days" icon={<Sparkles />} value={anomalies.data?.points.length ?? '—'} tone="auto" autoTone="warning" hint="Latest ML run" />
        </StatGrid>
      )}
      {stale && (
        <Callout tone="warning" title="ML results are more than two days old">
          Anomaly and forecast results are from {when(anomalies.data!.created_at)}. Is the ML worker running? (<code className="font-mono">docker compose --profile core --profile ml up -d</code>)
        </Callout>
      )}

      <div className="grid gap-5 xl:grid-cols-2">
        <Card title="Spend by group" icon={<BadgeDollarSign />} description={sum.data ? `${sum.data.from} → ${sum.data.to}, largest first` : undefined}
          actions={<Select aria-label="Group by" value={groupBy} onChange={(e) => go('cost', patchParams(params, { group_by: e.target.value === 'team' ? '' : e.target.value }))}>
            {GROUPS.map((g) => <option key={g} value={g}>{g.replace(/_/g, ' ')}</option>)}
          </Select>}>
          <ErrorState error={sum.error} onRetry={sum.reload} />
          {sum.data && <BarList label={`Spend by ${groupBy}`} format={usd}
            items={[...sum.data.groups].sort((a, b) => b.usd - a.usd).map((g) => ({ key: g.key, value: g.usd, note: pct(g.share) }))} />}
        </Card>

        <Card title="Forecast, total spend per day" icon={<LineChart />}
          description={forecast.data ? `${forecast.data.model} · trained on ${forecast.data.data_from} → ${forecast.data.data_to}` : 'From the ML worker'}>
          <ErrorState error={forecast.error} onRetry={forecast.reload} />
          {forecast.data === null ? <EmptyState title="No forecast yet">The ML worker has not run (python -m aegis_ml.worker).</EmptyState>
            : fcPoints.length > 0 && <AreaChart points={fcPoints} format={usd} label="Forecast of total spend per day" />}
        </Card>
      </div>

      <Card title="Recent anomalies" icon={<Sparkles />} description={anomalies.data ? `${anomalies.data.model}, run ${ago(anomalies.data.created_at)}` : undefined}>
        {anomalies.data === null ? <EmptyState title="The ML worker has not run yet" /> : (
          <DataTable rows={recent} loading={anomalies.loading} error={anomalies.error} onRetry={anomalies.reload}
            getRowId={(p) => `${p.date}${p.entity}`} empty="No anomalies in the latest run." rowTone={() => 'warning'}
            columns={[
              { key: 'date', header: 'Date', cell: (p) => String(p.date) },
              { key: 'entity', header: 'Entity', cell: (p) => String(p.entity) },
              { key: 'obs', header: 'Observed', align: 'right', cell: (p) => usd(Number(p.observed_usd)) },
              { key: 'exp', header: 'Expected', align: 'right', cell: (p) => <span className="text-fg-muted">{usd(Number(p.expected_usd))}</span> },
              { key: 'z', header: 'Score', align: 'right', cell: (p) => Number(p.score).toFixed(1), hideOnMobile: true },
            ]} />
        )}
      </Card>
      <Recommendations api={api} me={me} />
    </div>
  )
}

function Recommendations({ api, me }: Pick<PageProps, 'api' | 'me'>) {
  const [status, setStatus] = useState('open')
  const recs = useLoad(() => api<{ items: Recommendation[] }>('GET', `/api/v1/recommendations?status=${status}`), [api, status])
  const act = useAction()
  const toast = useToast()
  const decide = async (id: string, action: string) => {
    const body = action === 'implement' ? { implemented_at: new Date().toISOString().slice(0, 10) } : undefined
    const r = await act.run(() => api('POST', `/api/v1/recommendations/${id}/${action}`, body))
    if (r !== undefined) toast(`Recommendation ${action === 'implement' ? 'marked implemented' : action === 'accept' ? 'accepted' : 'dismissed'}.`)
    recs.reload()
  }
  const [shown, setShown] = useState(20)
  const items = [...(recs.data?.items ?? [])].sort((a, b) => b.projected_monthly_savings - a.projected_monthly_savings)
  const total = items.reduce((s, r) => s + r.projected_monthly_savings, 0)
  return (
    <Card title="Optimisation recommendations" icon={<Lightbulb />}
      description={`${items.length} recommendations · projected ${usd(total)} / month. Projections use illustrative list prices; measured savings appear after implementation.`}
      actions={
        <>
          <Select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
            {['open', 'accepted', 'implemented', 'dismissed'].map((s) => <option key={s}>{s}</option>)}
          </Select>
          {can(me, 'operate') && <Button variant="primary" loading={act.busy} onClick={async () => {
            const r = await act.run(() => api('POST', '/api/v1/recommendations', {}))
            if (r !== undefined) toast('Recommendations generated.')
            recs.reload()
          }}>Generate</Button>}
        </>
      }>
      <ErrorState error={act.error} className="mb-3" />
      <DataTable rows={recs.data ? items.slice(0, shown) : undefined} loading={recs.loading} error={recs.error} onRetry={recs.reload} getRowId={(r) => r.id}
        empty={<EmptyState icon={<Lightbulb />} title={`No ${status} recommendations`} />}
        columns={[
          { key: 'kind', header: 'Kind', cell: (r) => <StatusBadge value={r.status} icon={false} label={r.kind.replace(/_/g, ' ')} /> },
          { key: 'res', header: 'Resource', cell: (r) => <Mono value={r.resource_id} /> },
          { key: 'team', header: 'Team', cell: (r) => r.team || '—', hideOnMobile: true },
          { key: 'why', header: 'Why', cell: (r) => <span className="text-fg-muted">{String(r.details.reason ?? r.details.action ?? '')}</span>, hideOnMobile: true },
          { key: 'save', header: 'Savings / month', align: 'right', cell: (r) => (
            <>{usd(r.projected_monthly_savings)}{r.measured_monthly_savings !== undefined && <div className="ok-text text-xs text-success">measured {usd(r.measured_monthly_savings)}</div>}</>
          ) },
          { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: (r) => can(me, 'operate') && (
            <div className="flex justify-end gap-1.5">
              {r.status === 'open' && (
                <>
                  <Button size="sm" disabled={act.busy} onClick={() => decide(r.id, 'accept')}>Accept</Button>
                  <ConfirmAction size="sm" variant="ghost" label="Dismiss" title="Dismiss this recommendation?" description="It will not be suggested again for this resource." onConfirm={() => decide(r.id, 'dismiss')} />
                </>
              )}
              {r.status === 'accepted' && <Button size="sm" disabled={act.busy} onClick={() => decide(r.id, 'implement')}>Mark implemented</Button>}
            </div>
          ) },
        ]} />
      <Pager mode="more" hasNext={items.length > shown} onNext={() => setShown((n) => n + 40)} count={Math.min(shown, items.length)} />
    </Card>
  )
}
