import { useState } from 'react'
import { ApiError } from '../client'
import { can, type PageProps } from '../nav'
import type { CostSummary, MLResult, Recommendation } from '../types'
import { Badge, Empty, ErrorBox, Panel, Stat } from '../ui'
import { pct, useAction, useLoad, usd, when } from '../hooks'

const orNull = async <T,>(p: Promise<T>): Promise<T | null> => {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}

export default function Cost({ api, me }: PageProps) {
  const [groupBy, setGroupBy] = useState('team')
  const sum = useLoad(() => orNull(api<CostSummary>('GET', `/api/v1/cost/summary?group_by=${groupBy}`)), [api, groupBy])
  const anomalies = useLoad(() => orNull(api<MLResult>('GET', '/api/v1/cost/anomalies')), [api])
  const forecast = useLoad(() => orNull(api<MLResult>('GET', '/api/v1/cost/forecast?entity=total')), [api])
  const max = Math.max(...(sum.data?.groups ?? [{ usd: 1 }]).map((g) => g.usd))
  const fcTotal = (forecast.data?.points ?? []).reduce((s, p) => s + Number(p.predicted_usd ?? 0), 0)
  const recent = [...(anomalies.data?.points ?? [])].sort((a, b) => String(b.date).localeCompare(String(a.date))).slice(0, 12)

  return (
    <div className="stack">
      <Panel title="Spend" actions={
        <select aria-label="Group by" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
          {['team', 'service', 'environment', 'account', 'allocation_method'].map((g) => <option key={g}>{g}</option>)}
        </select>
      }>
        <ErrorBox error={sum.error} />
        {sum.data === null && <Empty>No cost data imported yet (POST /api/v1/cost/import).</Empty>}
        {sum.data && (
          <>
            <div className="stats">
              <Stat label={`Total ${sum.data.from} → ${sum.data.to}`} value={usd(sum.data.total_usd)} />
              <Stat label="Forecast, next 30 days" value={forecast.data ? usd(fcTotal) : '—'} />
              <Stat label="Anomalous days (latest run)" value={anomalies.data?.points.length ?? '—'} tone="warn" />
            </div>
            <div className="bars">
              {sum.data.groups.map((g) => (
                <div key={g.key} className="bar-row">
                  <span className="bar-label">{g.key}</span>
                  <span className="bar" style={{ width: `${(g.usd / max) * 100}%` }} />
                  <span className="bar-value">{usd(g.usd)} · {pct(g.share)}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>

      <div className="grid2">
        <Panel title="Recent anomalies">
          <ErrorBox error={anomalies.error} />
          {anomalies.data === null && <Empty>The ML worker has not run yet (python -m aegis_ml.worker).</Empty>}
          {anomalies.data && <p className="muted small">{anomalies.data.model}, run {when(anomalies.data.created_at)}</p>}
          <table className="table">
            <tbody>
              {recent.map((p) => (
                <tr key={`${p.date}${p.entity}`}>
                  <td>{String(p.date)}</td>
                  <td>{String(p.entity)}</td>
                  <td className="num">{usd(Number(p.observed_usd))}</td>
                  <td className="small muted">expected {usd(Number(p.expected_usd))}</td>
                  <td className="num">z {Number(p.score).toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Forecast (total)">
          {forecast.data && (() => {
            const vals = forecast.data.points.map((p) => Number(p.predicted_usd))
            return (
              <p className="muted small">
                {forecast.data.model} · trained on {forecast.data.data_from} → {forecast.data.data_to} · {vals.length} days,{' '}
                {usd(Math.min(...vals))} – {usd(Math.max(...vals))} per day
              </p>
            )
          })()}
          <div className="spark" aria-label="Forecast">
            {(forecast.data?.points ?? []).map((p) => {
              const v = Number(p.predicted_usd)
              const top = Math.max(...(forecast.data?.points ?? []).map((q) => Number(q.predicted_usd)))
              return <span key={String(p.date)} title={`${p.date}: ${usd(v)}`} style={{ height: `${(v / top) * 100}%` }} />
            })}
          </div>
        </Panel>
      </div>
      <Recommendations api={api} me={me} />
    </div>
  )
}

function Recommendations({ api, me }: Pick<PageProps, 'api' | 'me'>) {
  const [status, setStatus] = useState('open')
  const recs = useLoad(() => api<{ items: Recommendation[] }>('GET', `/api/v1/recommendations?status=${status}`), [api, status])
  const act = useAction()
  const decide = async (id: string, action: string) => {
    const body = action === 'implement' ? { implemented_at: new Date().toISOString().slice(0, 10) } : undefined
    await act.run(() => api('POST', `/api/v1/recommendations/${id}/${action}`, body))
    recs.reload()
  }
  const total = (recs.data?.items ?? []).reduce((s, r) => s + r.projected_monthly_savings, 0)
  return (
    <Panel title="Optimisation recommendations" actions={
      <>
        <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
          {['open', 'accepted', 'implemented', 'dismissed'].map((s) => <option key={s}>{s}</option>)}
        </select>
        {can(me, 'operate') && <button className="primary" disabled={act.busy} onClick={async () => { await act.run(() => api('POST', '/api/v1/recommendations', {})); recs.reload() }}>Generate</button>}
      </>
    }>
      <ErrorBox error={act.error ?? recs.error} />
      <p className="muted small">{recs.data?.items.length ?? 0} recommendations · projected {usd(total)} / month. Projections use illustrative list prices; measured savings appear after implementation.</p>
      <table className="table">
        <tbody>
          {(recs.data?.items ?? []).slice(0, 100).map((r) => (
            <tr key={r.id}>
              <td><Badge value={r.kind.replace(/_/g, ' ')} /></td>
              <td className="mono">{r.resource_id}</td>
              <td>{r.team || '—'}</td>
              <td className="small">{String(r.details.reason ?? r.details.action ?? '')}</td>
              <td className="num">{usd(r.projected_monthly_savings)}{r.measured_monthly_savings !== undefined && <div className="small ok-text">measured {usd(r.measured_monthly_savings)}</div>}</td>
              <td className="actions-cell">
                {can(me, 'operate') && r.status === 'open' && <><button onClick={() => decide(r.id, 'accept')}>Accept</button><button onClick={() => decide(r.id, 'dismiss')}>Dismiss</button></>}
                {can(me, 'operate') && r.status === 'accepted' && <button onClick={() => decide(r.id, 'implement')}>Mark implemented</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}
