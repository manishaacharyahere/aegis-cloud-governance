import type { PageProps } from '../nav'
import type { AuditEvent, Coverage, Recommendation, Remediation, RiskRun } from '../types'
import { Badge, Empty, ErrorBox, Panel, Stat } from '../ui'
import { useLoad, usd, when } from '../hooks'

export default function Overview({ api, go }: PageProps) {
  const cov = useLoad(() => api<Coverage>('GET', '/api/v1/compliance/coverage?framework=aegis-baseline-1'), [api])
  const risk = useLoad(() => api<RiskRun>('GET', '/api/v1/risk/assessments/latest?limit=5').catch(() => null), [api])
  const recs = useLoad(() => api<{ items: Recommendation[] }>('GET', '/api/v1/recommendations?status=open'), [api])
  const rems = useLoad(() => api<{ items: Remediation[] }>('GET', '/api/v1/remediations?status=pending_approval'), [api])
  const audit = useLoad(() => api<{ items: AuditEvent[] }>('GET', '/api/v1/audit/events?limit=8'), [api])

  const savings = (recs.data?.items ?? []).reduce((s, r) => s + r.projected_monthly_savings, 0)
  const bands = risk.data?.summary.by_band ?? {}
  return (
    <div className="stack">
      <div className="stats">
        <Stat label="Failing baseline controls" value={cov.data ? `${cov.data.summary.failing ?? 0} / ${cov.data.summary.total ?? 0}` : '—'}
          tone={(cov.data?.summary.failing ?? 0) > 0 ? 'bad' : 'ok'} />
        <Stat label="High and critical risk findings" value={risk.data ? (bands.critical ?? 0) + (bands.high ?? 0) : '—'} tone="warn" />
        <Stat label="Internet-reachable sensitive targets" value={risk.data?.summary.internet_reachable_sensitive_targets ?? '—'} tone="bad" />
        <Stat label="Open savings (projected / month)" value={recs.data ? usd(savings) : '—'} tone="ok" />
        <Stat label="Remediations awaiting approval" value={rems.data?.items.length ?? '—'} />
      </div>

      <div className="grid2">
        <Panel title="Top risks" actions={<button className="link" onClick={() => go('risk')}>All risks →</button>}>
          <ErrorBox error={risk.error} />
          {risk.data ? (
            <table className="table">
              <tbody>
                {risk.data.assessments.map((a) => (
                  <tr key={a.rule_id + a.subject}>
                    <td><Badge value={a.band} /></td>
                    <td className="mono">{a.subject}</td>
                    <td>{a.rule_id}</td>
                    <td className="num">{a.score.toFixed(1)}</td>
                    <td><button className="link" onClick={() => go('investigate', { resource: a.subject })}>Investigate</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty>No risk assessment yet. Run one from the Risk page.</Empty>
          )}
        </Panel>

        <Panel title="Recent activity (audit log)">
          <ErrorBox error={audit.error} />
          <table className="table">
            <tbody>
              {(audit.data?.items ?? []).map((e) => (
                <tr key={e.seq}>
                  <td className="muted small">{when(e.occurred_at)}</td>
                  <td className="mono small">{e.actor}</td>
                  <td>{e.action}</td>
                  <td><Badge value={e.outcome === 'success' ? 'succeeded' : e.outcome} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  )
}
