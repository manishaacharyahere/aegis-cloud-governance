import { useState } from 'react'
import { ApiError } from '../client'
import { can, type PageProps } from '../nav'
import type { AttackPath, RiskRun } from '../types'
import { Badge, Empty, ErrorBox, Panel, Stat } from '../ui'
import { useAction, useLoad, when } from '../hooks'

export default function Risk({ api, me, go }: PageProps) {
  const [band, setBand] = useState('high')
  const run = useLoad(async () => {
    try {
      return await api<RiskRun>('GET', `/api/v1/risk/assessments/latest?min_band=${band}&limit=200`)
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }
  }, [api, band])
  const paths = useLoad(() => api<{ items: AttackPath[] }>('GET', '/api/v1/risk/attack-paths?limit=20'), [api])
  const act = useAction()
  const [open, setOpen] = useState<string | null>(null)

  const assess = async () => {
    await act.run(() => api('POST', '/api/v1/risk/assessments', {}))
    run.reload()
    paths.reload()
  }

  const s = run.data?.summary
  return (
    <div className="stack">
      <Panel title="Contextual risk" actions={can(me, 'operate') && (
        <button className="primary" disabled={act.busy} onClick={assess}>{act.busy ? 'Assessing…' : 'Run assessment'}</button>
      )}>
        <p className="muted small">
          Each failing compliance finding is scored 0–100 from six explainable factors: rule severity, internet exposure, privilege,
          criticality, data sensitivity and age. It needs a compliance evaluation first.
        </p>
        <ErrorBox error={act.error ?? run.error} />
        {run.data === null && !run.loading && <Empty>No assessment yet.</Empty>}
        {s && (
          <div className="stats">
            <Stat label="Findings scored" value={s.findings} />
            <Stat label="Critical" value={s.by_band.critical ?? 0} tone="bad" />
            <Stat label="High" value={s.by_band.high ?? 0} tone="warn" />
            <Stat label="Medium" value={s.by_band.medium ?? 0} />
            <Stat label="Sensitive targets reachable from the internet" value={s.internet_reachable_sensitive_targets} tone="bad" />
          </div>
        )}
        {run.data && <p className="muted small">Assessment of {when(run.data.created_at)}.</p>}
      </Panel>

      <Panel title="Findings by risk" actions={
        <select aria-label="Minimum band" value={band} onChange={(e) => setBand(e.target.value)}>
          <option value="critical">Critical only</option>
          <option value="high">High and above</option>
          <option value="medium">Medium and above</option>
          <option value="low">All</option>
        </select>
      }>
        {run.data && run.data.assessments.length === 0 && <Empty>No findings in this band.</Empty>}
        <table className="table">
          <tbody>
            {(run.data?.assessments ?? []).map((a) => {
              const key = a.rule_id + a.subject
              return (
                <tr key={key} className="clickable" onClick={() => setOpen(open === key ? null : key)}>
                  <td style={{ width: 90 }}><Badge value={a.band} /></td>
                  <td className="num" style={{ width: 60 }}>{a.score.toFixed(1)}</td>
                  <td>
                    <div className="mono">{a.subject}</div>
                    <div className="small muted">{a.rule_id} · severity {a.rule_severity}</div>
                    {open === key && (
                      <div className="detail">
                        <ul>{a.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                        {a.attack_path && a.attack_path.length > 0 && (
                          <p className="small">Attack path: {['internet', ...a.attack_path.map((h) => h.to)].join(' → ')}</p>
                        )}
                        {a.blast_radius.length > 0 && <p className="small">Blast radius: {a.blast_radius.length} resources</p>}
                      </div>
                    )}
                  </td>
                  <td style={{ width: 110 }}>
                    <button className="link" onClick={(e) => { e.stopPropagation(); go('investigate', { resource: a.subject }) }}>Investigate</button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Panel>

      <Panel title="Attack paths to sensitive data">
        <ErrorBox error={paths.error} />
        {paths.data && paths.data.items.length === 0 && <Empty>No internet-reachable sensitive targets.</Empty>}
        <table className="table">
          <tbody>
            {(paths.data?.items ?? []).map((p) => (
              <tr key={p.target}>
                <td className="num">{p.sensitivity}</td>
                <td className="mono">{p.target}</td>
                <td className="small">{['internet', ...p.hops.map((h) => h.to)].join(' → ')}<div className="muted">{p.hops.map((h) => h.reason).join('; ')}</div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  )
}
