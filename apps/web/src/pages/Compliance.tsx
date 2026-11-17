import { useState } from 'react'
import { can, type PageProps } from '../nav'
import type { ControlDetail, Coverage, ExceptionView, Framework } from '../types'
import { Badge, ConfirmButton, Empty, ErrorBox, Panel } from '../ui'
import { useAction, useLoad, when, useDraft } from '../hooks'

export default function Compliance({ api, me, go }: PageProps) {
  const fw = useLoad(() => api<{ frameworks: Framework[]; catalog_version: string }>('GET', '/api/v1/compliance/frameworks'), [api])
  const [framework, setFramework] = useState('aegis-baseline-1')
  const cov = useLoad(() => api<Coverage>('GET', `/api/v1/compliance/coverage?framework=${framework}`), [api, framework])
  const [control, setControl] = useState<string | null>(null)
  const act = useAction()

  return (
    <div className="stack">
      <Panel title="Control coverage" actions={
        <>
          <select aria-label="Framework" value={framework} onChange={(e) => { setFramework(e.target.value); setControl(null) }}>
            {(fw.data?.frameworks ?? []).map((f) => <option key={f.id} value={f.id}>{f.name} {f.version}</option>)}
          </select>
          {can(me, 'operate') && (
            <button className="primary" disabled={act.busy} onClick={async () => {
              await act.run(() => api('POST', '/api/v1/compliance/evaluations', { source: 'inventory' }))
              cov.reload()
            }}>{act.busy ? 'Evaluating…' : 'Evaluate inventory now'}</button>
          )}
        </>
      }>
        <ErrorBox error={act.error ?? cov.error} />
        {cov.data && <p className="notice small">{cov.data.notice}</p>}
        <table className="table">
          <thead><tr><th>Control</th><th>Status</th><th className="num">Pass</th><th className="num">Fail</th><th className="num">Excepted</th><th>Evaluated</th></tr></thead>
          <tbody>
            {(cov.data?.controls ?? []).map((c) => (
              <tr key={c.control_id} className={`clickable ${control === c.control_id ? 'selected' : ''}`} onClick={() => setControl(c.control_id)}>
                <td><b>{c.control_id}</b> <span className="small">{c.title}</span></td>
                <td><Badge value={c.status} /> {c.stale && <Badge value="stale" />}</td>
                <td className="num">{c.pass}</td>
                <td className="num">{c.fail}</td>
                <td className="num">{c.excepted}</td>
                <td className="small muted">{when(c.last_evaluated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
      {control && <ControlPanel key={framework + control} {...{ api, me, go }} framework={framework} control={control} />}
      <Exceptions {...{ api, me }} />
    </div>
  )
}

function ControlPanel({ api, me, go, framework, control }: Pick<PageProps, 'api' | 'me' | 'go'> & { framework: string; control: string }) {
  const d = useLoad(() => api<ControlDetail>('GET', `/api/v1/compliance/controls/${framework}/${control}`), [api, framework, control])
  const [req, setReq] = useState<{ rule: string; subject: string } | null>(null)
  const fails = (d.data?.evaluations ?? []).filter((e) => e.result !== 'pass')
  return (
    <Panel title={`Evidence: ${control}`}>
      <ErrorBox error={d.error} />
      {d.data && (
        <>
          <p className="small">{d.data.title}</p>
          <table className="table">
            <thead><tr><th>Rule</th><th>Coverage</th><th>Mapping</th><th className="num">Fail</th></tr></thead>
            <tbody>
              {d.data.rules.map((r) => (
                <tr key={r.rule_id}><td>{r.rule_id} <span className="small muted">{r.title}</span></td><td>{r.coverage}</td><td><Badge value={r.review_status} /></td><td className="num">{r.fail}</td></tr>
              ))}
            </tbody>
          </table>
          <h3>Findings ({fails.length})</h3>
          {fails.length === 0 && <Empty>No failing evaluations.</Empty>}
          <table className="table">
            <tbody>
              {fails.slice(0, 100).map((e) => (
                <tr key={e.rule_id + e.subject}>
                  <td><Badge value={e.result} /></td>
                  <td className="mono">{e.subject}</td>
                  <td>{e.rule_id}</td>
                  <td className="small">{e.message}<div className="muted">snapshot v{String(e.evidence.version ?? '?')} · {String(e.evidence.content_sha256 ?? '').slice(0, 12)}</div></td>
                  <td className="actions-cell">
                    <button className="link" onClick={() => go('investigate', { resource: e.subject, run: '1' })}>Investigate</button>
                    {can(me, 'operate') && e.result === 'fail' && (
                      <>
                        <button className="link" onClick={() => go('remediation', { propose: '1', rule: e.rule_id, resource: e.subject })}>Fix</button>
                        <button className="link" onClick={() => setReq({ rule: e.rule_id, subject: e.subject })}>Exception</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {req && <RequestException api={api} rule={req.rule} subject={req.subject} onDone={() => { setReq(null); d.reload() }} />}
        </>
      )}
    </Panel>
  )
}

function RequestException({ api, rule, subject, onDone }: { api: PageProps['api']; rule: string; subject: string; onDone: () => void }) {
  const [just, setJust, clearJust] = useDraft(`exception.${rule}.${subject}`, '')
  const [days, setDays] = useState(30)
  const act = useAction()
  return (
    <form className="card" onSubmit={async (e) => {
      e.preventDefault()
      const expires = new Date(Date.now() + days * 86400_000).toISOString()
      const r = await act.run(() => api('POST', '/api/v1/compliance/exceptions', { rule_id: rule, subject, justification: just, expires_at: expires }))
      if (r !== undefined) {
        clearJust()
        onDone()
      }
    }}>
      <h3>Request an exception for {rule} on <span className="mono">{subject}</span></h3>
      <textarea aria-label="Justification" required minLength={20} placeholder="Why is this risk accepted, and what compensates for it? (20+ characters)"
        value={just} onChange={(e) => setJust(e.target.value)} />
      <div className="row">
        <label>Expires in <input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 70 }} /> days</label>
        <button className="primary" disabled={act.busy}>Request</button>
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
      <p className="muted small">Someone other than you must approve it. It expires automatically.</p>
      <ErrorBox error={act.error} />
    </form>
  )
}

function Exceptions({ api, me }: Pick<PageProps, 'api' | 'me'>) {
  const ex = useLoad(() => api<{ items: ExceptionView[] }>('GET', '/api/v1/compliance/exceptions'), [api])
  const act = useAction()
  const decide = async (id: string, d: string) => {
    await act.run(() => api('POST', `/api/v1/compliance/exceptions/${id}/${d}`))
    ex.reload()
  }
  return (
    <Panel title="Exceptions">
      <ErrorBox error={act.error ?? ex.error} />
      {ex.data && ex.data.items.length === 0 && <Empty>No exceptions.</Empty>}
      <table className="table">
        <tbody>
          {(ex.data?.items ?? []).map((x) => (
            <tr key={x.id}>
              <td><Badge value={x.status} /></td>
              <td>{x.rule_id}</td>
              <td className="mono">{x.subject}</td>
              <td className="small">{x.justification}<div className="muted">requested by {x.requested_by}{x.decided_by && `, decided by ${x.decided_by}`} · expires {when(x.expires_at)}</div></td>
              <td className="actions-cell">
                {can(me, 'approve') && x.status === 'requested' && x.requested_by !== me.subject && (
                  <>
                    <button onClick={() => decide(x.id, 'approve')}>Approve</button>
                    <ConfirmButton label="Reject" confirm="Reject this exception?" onConfirm={() => decide(x.id, 'reject')} />
                  </>
                )}
                {can(me, 'approve') && x.status === 'approved' && <ConfirmButton label="Revoke" confirm="Revoke this exception? The rule fails again." onConfirm={() => decide(x.id, 'revoke')} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}
