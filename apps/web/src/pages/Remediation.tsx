import { useState } from 'react'
import { can, type PageProps } from '../nav'
import type { Remediation as Rem, Template } from '../types'
import { Badge, Empty, ErrorBox, Panel } from '../ui'
import { useAction, useLoad, when, useDraft } from '../hooks'

const fmt = (v: unknown) => (v === undefined ? '—' : JSON.stringify(v))

export default function Remediation({ api, me, go, params }: PageProps) {
  const id = params.get('id')
  if (id) return <Detail {...{ api, me, go }} id={id} />
  return (
    <div className="stack">
      {can(me, 'operate') && <Propose {...{ api, go, params }} />}
      <List {...{ api, go }} />
    </div>
  )
}

function List({ api, go }: Pick<PageProps, 'api' | 'go'>) {
  const [status, setStatus] = useState('')
  const list = useLoad(() => api<{ items: Rem[] }>('GET', `/api/v1/remediations${status ? '?status=' + status : ''}`), [api, status])
  return (
    <Panel title="Remediations" actions={
      <select aria-label="Status" value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="">All</option>
        {['pending_approval', 'approved', 'released', 'verified', 'verification_failed', 'blocked', 'rejected', 'stale'].map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
      </select>
    }>
      <ErrorBox error={list.error} />
      {list.data && list.data.items.length === 0 && <Empty>No remediations.</Empty>}
      <table className="table">
        <tbody>
          {(list.data?.items ?? []).map((r) => (
            <tr key={r.id} className="clickable" onClick={() => go('remediation', { id: r.id })}>
              <td><Badge value={r.status} /></td>
              <td className="mono">{r.resource_id}</td>
              <td>{r.rule_id || 'manual'}</td>
              <td className="small muted">by {r.requested_by} · {when(r.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}

function Propose({ api, go, params }: Pick<PageProps, 'api' | 'go' | 'params'>) {
  const tpl = useLoad(() => api<{ items: Template[] }>('GET', '/api/v1/remediation/templates'), [api])
  const [source, setSource] = useState<'finding' | 'manual'>('finding')
  const [rule, setRule] = useState(params.get('rule') ?? 'AEGIS-S3-001')
  const [resource, setResource] = useState(params.get('resource') ?? '')
  const [ops, setOps, clearOps] = useDraft('remediation.ops', '[{"op": "set", "path": "tags.owner", "value": "platform-team"}]')
  const [just, setJust, clearJust] = useDraft('remediation.justification', '')
  const act = useAction()
  const submit = async () => {
    let operations: unknown
    if (source === 'manual') {
      try {
        operations = JSON.parse(ops)
      } catch {
        act.setError(new Error('Operations must be valid JSON.'))
        return
      }
    }
    const r = await act.run(() => api<Rem>('POST', '/api/v1/remediations', source === 'finding'
      ? { source, rule_id: rule, resource_id: resource, justification: just }
      : { source, resource_id: resource, operations, justification: just }))
    if (r) {
      clearOps()
      clearJust()
      go('remediation', { id: r.id })
    }
  }
  const t = tpl.data?.items.find((x) => x.rule_id === rule)
  return (
    <Panel title="Propose a remediation">
      <p className="muted small">
        Aegis simulates the change with the same policies used for compliance. A plan that breaks another rule, or does not fix
        the target, is blocked. Approved plans are released as a change set for your pipeline; Aegis never changes the cloud itself.
      </p>
      <form className="form" onSubmit={(e) => { e.preventDefault(); void submit() }}>
        <div className="row">
          <label><input type="radio" checked={source === 'finding'} onChange={() => setSource('finding')} /> Fix a failing rule (template)</label>
          <label><input type="radio" checked={source === 'manual'} onChange={() => setSource('manual')} /> Manual change</label>
        </div>
        <input aria-label="Resource ID" required placeholder="Resource ID" value={resource} onChange={(e) => setResource(e.target.value)} />
        {source === 'finding' ? (
          <>
            <select aria-label="Rule" value={rule} onChange={(e) => setRule(e.target.value)}>
              {(tpl.data?.items ?? []).map((x) => <option key={x.rule_id} value={x.rule_id}>{x.rule_id}: {x.title}</option>)}
            </select>
            {t && <p className="small">{t.disruptive && <Badge value="disruptive" />} {t.note}</p>}
          </>
        ) : (
          <textarea aria-label="Operations" className="mono" rows={4} value={ops} onChange={(e) => setOps(e.target.value)} />
        )}
        <textarea aria-label="Justification" required minLength={10} placeholder="Justification (10+ characters)" value={just} onChange={(e) => setJust(e.target.value)} />
        <div><button className="primary" disabled={act.busy}>{act.busy ? 'Simulating…' : 'Simulate and propose'}</button></div>
        <ErrorBox error={act.error} />
      </form>
    </Panel>
  )
}

function Detail({ api, me, go, id }: Pick<PageProps, 'api' | 'me' | 'go'> & { id: string }) {
  const r = useLoad(() => api<Rem>('GET', `/api/v1/remediations/${id}`), [api, id])
  const act = useAction()
  const [comment, setComment] = useState('')
  const step = async (s: string) => {
    const body = s === 'approve' || s === 'reject' ? { comment } : undefined
    const out = await act.run(() => api<Rem>('POST', `/api/v1/remediations/${id}/${s}`, body))
    if (out) r.reload()
  }
  const x = r.data
  if (!x) return <Panel title="Remediation"><ErrorBox error={r.error} /></Panel>
  const sim = x.simulation
  const approvals = x.approvals.filter((a) => a.decision === 'approve').length
  const mine = x.requested_by === me.subject
  const decided = x.approvals.some((a) => a.actor === me.subject)
  return (
    <div className="stack">
      <button className="link" onClick={() => go('remediation')}>← All remediations</button>
      <Panel title={`${x.rule_id || 'Manual change'} on ${x.resource_id}`} actions={<Badge value={x.status} />}>
        <p className="small">Requested by <b>{x.requested_by}</b> · {when(x.created_at)} · environment {sim.environment || '—'} · plan <code>{x.plan_sha256.slice(0, 12)}</code></p>
        <p className="small">{x.justification}</p>
        {x.status === 'stale' && (
          <p className="error">This plan is stale: {x.stale_reason || 'the resource or the policies changed'}. Propose it again to simulate against the current state.</p>
        )}
        <div className="grid2">
          <div>
            <h3>Simulation (OPA, before → after)</h3>
            <p><Badge value={sim.passed ? 'passed' : 'blocked'} /> {sim.blocked_reasons.join('; ')}</p>
            <p className="small">Resolved: {sim.resolved.join(', ') || 'none'}<br />Introduced: {sim.introduced.join(', ') || 'none'}<br />Still failing: {sim.failing_after.join(', ') || 'none'}</p>
            <table className="table"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead>
              <tbody>{sim.diff.map((d) => <tr key={d.path}><td className="mono">{d.path}</td><td className="mono small">{fmt(d.before)}</td><td className="mono small">{fmt(d.after)}</td></tr>)}</tbody>
            </table>
          </div>
          <div>
            <h3>Reviewer notes</h3>
            <ul className="small">{sim.notes.map((n) => <li key={n}>{n}</li>)}</ul>
            <h3>Impact ({sim.impact.incoming.length + sim.impact.outgoing.length} connected resources)</h3>
            <ul className="small mono">{[...sim.impact.incoming, ...sim.impact.outgoing].slice(0, 15).map((i) => <li key={i}>{i}</li>)}</ul>
          </div>
        </div>
      </Panel>

      <Panel title={`Approvals (${approvals} of ${x.required_approvals} required)`}>
        {x.approvals.length === 0 && <Empty>No decisions yet.</Empty>}
        <ul className="small">{x.approvals.map((a) => <li key={a.actor}><Badge value={a.decision === 'approve' ? 'approved' : 'rejected'} /> {a.actor} · {when(a.created_at)} {a.comment && `· “${a.comment}”`}</li>)}</ul>
        {x.status === 'pending_approval' && can(me, 'approve') && (
          mine ? <p className="muted small">You requested this change, so someone else must approve it.</p>
            : decided ? <p className="muted small">You have already decided.</p>
              : (
                <div className="row">
                  <input aria-label="Comment" placeholder="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} />
                  <button className="primary" disabled={act.busy} onClick={() => step('approve')}>Approve</button>
                  <button disabled={act.busy} onClick={() => step('reject')}>Reject</button>
                </div>
              )
        )}
        {x.status === 'approved' && can(me, 'approve') && <button className="primary" disabled={act.busy} onClick={() => step('release')}>Release change set</button>}
        {(x.status === 'released' || x.status === 'verification_failed') && can(me, 'operate') && (
          <button disabled={act.busy} onClick={() => step('verify')}>Verify against latest inventory</button>
        )}
        <ErrorBox error={act.error} />
      </Panel>

      {x.change_set && (
        <Panel title="Change set">
          <p className="small">{x.change_set.instructions}</p>
          {x.change_set.signed ? (
            <p className="small ok-text">
              Signed (Ed25519, key <code>{x.change_set.signed.key_id}</code>). Before applying, verify it with
              {' '}<code>go run ./cmd/aegis-verify -key &lt;public key&gt; remediation.json</code>; the public key is at <code>/api/v1/signing-key</code>.
            </p>
          ) : <p className="small muted">This change set is not signed (no signing key configured).</p>}
          <pre className="code">{JSON.stringify(x.change_set.operations, null, 2)}</pre>
        </Panel>
      )}
      {x.verification && (
        <Panel title="Verification">
          <p><Badge value={x.verification.verified ? 'verified' : 'verification_failed'} /></p>
          <p className="small">Approved values present: {String(x.verification.config_matches)} · target rule passes: {String(x.verification.target_resolved)}
            {x.verification.mismatched_paths.length > 0 && <> · mismatched: {x.verification.mismatched_paths.join(', ')}</>}
            {x.verification.unexpected_failures.length > 0 && <> · unexpected failures: {x.verification.unexpected_failures.join(', ')}</>}</p>
        </Panel>
      )}
    </div>
  )
}
