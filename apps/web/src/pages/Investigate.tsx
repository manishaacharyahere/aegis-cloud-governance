import { useEffect, useState } from 'react'
import { can, type PageProps } from '../nav'
import type { Claim, Investigation } from '../types'
import { Badge, ErrorBox, Panel } from '../ui'
import { useAction, when } from '../hooks'

function Cites({ ids, onPick }: { ids: string[]; onPick: (id: string) => void }) {
  return (
    <>
      {ids.map((id) => (
        <button key={id} className="cite" onClick={() => onPick(id)} title="Show the evidence">
          {id}
        </button>
      ))}
    </>
  )
}

function Claims({ claims, onPick }: { claims: Claim[]; onPick: (id: string) => void }) {
  return (
    <ul className="claims">
      {claims.map((c, i) => (
        <li key={i}>
          {c.text} <Cites ids={c.citations} onPick={onPick} />
        </li>
      ))}
    </ul>
  )
}

export default function Investigate({ api, me, go, params }: PageProps) {
  const [resource, setResource] = useState(params.get('resource') ?? '')
  const [question, setQuestion] = useState('')
  const [inv, setInv] = useState<Investigation | null>(null)
  const [focus, setFocus] = useState<string | null>(null)
  const act = useAction()

  const runIt = async (rid: string) => {
    if (!rid) return
    const r = await act.run(() => api<Investigation>('POST', '/api/v1/investigations', { resource_id: rid, question }))
    if (r) setInv(r)
  }
  useEffect(() => {
    const r = params.get('resource')
    if (r && can(me, 'operate')) void Promise.resolve().then(() => runIt(r))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.get('resource')])

  const pick = (id: string) => {
    setFocus(id)
    document.getElementById(`ev-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }
  const failing = (inv?.evidence ?? []).filter((e) => e.kind === 'compliance_finding' && e.facts.result === 'fail')

  return (
    <div className="stack">
      <Panel title="Investigate a resource">
        <form className="row" onSubmit={(e) => { e.preventDefault(); void runIt(resource) }}>
          <input aria-label="Resource ID" placeholder="Resource ID, e.g. aws_s3_bucket.billing_data_002" value={resource}
            onChange={(e) => setResource(e.target.value)} style={{ flex: 2 }} />
          <input aria-label="Question" placeholder="Question (optional)" value={question} onChange={(e) => setQuestion(e.target.value)} style={{ flex: 2 }} />
          <button className="primary" disabled={act.busy || !can(me, 'operate')}>{act.busy ? 'Collecting evidence…' : 'Investigate'}</button>
        </form>
        {!can(me, 'operate') && <p className="muted small">Investigations need the analyst role.</p>}
        <ErrorBox error={act.error} />
      </Panel>

      {inv && (
        <>
          <p className="notice">{inv.notice}</p>
          <div className="grid2">
            <Panel title="Brief (written by Aegis from the evidence)">
              <Claims claims={inv.brief.claims} onPick={pick} />
              {inv.brief.next_steps.length > 0 && (
                <>
                  <h3>Next steps</h3>
                  <Claims claims={inv.brief.next_steps} onPick={pick} />
                </>
              )}
              {failing.length > 0 && can(me, 'operate') && (
                <div className="row">
                  {failing.map((e) => (
                    <button key={e.id} onClick={() => go('remediation', { propose: '1', rule: String(e.facts.rule_id), resource: inv.resource_id })}>
                      Propose fix for {String(e.facts.rule_id)}
                    </button>
                  ))}
                </div>
              )}
            </Panel>
            <Panel title="Model explanation (optional)">
              <p><Badge value={inv.model.status} /> {inv.model.model && <span className="muted small">{inv.model.model}</span>}</p>
              {inv.model.status === 'not_configured' && (
                <p className="muted small">No local model is configured. The brief is complete without one.</p>
              )}
              {inv.model.accepted.length > 0 && (
                <>
                  <p className="muted small">Accepted claims cite evidence and contain only numbers and identifiers found in it. Meaning is not checked: read them as a draft.</p>
                  <Claims claims={inv.model.accepted} onPick={pick} />
                </>
              )}
              {inv.model.rejected.length > 0 && (
                <details>
                  <summary>{inv.model.rejected.length} rejected claims</summary>
                  <ul className="claims rejected">
                    {inv.model.rejected.map((r, i) => <li key={i}>{r.claim.text} <span className="small muted">({r.reasons.join(', ')})</span></li>)}
                  </ul>
                </details>
              )}
              {inv.model.error && <p className="error">{inv.model.error}</p>}
            </Panel>
          </div>
          <Panel title={`Evidence (${inv.evidence.length} items)`}>
            <p className="muted small">Read in one read-only transaction at {when(inv.created_at)} · SHA-256 <code>{inv.evidence_sha256.slice(0, 16)}…</code></p>
            <ol className="evidence">
              {inv.evidence.map((e) => (
                <li key={e.id} id={`ev-${e.id}`} className={focus === e.id ? 'focus' : ''}>
                  <span className="cite static">{e.id}</span> <Badge value={e.kind.replace('_', ' ')} /> {e.summary}
                  <div className="small muted mono">{e.source}</div>
                </li>
              ))}
            </ol>
          </Panel>
        </>
      )}
    </div>
  )
}
