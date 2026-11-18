import { useEffect, useRef, useState } from 'react'
import { Bot, FileSearch, ScanSearch, Sparkles, Wrench } from 'lucide-react'
import { can, type PageProps } from '../nav'
import type { Claim, Investigation } from '../types'
import { Button, Callout, Card, ErrorState, Field, Input, Mono, SectionTitle, Skeleton, StatusBadge } from '@/components/ui'
import { cn } from '@/lib/utils'
import { useAction, when } from '../hooks'

/** A citation chip: moves focus to the cited evidence item (adapted from SmoothUI's AI Citation pattern). */
function Cite({ id, onPick }: { id: string; onPick: (id: string) => void }) {
  return (
    <button type="button" className="cite ml-1 inline-flex h-[18px] items-center rounded border border-accent/30 bg-accent-soft px-1 align-[1px] font-mono text-[10.5px] font-semibold text-accent hover:bg-accent/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      onClick={() => onPick(id)} aria-label={`Evidence ${id}`} title="Show the evidence">{id}</button>
  )
}

function Claims({ claims, onPick, muted }: { claims: Claim[]; onPick: (id: string) => void; muted?: boolean }) {
  return (
    <ul className={cn('claims m-0 list-none space-y-2 p-0 text-[13.5px] leading-6', muted && 'text-fg-muted')}>
      {claims.map((c, i) => (
        <li key={i} className="relative pl-4 before:absolute before:left-0 before:top-[11px] before:size-1.5 before:rounded-full before:bg-border-strong">
          {c.text}{c.citations.map((id) => <Cite key={id} id={id} onPick={onPick} />)}
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
  const started = useRef<string | null>(null)

  const runIt = async (rid: string) => {
    if (!rid) return
    const r = await act.run(() => api<Investigation>('POST', '/api/v1/investigations', { resource_id: rid, question }))
    if (r) setInv(r)
  }
  // Only an explicit "Investigate" click (run=1) starts an investigation. The
  // marker is consumed at once with location.replace (no history entry, and
  // the app sees the new URL), so Back, reload or a bookmark shows the form
  // instead of storing a duplicate. The ref stops StrictMode's second effect
  // run from posting twice.
  const runParam = params.get('run')
  const resourceParam = params.get('resource')
  useEffect(() => {
    if (runParam !== '1') {
      started.current = null
      return
    }
    if (started.current === resourceParam) return
    started.current = resourceParam
    window.location.replace(`#/investigate?resource=${encodeURIComponent(resourceParam ?? '')}`)
    if (resourceParam) {
      void Promise.resolve().then(() => {
        setResource(resourceParam)
        if (can(me, 'operate')) void runIt(resourceParam)
      })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resourceParam, runParam])

  const pick = (id: string) => {
    setFocus(id)
    const el = document.getElementById(`ev-${id}`)
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    el?.focus({ preventScroll: true })
  }
  const failing = (inv?.evidence ?? []).filter((e) => e.kind === 'compliance_finding' && e.facts.result === 'fail')

  return (
    <div className="space-y-5">
      <Card title="Investigate a resource" icon={<ScanSearch />}
        description="Aegis collects every fact it holds about the resource in one read-only transaction and writes a brief that cites each fact.">
        <form className="flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); void runIt(resource) }}>
          <Field label="Resource ID" className="min-w-[260px] flex-[2]">
            {(p) => <Input {...p} aria-label="Resource ID" placeholder="e.g. aws_s3_bucket.billing_data_002" value={resource} onChange={(e) => setResource(e.target.value)} />}
          </Field>
          <Field label="Question (optional)" className="min-w-[200px] flex-[2]">
            {(p) => <Input {...p} aria-label="Question" placeholder="Why is this risky?" value={question} onChange={(e) => setQuestion(e.target.value)} />}
          </Field>
          <Button type="submit" variant="primary" loading={act.busy} disabled={!can(me, 'operate')}><FileSearch />{act.busy ? 'Collecting evidence…' : 'Investigate'}</Button>
        </form>
        {!can(me, 'operate') && <p className="mb-0 mt-2 text-xs text-fg-subtle">Investigations need the analyst role.</p>}
        <ErrorState error={act.error} className="mt-3" />
      </Card>

      {act.busy && !inv && <Card><Skeleton rows={6} /></Card>}

      {inv && (
        <>
          <Callout tone="info">{inv.notice}</Callout>
          <div className="grid gap-5 xl:grid-cols-[1fr_1fr]">
            <div className="space-y-5">
              <Card title="Brief" icon={<Sparkles />} description="Written by Aegis from the evidence. Every sentence cites its source."
                actions={failing.length > 0 && can(me, 'operate') && <StatusBadge value="fail" label={`${failing.length} failing rule${failing.length > 1 ? 's' : ''}`} />}>
                <Claims claims={inv.brief.claims} onPick={pick} />
                {inv.brief.next_steps.length > 0 && (
                  <>
                    <SectionTitle>Next steps</SectionTitle>
                    <Claims claims={inv.brief.next_steps} onPick={pick} />
                  </>
                )}
                {failing.length > 0 && can(me, 'operate') && (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {failing.map((e) => (
                      <Button key={e.id} variant="primary" onClick={() => go('remediation', { propose: '1', rule: String(e.facts.rule_id), resource: inv.resource_id })}>
                        <Wrench />Propose fix for {String(e.facts.rule_id)}
                      </Button>
                    ))}
                  </div>
                )}
              </Card>

              <Card title="Model explanation" icon={<Bot />} description="Optional, from the local model. A draft: read it against the evidence."
                actions={<StatusBadge value={inv.model.status} />}>
                {inv.model.model && <p className="mb-2 mt-0 text-xs text-fg-subtle">Model <code className="font-mono">{inv.model.model}</code></p>}
                {inv.model.status === 'not_configured' && <p className="m-0 text-[13px] text-fg-muted">No local model is configured. The brief is complete without one.</p>}
                {inv.model.accepted.length > 0 && (
                  <details className="group">
                    <summary className="cursor-pointer select-none text-[13px] text-fg-muted hover:text-fg">Show {inv.model.accepted.length} accepted claims</summary>
                    <p className="mb-2 mt-2 text-xs text-fg-subtle">Accepted claims cite evidence and contain only numbers and identifiers found in it. Meaning is not checked.</p>
                    <Claims claims={inv.model.accepted} onPick={pick} muted />
                  </details>
                )}
                {inv.model.rejected.length > 0 && (
                  <details className="mt-2">
                    <summary className="cursor-pointer select-none text-[13px] text-fg-muted hover:text-fg">{inv.model.rejected.length} rejected claims</summary>
                    <ul className="claims rejected m-0 mt-2 list-none space-y-1.5 p-0 text-[13px] text-fg-subtle">
                      {inv.model.rejected.map((r, i) => <li key={i} className="line-through decoration-fg-subtle/40">{r.claim.text} <span className="no-underline">({r.reasons.join(', ')})</span></li>)}
                    </ul>
                  </details>
                )}
                {inv.model.error && <Callout tone="danger" className="mt-3">{inv.model.error}</Callout>}
              </Card>
            </div>

            <Card title={`Evidence (${inv.evidence.length} items)`} icon={<FileSearch />}
              description={<>Read at {when(inv.created_at)} · SHA-256 <Mono value={inv.evidence_sha256} max={20} /></>}>
              <ol className="evidence m-0 list-none space-y-1.5 p-0">
                {inv.evidence.map((e) => (
                  <li key={e.id} id={`ev-${e.id}`} tabIndex={-1}
                    className={cn('rounded-md border px-3 py-2 text-[13px] outline-none transition-colors',
                      focus === e.id ? 'focus border-accent/60 bg-accent-soft' : 'border-border bg-surface-2/50')}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[11px] font-semibold text-accent">{e.id}</span>
                      <StatusBadge value={e.kind} icon={false} label={e.kind.replace(/_/g, ' ')} />
                    </div>
                    <div className="mt-1">{e.summary}</div>
                    <div className="mt-0.5 truncate font-mono text-[11.5px] text-fg-subtle" title={e.source}>{e.source}</div>
                  </li>
                ))}
              </ol>
            </Card>
          </div>
        </>
      )}
    </div>
  )
}
