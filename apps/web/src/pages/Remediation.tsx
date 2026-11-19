import { useState } from 'react'
import { CheckCircle2, FileSignature, GitPullRequestArrow, ShieldCheck, Wrench } from 'lucide-react'
import { can, patchParams, type PageProps } from '../nav'
import type { Paged, Remediation as Rem, RequestBody, Template } from '../types'
import {
  BackLink, Button, Callout, Card, ConfirmAction, CopyButton, DataTable, DiffList, EmptyState, ErrorState, Field, Input, KeyValue,
  Mono, Pager, RadioGroup, SectionTitle, Select, Skeleton, StatusBadge, Textarea, Timeline, useToast,
} from '@/components/ui'
import { ago, useAction, useDraft, useLoad, usePaged, when } from '../hooks'
import { qs, seg } from '../client'

const STATUSES = ['pending_approval', 'approved', 'released', 'verified', 'verification_failed', 'blocked', 'rejected', 'stale']

export default function Remediation({ api, me, go, params }: PageProps) {
  const id = params.get('id')
  if (id) return <Detail {...{ api, me, go }} id={id} />
  return (
    <div className="space-y-5">
      {can(me, 'operate') && <Propose {...{ api, go, params }} />}
      <List {...{ api, go, params }} />
    </div>
  )
}

function List({ api, go, params }: Pick<PageProps, 'api' | 'go' | 'params'>) {
  const status = params.get('status') ?? ''
  const list = usePaged((after) => api<Paged<Rem>>('GET', `/api/v1/remediations${qs({ limit: 50, status, after })}`), [api, status])
  return (
    <Card title="Remediations" icon={<GitPullRequestArrow />} actions={
      <Select aria-label="Status" value={status} onChange={(e) => go('remediation', patchParams(params, { status: e.target.value }))}>
        <option value="">All</option>
        {STATUSES.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
      </Select>
    }>
      <DataTable rows={list.items} loading={list.loading} error={list.error} onRetry={list.reload} getRowId={(r) => r.id}
        onRowOpen={(r) => go('remediation', { id: r.id })} rowLabel={(r) => `Open ${r.rule_id || 'manual change'} on ${r.resource_id}`}
        rowTone={(r) => (r.status === 'pending_approval' ? 'warning' : r.status === 'blocked' || r.status === 'verification_failed' ? 'danger' : undefined)}
        empty={<EmptyState icon={<Wrench />} title="No remediations">Propose one from a failing finding.</EmptyState>}
        columns={[
          { key: 'res', header: 'Resource', cell: (r) => <span className="font-mono text-[12.5px]">{r.resource_id}</span> },
          { key: 'status', header: 'Status', cell: (r) => <StatusBadge value={r.status} /> },
          { key: 'rule', header: 'Rule', cell: (r) => <code className="font-mono text-[12px]">{r.rule_id || 'manual'}</code> },
          { key: 'by', header: 'Requested', align: 'right', cell: (r) => <span className="text-fg-subtle" title={when(r.created_at)}>{r.requested_by} · {ago(r.created_at)}</span>, hideOnMobile: true },
        ]} />
      <Pager mode="more" hasNext={!!list.next} onNext={list.more} loading={list.loading} count={list.items.length} />
    </Card>
  )
}

function Propose({ api, go, params }: Pick<PageProps, 'api' | 'go' | 'params'>) {
  const tpl = useLoad(() => api<{ items: Template[] }>('GET', '/api/v1/remediation/templates'), [api])
  const [source, setSource] = useState<'finding' | 'manual'>('finding')
  const [rule, setRule] = useState(params.get('rule') ?? '')
  const [resource, setResource] = useState(params.get('resource') ?? '')
  const draftKey = `${source}.${rule}.${resource}`
  const [ops, setOps, clearOps] = useDraft(`remediation.ops.${resource}`, '[{"op": "set", "path": "tags.owner", "value": "platform-team"}]')
  const [just, setJust, clearJust] = useDraft(`remediation.justification.${draftKey}`, '')
  const act = useAction()
  const templates = tpl.data?.items ?? []
  const effectiveRule = rule || templates[0]?.rule_id || ''
  const t = templates.find((x) => x.rule_id === effectiveRule)
  const unknownRule = !!rule && !!tpl.data && !t

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
    const body: RequestBody<'ProposeRequest'> = source === 'finding'
      ? { source, rule_id: effectiveRule, resource_id: resource, justification: just }
      : { source, resource_id: resource, operations: operations as RequestBody<'ProposeRequest'>['operations'], justification: just }
    const r = await act.run(() => api<Rem>('POST', '/api/v1/remediations', body))
    if (r) {
      clearOps()
      clearJust()
      go('remediation', { id: r.id })
    }
  }
  return (
    <Card title="Propose a remediation" icon={<Wrench />}
      description="Aegis simulates the change with the same policies used for compliance. A plan that breaks another rule, or does not fix the target, is blocked. Approved plans are released as a change set for your pipeline; Aegis never changes the cloud itself.">
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); void submit() }}>
        <RadioGroup legend="Kind of change" name="remediation-source" value={source} onChange={setSource}
          options={[{ value: 'finding', label: 'Fix a failing rule (template)' }, { value: 'manual', label: 'Manual change' }]} />
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="Resource ID" required>
            {(p) => <Input {...p} aria-label="Resource ID" placeholder="aws_s3_bucket.billing_data_002" value={resource} onChange={(e) => setResource(e.target.value)} />}
          </Field>
          {source === 'finding' && (
            <Field label="Rule" error={unknownRule ? `${rule} has no remediation template; choose another rule or a manual change.` : undefined}>
              {(p) => (
                <Select {...p} aria-label="Rule" className="w-full" value={unknownRule ? rule : effectiveRule} onChange={(e) => setRule(e.target.value)}>
                  {unknownRule && <option value={rule} disabled>{rule} (no template)</option>}
                  {templates.map((x) => <option key={x.rule_id} value={x.rule_id}>{x.rule_id}: {x.title}</option>)}
                </Select>
              )}
            </Field>
          )}
        </div>
        {source === 'finding' && t && (
          <Callout tone={t.disruptive ? 'warning' : 'info'} title={t.disruptive ? 'Disruptive change' : undefined}>{t.note}</Callout>
        )}
        {source === 'manual' && (
          <Field label="Operations (JSON)" hint='e.g. [{"op": "set", "path": "tags.owner", "value": "platform-team"}]'>
            {(p) => <Textarea {...p} aria-label="Operations" className="font-mono" rows={4} value={ops} onChange={(e) => setOps(e.target.value)} />}
          </Field>
        )}
        <Field label="Justification" hint="Why this change, and why now? (10+ characters)" required>
          {(p) => <Textarea {...p} aria-label="Justification" minLength={10} value={just} onChange={(e) => setJust(e.target.value)} />}
        </Field>
        <Button type="submit" variant="primary" loading={act.busy} disabled={source === 'finding' && unknownRule}>{act.busy ? 'Simulating…' : 'Simulate and propose'}</Button>
        <ErrorState error={act.error} />
      </form>
    </Card>
  )
}

function Detail({ api, me, go, id }: Pick<PageProps, 'api' | 'me' | 'go'> & { id: string }) {
  const r = useLoad(() => api<Rem>('GET', `/api/v1/remediations/${seg(id)}`), [api, id])
  const act = useAction()
  const toast = useToast()
  const [comment, setComment] = useState('')
  const step = async (s: string) => {
    const body = s === 'approve' || s === 'reject' ? { comment } : undefined
    const out = await act.run(() => api<Rem>('POST', `/api/v1/remediations/${seg(id)}/${s}`, body))
    if (out) {
      toast(({ approve: 'Approved.', reject: 'Rejected.', release: 'Change set released.', verify: 'Verification recorded.' } as Record<string, string>)[s] ?? 'Done.')
      setComment('')
      r.reload()
    }
  }
  const x = r.data
  if (!x) {
    return (
      <div className="space-y-5">
        <BackLink onClick={() => go('remediation')}>All remediations</BackLink>
        {r.error ? <ErrorState error={r.error} onRetry={r.reload} /> : <Card><Skeleton rows={6} /></Card>}
      </div>
    )
  }
  const sim = x.simulation
  const approvals = x.approvals.filter((a) => a.decision === 'approve').length
  const mine = x.requested_by === me.subject
  const decided = x.approvals.some((a) => a.actor === me.subject)
  // A neighbour linked both ways is one connected resource, not two.
  const impact = [...new Set([...sim.impact.incoming, ...sim.impact.outgoing])]

  return (
    <div className="space-y-5">
      <BackLink onClick={() => go('remediation')}>All remediations</BackLink>
      <Card title={`${x.rule_id || 'Manual change'} on ${x.resource_id}`} actions={<StatusBadge value={x.status} />} description={x.justification}>
        <KeyValue items={[
          { label: 'Requested by', value: <>{x.requested_by} · {when(x.created_at)}</> },
          { label: 'Environment', value: sim.environment || '—' },
          { label: 'Plan', value: <Mono value={x.plan_sha256} max={20} /> },
        ]} />
        {x.status === 'stale' && (
          <Callout tone="warning" className="mt-3" title="This plan is stale">
            {x.stale_reason || 'The resource or the policies changed'}. Propose it again to simulate against the current state.
          </Callout>
        )}
        <div className="mt-5 grid gap-6 lg:grid-cols-[3fr_2fr]">
          <div>
            <SectionTitle>Simulation (OPA, before → after)</SectionTitle>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <StatusBadge value={sim.passed ? 'passed' : 'blocked'} />
              {sim.blocked_reasons.length > 0 && <span className="text-[13px] text-danger">{sim.blocked_reasons.join('; ')}</span>}
            </div>
            <KeyValue className="mb-3" items={[
              { label: 'Resolved', value: sim.resolved.join(', ') || 'none' },
              { label: 'Introduced', value: sim.introduced.join(', ') || 'none' },
              { label: 'Still failing', value: sim.failing_after.join(', ') || 'none' },
            ]} />
            <DiffList changes={sim.diff} />
          </div>
          <div>
            <SectionTitle>Reviewer notes</SectionTitle>
            <ul className="m-0 list-disc space-y-1 pl-4 text-[13px] text-fg-muted">{sim.notes.map((n) => <li key={n}>{n}</li>)}</ul>
            <SectionTitle>Impact ({impact.length} connected resources)</SectionTitle>
            <ul className="m-0 list-none space-y-1 p-0 font-mono text-[12px] text-fg-muted">{impact.slice(0, 15).map((i) => <li key={i} className="truncate">{i}</li>)}</ul>
          </div>
        </div>
      </Card>

      <Card title={`Approvals (${approvals} of ${x.required_approvals} required)`} icon={<ShieldCheck />}>
        <Timeline empty="No decisions yet." items={x.approvals.map((a) => ({
          key: a.actor, status: a.decision === 'approve' ? 'approved' : 'rejected', title: <b>{a.actor}</b>,
          meta: when(a.created_at), body: a.comment ? `“${a.comment}”` : undefined,
        }))} />
        <div className="mt-4 space-y-3">
          {/* The requester learns why they cannot approve, whatever their role. */}
          {x.status === 'pending_approval' && mine && <Callout tone="info">You requested this change, so someone else must approve it.</Callout>}
          {x.status === 'pending_approval' && !mine && can(me, 'approve') && (
            decided ? <p className="m-0 text-[13px] text-fg-muted">You have already decided.</p>
                : (
                  <div className="flex flex-wrap items-end gap-2">
                    <Field label="Comment (optional)" className="min-w-[240px] flex-1">
                      {(p) => <Input {...p} aria-label="Comment" value={comment} onChange={(e) => setComment(e.target.value)} />}
                    </Field>
                    <Button variant="primary" loading={act.busy} onClick={() => step('approve')}><CheckCircle2 />Approve</Button>
                    <ConfirmAction label="Reject" title="Reject this change?" description="A rejected remediation cannot be reopened; propose a new one instead." disabled={act.busy} onConfirm={() => step('reject')} />
                  </div>
                )
          )}
          {x.status === 'approved' && can(me, 'approve') && (
            <ConfirmAction tone="primary" label="Release change set" title="Release the signed change set?" icon={<FileSignature />}
              description="The change set is signed and handed to your pipeline. Aegis itself never changes cloud resources." disabled={act.busy} onConfirm={() => step('release')} />
          )}
          {(x.status === 'released' || x.status === 'verification_failed') && !can(me, 'operate') && (
            <p className="m-0 text-[13px] text-fg-muted">Verification needs the analyst role.</p>
          )}
          {(x.status === 'released' || x.status === 'verification_failed') && can(me, 'operate') && (
            <>
              <p className="m-0 text-[13px] text-fg-muted">
                Plan pinned to inventory version {x.resource_version}; the latest import shows version {x.observed_version ?? '?'}
                {x.observed_updated_at && <> (updated {ago(x.observed_updated_at)})</>}.
                {x.observed_version === x.resource_version && ' Import the inventory again after the change is applied, then verify.'}
              </p>
              <Button loading={act.busy} onClick={() => step('verify')}>Verify against latest inventory</Button>
            </>
          )}
          <ErrorState error={act.error} />
        </div>
      </Card>

      {x.change_set && (
        <Card title="Change set" icon={<FileSignature />} description={x.change_set.instructions}>
          {x.change_set.signed ? (
            <Callout tone="success" className="ok-text mb-3" title={`Signed (Ed25519, key ${x.change_set.signed.key_id})`}>
              Verify it before applying: <code className="font-mono">go run ./cmd/aegis-verify -key &lt;public key&gt; remediation.json</code>. The public key is at <code className="font-mono">/api/v1/signing-key</code>.
            </Callout>
          ) : <Callout tone="warning" className="mb-3">This change set is not signed (no signing key configured).</Callout>}
          <div className="relative">
            <div className="absolute right-2 top-2"><CopyButton value={JSON.stringify(x.change_set.operations, null, 2)} label="Copy operations" /></div>
            <pre className="m-0 max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] leading-5">{JSON.stringify(x.change_set.operations, null, 2)}</pre>
          </div>
        </Card>
      )}
      {x.verification && (
        <Card title="Verification" actions={<StatusBadge value={x.verification.verified ? 'verified' : 'verification_failed'} />}>
          <KeyValue items={[
            { label: 'Approved values present', value: String(x.verification.config_matches) },
            { label: 'Target rule passes', value: String(x.verification.target_resolved) },
            ...(x.verification.mismatched_paths.length ? [{ label: 'Mismatched', value: x.verification.mismatched_paths.join(', ') }] : []),
            ...(x.verification.unexpected_failures.length ? [{ label: 'Unexpected failures', value: x.verification.unexpected_failures.join(', ') }] : []),
          ]} />
        </Card>
      )}
    </div>
  )
}
