import { useState } from 'react'
import { FileCheck2, Play, ShieldCheck, ShieldOff } from 'lucide-react'
import { can, patchParams, type PageProps } from '../nav'
import type { ControlDetail, Coverage, ExceptionView, Framework, Paged } from '../types'
import {
  Button, Callout, Card, ConfirmAction, DataTable, EmptyState, ErrorState, Field, Input, Meter, Mono, Pager, Select,
  SectionTitle, Skeleton, StatusBadge, Textarea, useToast,
} from '@/components/ui'
import { ago, useAction, useDraft, useLoad, usePaged, when } from '../hooks'
import { qs, seg } from '../client'

export default function Compliance({ api, me, go, params }: PageProps) {
  const fw = useLoad(() => api<{ frameworks: Framework[]; catalog_version: string }>('GET', '/api/v1/compliance/frameworks'), [api])
  const framework = params.get('framework') || 'aegis-baseline-1'
  const control = params.get('control')
  const cov = useLoad(() => api<Coverage>('GET', `/api/v1/compliance/coverage${qs({ framework })}`), [api, framework])
  const act = useAction()
  const toast = useToast()
  const [exTick, setExTick] = useState(0)
  const controls = [...(cov.data?.controls ?? [])].sort((a, b) => b.fail - a.fail || a.control_id.localeCompare(b.control_id))
  const failing = controls.filter((c) => c.fail > 0).length

  return (
    <div className="space-y-5">
      <Card title="Control coverage" icon={<ShieldCheck />}
        description={cov.data ? `${controls.length - failing} of ${controls.length} controls without failing evidence. Sorted by failing count.` : undefined}
        actions={
          <>
            <Select aria-label="Framework" value={framework} onChange={(e) => go('compliance', { framework: e.target.value })}>
              {(fw.data?.frameworks ?? []).map((f) => <option key={f.id} value={f.id}>{f.name} {f.version}</option>)}
            </Select>
            {can(me, 'operate') && (
              <Button variant="primary" loading={act.busy} onClick={async () => {
                if (await act.attempt(() => api('POST', '/api/v1/compliance/evaluations', { source: 'inventory' }))) toast('Inventory evaluated against the policies.')
                cov.reload()
              }}><Play />Evaluate inventory now</Button>
            )}
          </>
        }>
        {cov.data && <Meter value={controls.length - failing} max={controls.length} tone={failing ? 'warning' : 'success'} label="Controls without failing evidence" />}
        {cov.data?.notice && <Callout tone="info" className="my-3">{cov.data.notice}</Callout>}
        <ErrorState error={act.error} className="mb-3" />
        <DataTable rows={controls} loading={cov.loading} error={cov.error} onRetry={cov.reload} getRowId={(c) => c.control_id}
          onRowOpen={(c) => go('compliance', patchParams(params, { control: c.control_id }))} rowLabel={(c) => `Show evidence for ${c.control_id}`}
          rowTone={(c) => (c.fail > 0 ? 'danger' : undefined)}
          columns={[
            { key: 'id', header: 'Control', cell: (c) => <span>{c.control_id}</span> },
            { key: 'title', header: 'Title', cell: (c) => <span className="text-fg-muted">{c.title}</span> },
            { key: 'status', header: 'Status', cell: (c) => <span className="flex flex-wrap gap-1"><StatusBadge value={c.status} />{c.stale && <StatusBadge value="stale" />}</span> },
            { key: 'pass', header: 'Pass', align: 'right', cell: (c) => c.pass },
            { key: 'fail', header: 'Fail', align: 'right', cell: (c) => <span className={c.fail ? 'font-semibold text-danger' : ''}>{c.fail}</span> },
            { key: 'exc', header: 'Excepted', align: 'right', cell: (c) => c.excepted, hideOnMobile: true },
            { key: 'when', header: 'Evaluated', align: 'right', cell: (c) => <span className="text-fg-subtle" title={when(c.last_evaluated_at)}>{c.last_evaluated_at ? ago(c.last_evaluated_at) : '—'}</span>, hideOnMobile: true },
          ]} />
      </Card>
      {control && <ControlPanel key={framework + control} {...{ api, me, go }} framework={framework} control={control} onException={() => setExTick((t) => t + 1)} />}
      <Exceptions api={api} me={me} tick={exTick} />
    </div>
  )
}

function ControlPanel({ api, me, go, framework, control, onException }: Pick<PageProps, 'api' | 'me' | 'go'> & { framework: string; control: string; onException: () => void }) {
  const d = useLoad(() => api<ControlDetail>('GET', `/api/v1/compliance/controls/${seg(framework)}/${seg(control)}`), [api, framework, control])
  const [req, setReq] = useState<{ rule: string; subject: string } | null>(null)
  const [shown, setShown] = useState(50)
  const fails = (d.data?.evaluations ?? []).filter((e) => e.result !== 'pass')
  return (
    <Card title={`Evidence: ${control}`} icon={<FileCheck2 />} description={d.data?.title}>
      <ErrorState error={d.error} onRetry={d.reload} />
      {!d.data ? !d.error && <Skeleton rows={4} /> : (
        <>
          <SectionTitle>Rules</SectionTitle>
          <DataTable rows={d.data.rules} getRowId={(r) => r.rule_id} dense
            columns={[
              { key: 'rule', header: 'Rule', cell: (r) => <><code className="font-mono text-[12px]">{r.rule_id}</code> <span className="text-fg-muted">{r.title}</span></> },
              { key: 'cov', header: 'Coverage', cell: (r) => r.coverage },
              { key: 'map', header: 'Mapping', cell: (r) => <StatusBadge value={r.review_status} /> },
              { key: 'fail', header: 'Fail', align: 'right', cell: (r) => r.fail },
            ]} />
          <SectionTitle>Findings ({fails.length})</SectionTitle>
          <DataTable rows={fails.slice(0, shown)} getRowId={(e) => e.rule_id + e.subject} empty="No failing evaluations."
            rowTone={(e) => (e.result === 'fail' ? 'danger' : undefined)}
            columns={[
              { key: 'res', header: 'Result', cell: (e) => <StatusBadge value={e.result} /> },
              { key: 'sub', header: 'Resource', cell: (e) => <Mono value={e.subject} /> },
              { key: 'rule', header: 'Rule', cell: (e) => <code className="font-mono text-[12px]">{e.rule_id}</code>, hideOnMobile: true },
              { key: 'msg', header: 'Message', cell: (e) => <><div className="text-fg-muted">{e.message}</div><div className="text-xs text-fg-subtle">snapshot v{String(e.evidence.version ?? '?')} · {String(e.evidence.content_sha256 ?? '').slice(0, 12)}</div></> },
              { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: (e) => (
                <div className="flex justify-end gap-1">
                  <Button size="sm" variant="ghost" onClick={() => go('investigate', { resource: e.subject, run: '1' })}>Investigate</Button>
                  {can(me, 'operate') && e.result === 'fail' && (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => go('remediation', { propose: '1', rule: e.rule_id, resource: e.subject })}>Fix</Button>
                      <Button size="sm" variant="ghost" onClick={() => setReq({ rule: e.rule_id, subject: e.subject })}>Exception</Button>
                    </>
                  )}
                </div>
              ) },
            ]} />
          <Pager mode="more" hasNext={fails.length > shown} onNext={() => setShown((n) => n + 100)} count={Math.min(shown, fails.length)} />
          {req && <RequestException api={api} rule={req.rule} subject={req.subject} onCancel={() => setReq(null)}
            onDone={() => { setReq(null); d.reload(); onException() }} />}
        </>
      )}
    </Card>
  )
}

function RequestException({ api, rule, subject, onDone, onCancel }: { api: PageProps['api']; rule: string; subject: string; onDone: () => void; onCancel: () => void }) {
  const [just, setJust, clearJust] = useDraft(`exception.${rule}.${subject}`, '')
  const [days, setDays] = useState('30')
  const act = useAction()
  const toast = useToast()
  const n = Number(days)
  const daysOk = Number.isInteger(n) && n >= 1 && n <= 365
  return (
    <form className="mt-4 space-y-3 rounded-md border border-border bg-surface-2 p-4" onSubmit={async (e) => {
      e.preventDefault()
      if (!daysOk) return
      const expires = new Date(Date.now() + n * 86400_000).toISOString()
      if (await act.attempt(() => api('POST', '/api/v1/compliance/exceptions', { rule_id: rule, subject, justification: just, expires_at: expires }))) {
        clearJust()
        toast('Exception requested. Someone else must approve it.')
        onDone()
      }
    }}>
      <h3 className="m-0 text-[14px] font-semibold">Request an exception for {rule} on <Mono value={subject} copy={false} /></h3>
      <Field label="Justification" hint="Why is this risk accepted, and what compensates for it? (20+ characters)" required>
        {(p) => <Textarea {...p} aria-label="Justification" minLength={20} value={just} onChange={(e) => setJust(e.target.value)} />}
      </Field>
      <Field label="Expires in (days)" error={!daysOk ? 'Between 1 and 365 days.' : undefined} className="max-w-[180px]">
        {(p) => <Input {...p} type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} />}
      </Field>
      <div className="flex gap-2">
        <Button type="submit" variant="primary" loading={act.busy} disabled={!daysOk}>Request</Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
      <ErrorState error={act.error} />
    </form>
  )
}

function Exceptions({ api, me, tick }: Pick<PageProps, 'api' | 'me'> & { tick: number }) {
  const ex = usePaged((after) => api<Paged<ExceptionView>>('GET', `/api/v1/compliance/exceptions${qs({ limit: 50, after })}`), [api, tick])
  const act = useAction()
  const toast = useToast()
  const decide = async (id: string, d: string) => {
    if (await act.attempt(() => api('POST', `/api/v1/compliance/exceptions/${seg(id)}/${d}`))) toast(`Exception ${d === 'approve' ? 'approved' : d === 'reject' ? 'rejected' : 'revoked'}.`)
    ex.reload()
  }
  return (
    <Card title="Exceptions" icon={<ShieldOff />} description="Accepted risks, each with a justification, an approver and an expiry.">
      <ErrorState error={act.error} className="mb-3" />
      <DataTable rows={ex.items} loading={ex.loading} error={ex.error} onRetry={ex.reload} getRowId={(x) => x.id}
        empty={<EmptyState icon={<ShieldOff />} title="No exceptions">Request one from a failing finding above.</EmptyState>}
        columns={[
          { key: 'status', header: 'Status', cell: (x) => <StatusBadge value={x.status} /> },
          { key: 'rule', header: 'Rule', cell: (x) => <code className="font-mono text-[12px]">{x.rule_id}</code> },
          { key: 'sub', header: 'Resource', cell: (x) => <Mono value={x.subject} /> },
          { key: 'why', header: 'Justification', className: 'min-w-[240px]', cell: (x) => <><div className="text-fg-muted">{x.justification}</div><div className="text-xs text-fg-subtle">requested by {x.requested_by}{x.decided_by && `, decided by ${x.decided_by}`} · expires {when(x.expires_at)}</div></> },
          { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: (x) => (
            <div className="flex justify-end gap-1.5">
              {can(me, 'approve') && x.status === 'requested' && x.requested_by !== me.subject && (
                <>
                  <Button size="sm" variant="primary" disabled={act.busy} onClick={() => decide(x.id, 'approve')}>Approve</Button>
                  <ConfirmAction size="sm" label="Reject" title="Reject this exception?" description="The finding keeps failing." onConfirm={() => decide(x.id, 'reject')} />
                </>
              )}
              {can(me, 'approve') && x.status === 'approved' && (
                <ConfirmAction size="sm" label="Revoke" title="Revoke this exception?" description="The rule fails again from the next evaluation." onConfirm={() => decide(x.id, 'revoke')} />
              )}
            </div>
          ) },
        ]} />
      <Pager mode="more" hasNext={!!ex.next} onNext={ex.more} loading={ex.loading} count={ex.items.length} />
    </Card>
  )
}
