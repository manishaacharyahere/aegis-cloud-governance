import { useState } from 'react'
import { GitCompareArrows, ShieldCheck } from 'lucide-react'
import { can, patchParams, type PageProps } from '../nav'
import type { Account, DriftBaseline, DriftReport, Paged } from '../types'
import {
  BackLink, Button, Callout, Card, ConfirmAction, DataTable, DiffList, EmptyState, ErrorState, Input, Mono, Pager, Select,
  Skeleton, StatCard, StatGrid, StatusBadge, Timeline, useToast,
} from '@/components/ui'
import { ago, useAction, useLoad, usePaged, when } from '../hooks'

const CATEGORIES = ['security', 'deleted', 'unmanaged', 'cost', 'configuration', 'tagging']
const SEVERITIES = ['critical', 'high', 'medium', 'low']

export default function Drift(props: PageProps) {
  const id = props.params.get('id')
  return id ? <ReportView {...props} id={id} /> : <DriftHome {...props} />
}

function fmtCounts(c: Record<string, number> | undefined, order: string[]): string {
  if (!c) return '—'
  return order.filter((k) => c[k]).map((k) => `${c[k]} ${k}`).join(', ') || 'none'
}

function DriftHome({ api, me, go }: PageProps) {
  const accounts = useLoad(() => api<{ items: Account[] }>('GET', '/api/v1/accounts'), [api])
  const baselines = useLoad(() => api<{ items: DriftBaseline[] }>('GET', '/api/v1/drift/baselines'), [api])
  const reports = usePaged((after) => api<Paged<DriftReport>>('GET', `/api/v1/drift/reports?limit=20${after ? '&after=' + encodeURIComponent(after) : ''}`), [api])
  const act = useAction()
  const toast = useToast()
  const [note, setNote] = useState('')
  const [chosen, setChosen] = useState('')
  const acctList = accounts.data?.items ?? []
  const account = chosen || acctList[0]?.id || ''
  const mine = (baselines.data?.items ?? []).filter((b) => b.account_id === account)
  const active = mine.find((b) => b.status === 'active')
  const name = (id: string) => acctList.find((a) => a.id === id)?.name ?? id.slice(0, 8)

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-[3fr_2fr]">
        <Card title="Approved baseline" icon={<ShieldCheck />}
          description="An approved copy of an account's inventory. Drift is any later difference, with the rules that newly fail or now pass."
          actions={acctList.length > 1 && (
            <Select aria-label="Cloud account" value={account} onChange={(e) => setChosen(e.target.value)}>
              {acctList.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.external_id}, {a.resource_count} resources)</option>)}
            </Select>
          )}>
          {(baselines.loading && !baselines.data) || (accounts.loading && !accounts.data) ? <Skeleton rows={2} /> : acctList.length === 0 ? (
            <EmptyState icon={<GitCompareArrows />} title="No inventory yet" action={<Button size="sm" onClick={() => go('inventory')}>Import a snapshot</Button>} />
          ) : active ? (
            <div className="flex flex-wrap items-center gap-2 text-[13.5px]">
              <StatusBadge value="active" /> <b className="tabular-nums">{active.resource_count}</b> resources in <b>{name(account)}</b>, approved by <b>{active.approved_by}</b>
              <span className="text-fg-subtle" title={when(active.created_at)}>{ago(active.created_at)}</span>
              {active.note && <span className="w-full text-[13px] text-fg-muted">“{active.note}”</span>}
            </div>
          ) : <Callout tone="info" title={`No baseline for ${name(account)} yet`}>Approve its latest import to start detecting drift.</Callout>}
          <ErrorState error={accounts.error ?? baselines.error ?? act.error} className="mt-3" />
          {acctList.length > 0 && (can(me, 'approve') || can(me, 'operate')) && (
            <div className="mt-4 flex flex-wrap items-center gap-2">
              {can(me, 'approve') && (
                <>
                  <Input aria-label="Baseline note" placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} className="max-w-[260px]" />
                  <ConfirmAction tone="primary" variant="secondary" label="Approve latest import" title={`Make the latest import of ${name(account)} the baseline?`}
                    description="Later imports are compared against it. The approval is recorded in the audit log." disabled={act.busy}
                    onConfirm={async () => {
                      const b = await act.run(() => api<DriftBaseline>('POST', '/api/v1/drift/baselines', { account_id: account, note }))
                      if (b) {
                        toast(`Baseline approved: ${b.resource_count} resources.`)
                        setNote('')
                        baselines.reload()
                      }
                    }} />
                </>
              )}
              {can(me, 'operate') && (
                <Button variant="primary" loading={act.busy} disabled={!active} onClick={async () => {
                  const r = await act.run(() => api<DriftReport>('POST', '/api/v1/drift/compare', { account_id: account }))
                  if (r) {
                    toast(`Drift check done: ${r.counts.total ?? r.items.length} differences.`)
                    go('drift', { id: r.id })
                  }
                }}><GitCompareArrows />Check for drift now</Button>
              )}
            </div>
          )}
        </Card>
        <Card title="Baseline history">
          <Timeline empty="None for this account." items={mine.slice(0, 6).map((b) => ({
            key: b.id, status: b.status, title: <span className="tabular-nums">{b.resource_count} resources</span>,
            meta: `${b.approved_by} · ${when(b.created_at)}`, body: b.note || undefined,
          }))} />
        </Card>
      </div>

      <Card title="Drift reports" description="Each check compares the latest import with the approved baseline.">
        <DataTable rows={reports.items} loading={reports.loading} error={reports.error} onRetry={reports.reload}
          getRowId={(r) => r.id} onRowOpen={(r) => go('drift', { id: r.id })} rowLabel={(r) => `Open drift report of ${when(r.created_at)}`}
          rowTone={(r) => ((r.counts.by_severity?.critical ?? 0) > 0 ? 'danger' : (r.counts.by_severity?.high ?? 0) > 0 ? 'high' : undefined)}
          empty={<EmptyState icon={<GitCompareArrows />} title="No drift checks yet">Approve a baseline, then run a check.</EmptyState>}
          columns={[
            { key: 'when', header: 'When', cell: (r) => <span title={when(r.created_at)}>{ago(r.created_at)}</span> },
            { key: 'acct', header: 'Account', cell: (r) => name(r.account_id) },
            { key: 'by', header: 'By', cell: (r) => <span className="text-fg-muted">{r.actor}</span>, hideOnMobile: true },
            { key: 'n', header: 'Differences', align: 'right', cell: (r) => r.counts.total ?? 0 },
            { key: 'sev', header: 'By severity', cell: (r) => <span className="text-fg-muted">{fmtCounts(r.counts.by_severity, SEVERITIES)}</span>, hideOnMobile: true },
            { key: 'cat', header: 'By category', cell: (r) => <span className="text-fg-muted">{fmtCounts(r.counts.by_category, CATEGORIES)}</span>, hideOnMobile: true },
          ]} />
        <Pager mode="more" hasNext={!!reports.next} onNext={reports.more} loading={reports.loading} />
      </Card>
    </div>
  )
}

function ReportView({ api, go, params, id }: PageProps & { id: string }) {
  const category = params.get('category') ?? ''
  const severity = params.get('min_severity') ?? ''
  const q = new URLSearchParams({ ...(category && { category }), ...(severity && { min_severity: severity }) })
  const rep = useLoad(() => api<DriftReport>('GET', `/api/v1/drift/reports/${id}?${q}`), [api, id, category, severity])
  const set = (k: string, v: string) => go('drift', patchParams(params, { [k]: v }))
  const r = rep.data

  return (
    <div className="space-y-5">
      <BackLink onClick={() => go('drift')}>All drift reports</BackLink>
      <ErrorState error={rep.error} onRetry={rep.reload} />
      {!r ? !rep.error && <Skeleton rows={6} /> : (
        <>
          <StatGrid>
            <StatCard label="differences" value={r.counts.total ?? 0} tone="auto" autoTone="warning" />
            {SEVERITIES.map((s) => (
              <StatCard key={s} label={s} value={r.counts.by_severity?.[s] ?? 0} tone="auto" autoTone={s === 'critical' ? 'danger' : s === 'high' ? 'high' : s === 'medium' ? 'warning' : 'info'} />
            ))}
          </StatGrid>
          <Card title={`Drift found ${ago(r.created_at)}`} description={`Checked by ${r.actor} · ${when(r.created_at)}`} actions={
            <>
              <Select aria-label="Category" value={category} onChange={(e) => set('category', e.target.value)}>
                <option value="">All categories</option>
                {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
              </Select>
              <Select aria-label="Minimum severity" value={severity} onChange={(e) => set('min_severity', e.target.value)}>
                <option value="">Any severity</option>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </Select>
            </>
          }>
            <DataTable rows={r.items} getRowId={(it) => it.resource_id + it.category}
              empty={<EmptyState icon={<ShieldCheck />} title="No drift matches these filters." />}
              rowTone={(it) => (it.severity === 'critical' ? 'danger' : it.severity === 'high' ? 'high' : undefined)}
              columns={[
                { key: 'res', header: 'Resource', cell: (it) => <><Mono value={it.resource_id} /><div className="text-xs text-fg-subtle">{it.resource_type}</div></> },
                { key: 'cat', header: 'Category', cell: (it) => it.category },
                { key: 'sev', header: 'Severity', cell: (it) => <StatusBadge value={it.severity} /> },
                { key: 'what', header: 'What changed', className: 'min-w-[320px]', cell: (it) => (
                  <div className="space-y-1.5">
                    {(it.changes?.length ?? 0) > 0 && <DiffList changes={it.changes!} max={4} />}
                    {(it.new_failures ?? []).length > 0 && <div className="text-[12.5px] text-danger">Now failing: {it.new_failures!.join(', ')}</div>}
                    {(it.resolved ?? []).length > 0 && <div className="text-[12.5px] text-success">Now passing: {it.resolved!.join(', ')}</div>}
                  </div>
                ) },
                { key: 'go', header: <span className="sr-only">Actions</span>, align: 'right', cell: (it) => <Button size="sm" variant="ghost" onClick={() => go('investigate', { resource: it.resource_id, run: '1' })}>Investigate</Button> },
              ]} />
          </Card>
        </>
      )}
    </div>
  )
}
