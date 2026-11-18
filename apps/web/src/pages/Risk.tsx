import { useState } from 'react'
import { ChevronRight, Globe2, Play, Radar, Route } from 'lucide-react'
import { ApiError } from '../client'
import { can, patchParams, type PageProps } from '../nav'
import type { Assessment, AttackPath, RiskRun } from '../types'
import { Button, Card, DataTable, EmptyState, ErrorState, Mono, Segmented, Skeleton, StatCard, StatGrid, StatusBadge, useToast } from '@/components/ui'
import { cn } from '@/lib/utils'
import { toneSolid, toneOf } from '@/lib/tones'
import { ago, useAction, useLoad, when } from '../hooks'

type Band = 'critical' | 'high' | 'medium' | 'low'

export default function Risk({ api, me, go, params }: PageProps) {
  const band = (params.get('band') as Band) || 'high'
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
  const toast = useToast()
  const [allPaths, setAllPaths] = useState(false)
  const pathItems = paths.data?.items ?? []

  const assess = async () => {
    const r = await act.run(() => api<RiskRun>('POST', '/api/v1/risk/assessments', {}))
    if (r) toast(`Scored ${r.summary.findings} findings.`)
    run.reload()
    paths.reload()
  }
  const s = run.data?.summary

  return (
    <div className="space-y-5">
      <Card title="Contextual risk" icon={<Radar />}
        description="Each failing finding is scored 0–100 from six explainable factors: rule severity, internet exposure, privilege, criticality, data sensitivity and age."
        actions={can(me, 'operate') && <Button variant="primary" loading={act.busy} onClick={assess}><Play />Run assessment</Button>}>
        <ErrorState error={act.error ?? run.error} onRetry={run.reload} className="mb-3" />
        {run.loading && !run.data ? <Skeleton rows={2} /> : run.data === null ? (
          <EmptyState icon={<Radar />} title="No assessment yet" action={can(me, 'operate') ? undefined : <Button size="sm" onClick={() => go('compliance')}>Compliance</Button>}>
            Evaluate compliance first, then run an assessment.
          </EmptyState>
        ) : s && (
          <>
            <StatGrid>
              <StatCard label="Findings scored" value={s.findings} />
              <StatCard label="Critical" value={s.by_band.critical ?? 0} tone="auto" autoTone="danger" />
              <StatCard label="High" value={s.by_band.high ?? 0} tone="auto" autoTone="high" />
              <StatCard label="Medium" value={s.by_band.medium ?? 0} tone="auto" autoTone="warning" />
              <StatCard label="Sensitive targets reachable from the internet" icon={<Globe2 />} value={s.internet_reachable_sensitive_targets} tone="auto" autoTone="danger" />
            </StatGrid>
            {run.data && <p className="mb-0 mt-3 text-xs text-fg-subtle">Assessment of {when(run.data.created_at)} ({ago(run.data.created_at)}).</p>}
          </>
        )}
      </Card>

      <Card title="Attack paths to sensitive data" icon={<Route />} description="Chains from the internet to sensitive data stores, most sensitive first.">
        <DataTable rows={paths.data ? (allPaths ? pathItems : pathItems.slice(0, 5)) : undefined} loading={paths.loading} error={paths.error} onRetry={paths.reload} getRowId={(p) => p.target}
          rowTone={(p) => (p.sensitivity >= 80 ? 'danger' : p.sensitivity >= 50 ? 'high' : undefined)}
          empty={<EmptyState icon={<Route />} title="No internet-reachable sensitive targets." />}
          columns={[
            { key: 'sens', header: 'Sensitivity', align: 'right', cell: (p) => p.sensitivity },
            { key: 'target', header: 'Target', cell: (p) => <><Mono value={p.target} /><div className="text-xs text-fg-subtle">{p.target_type}</div></> },
            { key: 'path', header: 'Path', className: 'min-w-[280px]', cell: (p) => <PathTrail hops={['internet', ...p.hops.map((h) => h.to)]} reasons={p.hops.map((h) => h.reason)} /> },
          ]} />
        {pathItems.length > 5 && (
          <Button size="sm" variant="ghost" className="mt-2" onClick={() => setAllPaths(!allPaths)}>
            {allPaths ? 'Show the top 5' : `Show all ${pathItems.length} paths`}
          </Button>
        )}
      </Card>

      <Card title="Findings by risk" actions={
        <Segmented label="Minimum band" value={band} onChange={(v) => go('risk', patchParams(params, { band: v === 'high' ? '' : v }))}
          options={[{ value: 'critical', label: 'Critical' }, { value: 'high', label: 'High+' }, { value: 'medium', label: 'Medium+' }, { value: 'low', label: 'All' }]} />
      }>
        {run.data && run.data.assessments.length === 0 ? <EmptyState title="No findings in this band." /> : (
          <ul className="m-0 -mx-5 list-none divide-y divide-border/60 p-0">
            {(run.data?.assessments ?? []).map((a) => <FindingRow key={a.rule_id + a.subject} a={a} go={go} />)}
          </ul>
        )}
        {run.loading && !run.data && <Skeleton rows={5} />}
      </Card>
    </div>
  )
}

function FindingRow({ a, go }: { a: Assessment; go: PageProps['go'] }) {
  const [open, setOpen] = useState(false)
  const id = `risk-${a.rule_id}-${a.subject}`.replace(/[^a-zA-Z0-9_-]/g, '_')
  return (
    <li className="relative px-5">
      <span className={cn('absolute inset-y-2 left-0 w-[3px] rounded-r-full', toneSolid[toneOf(a.band)])} aria-hidden />
      <div className="flex items-start gap-3 py-2.5">
        <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}
          className="flex min-w-0 flex-1 items-start gap-3 rounded-sm text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <ChevronRight className={cn('mt-0.5 size-4 shrink-0 text-fg-subtle transition-transform', open && 'rotate-90')} aria-hidden />
          <span className="w-[74px] shrink-0"><StatusBadge value={a.band} /></span>
          <span className="w-10 shrink-0 text-right font-semibold tabular-nums">{a.score.toFixed(1)}</span>
          <span className="min-w-0">
            <span className="block truncate font-mono text-[12.5px]">{a.subject}</span>
            <span className="block text-xs text-fg-subtle">{a.rule_id} · severity {a.rule_severity}</span>
          </span>
        </button>
        <Button size="sm" variant="ghost" onClick={() => go('investigate', { resource: a.subject, run: '1' })}>Investigate</Button>
      </div>
      {open && (
        <div id={id} className="mb-3 ml-7 rounded-md border border-border bg-surface-2 px-4 py-3 text-[13px]">
          <ul className="m-0 list-disc space-y-1 pl-4 text-fg-muted">{a.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
          {a.attack_path && a.attack_path.length > 0 && (
            <div className="mt-2"><span className="text-xs text-fg-subtle">Attack path</span><PathTrail hops={['internet', ...a.attack_path.map((h) => h.to)]} /></div>
          )}
          {a.blast_radius.length > 0 && <p className="mb-0 mt-2 text-xs text-fg-subtle">Blast radius: {a.blast_radius.length} connected resources</p>}
        </div>
      )}
    </li>
  )
}

/** internet → lb → instance → bucket, as a readable chain. */
function PathTrail({ hops, reasons }: { hops: string[]; reasons?: string[] }) {
  return (
    <div>
      <ol className="m-0 flex list-none flex-wrap items-center gap-1 p-0 font-mono text-[12px]">
        {hops.map((h, i) => (
          <li key={i} className="flex items-center gap-1">
            {i > 0 && <ChevronRight className="size-3 text-fg-subtle" aria-hidden />}
            <span className={cn('rounded border px-1.5 py-0.5', i === 0 ? 'border-danger/30 text-danger' : 'border-border bg-surface-2')}>{h}</span>
          </li>
        ))}
      </ol>
      {reasons && reasons.length > 0 && <p className="mb-0 mt-1 text-xs text-fg-subtle">{reasons.join('; ')}</p>}
    </div>
  )
}
