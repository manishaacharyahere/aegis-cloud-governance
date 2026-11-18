import { useState } from 'react'
import { Boxes, FileUp, ScanLine } from 'lucide-react'
import { can, patchParams, type PageProps } from '../nav'
import type { ImportReport, Paged, Resource, Scan, ScanReport, TypeCount } from '../types'
import {
  BackLink, Button, Callout, Card, DataTable, EmptyState, ErrorState, Field, Input, KeyValue, Mono, Pager, Select,
  SectionTitle, Skeleton, StatCard, StatGrid, StatusBadge, useToast,
} from '@/components/ui'
import { SEVERITY_ORDER } from '@/lib/tones'
import { ago, useAction, useLoad, usePaged, usePoll, when } from '../hooks'

const DONE = ['succeeded', 'failed', 'dead']
const planText = (s?: Record<string, number>) =>
  s ? Object.entries(s).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') || 'no changes' : '—'

export default function Inventory(props: PageProps) {
  const scan = props.params.get('scan')
  return scan ? <ScanView {...props} id={scan} /> : <InventoryHome {...props} />
}

function InventoryHome({ api, me, go, params }: PageProps) {
  return (
    <div className="space-y-5">
      {can(me, 'operate') && (
        <div className="grid gap-5 xl:grid-cols-2">
          <ImportCard api={api} />
          <ScanCard api={api} go={go} />
        </div>
      )}
      <ScanHistory api={api} go={go} />
      <ResourceList api={api} go={go} params={params} />
    </div>
  )
}

function ImportCard({ api }: Pick<PageProps, 'api'>) {
  const imp = useAction()
  const toast = useToast()
  const [report, setReport] = useState<ImportReport | null>(null)
  async function onFile(f: File | undefined) {
    if (!f) return
    let snapshot: unknown
    try {
      snapshot = JSON.parse(await f.text())
    } catch {
      imp.setError(new Error('The file is not valid JSON.'))
      return
    }
    const r = await imp.run(() => api<ImportReport>('POST', '/api/v1/inventory/import', snapshot))
    if (r) {
      setReport(r)
      toast(r.duplicate ? 'Snapshot already imported; nothing changed.' : `Imported ${r.resource_count} resources.`)
    }
  }
  return (
    <Card title="Import an inventory snapshot" icon={<FileUp />}
      description={<>JSON in the <code className="font-mono">aegis.inventory/v1</code> format. Secrets are redacted on import; re-importing the same file changes nothing.</>}>
      <Field label="Snapshot file" hint={<>Terraform state can be imported through the API: <code className="font-mono">POST /api/v1/inventory/import/terraform-state</code>.</>}>
        {(p) => <Input {...p} type="file" accept="application/json,.json" aria-label="Inventory snapshot file" disabled={imp.busy} onChange={(e) => onFile(e.target.files?.[0])} />}
      </Field>
      <ErrorState error={imp.error} className="mt-3" />
      {report && (
        <Callout tone="success" className="ok-text mt-3" title={report.duplicate ? 'Already imported' : 'Imported'}>
          {report.duplicate
            ? `This exact snapshot (${report.resource_count} resources) was imported before; nothing changed.`
            : `Imported ${report.resource_count} resources: ${report.created} new, ${report.updated} changed, ${report.deleted} deleted, ${report.unchanged} unchanged${report.warnings.length > 0 ? `, ${report.warnings.length} warnings` : ''}.`}
        </Callout>
      )}
    </Card>
  )
}

function ScanCard({ api, go }: Pick<PageProps, 'api' | 'go'>) {
  const fixtures = useLoad(() => api<{ items: string[] }>('GET', '/api/v1/iac/fixtures'), [api])
  const [chosen, setChosen] = useState('')
  const fixture = chosen || fixtures.data?.items.find((f) => f === 'insecure-storage') || fixtures.data?.items[0] || ''
  const act = useAction()
  const poll = usePoll<Scan>(null, (s) => api<Scan>('GET', `/api/v1/iac/scans/${s.id}`), (s) => DONE.includes(s.status))
  const scan = poll.value

  return (
    <Card title="Scan Terraform before it is applied" icon={<ScanLine />}
      description="An offline Terraform plan in a sandbox, then Trivy, Checkov and the Aegis OPA rules. Needs the IaC worker running.">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Fixture" className="min-w-[220px] flex-1">
          {(p) => (
            <Select {...p} aria-label="Terraform fixture" value={fixture} onChange={(e) => setChosen(e.target.value)} disabled={!fixtures.data} className="w-full">
              {(fixtures.data?.items ?? []).map((f) => <option key={f}>{f}</option>)}
            </Select>
          )}
        </Field>
        <Button variant="primary" loading={act.busy} disabled={!fixture}
          onClick={async () => {
            const s = await act.run(() => api<Scan>('POST', '/api/v1/iac/scans', { source: { type: 'fixture', ref: fixture } }))
            if (s) poll.start(s)
          }}>Scan</Button>
      </div>
      <ErrorState error={act.error ?? fixtures.error} className="mt-3" />
      {fixtures.data?.items.length === 0 && <Callout className="mt-3" tone="warning">The API lists no fixtures (check AEGIS_FIXTURES_DIR).</Callout>}
      {scan && (
        <div className="scan mt-4 rounded-md border border-border bg-surface-2 px-4 py-3 text-[13px]">
          <div className="flex flex-wrap items-center gap-2">
            Scan <Mono value={scan.id.slice(0, 8)} copy={false} /> of <b>{scan.source_ref}</b>: <StatusBadge value={scan.status} />
            {poll.running && <span className="text-xs text-fg-subtle">checking…</span>}
          </div>
          {scan.plan_summary && <p className="mb-0 mt-1.5 text-fg-muted">Planned: {planText(scan.plan_summary)}</p>}
          {scan.last_error && <p className="mb-0 mt-1.5 text-danger">{scan.last_error}</p>}
          {poll.gaveUp && <p className="mb-0 mt-1.5 text-warning">Still not finished. Is the worker running? The scan stays queued until it is.</p>}
          {scan.status === 'succeeded' && <Button variant="link" className="mt-2" onClick={() => go('inventory', { scan: scan.id })}>View findings →</Button>}
        </div>
      )}
    </Card>
  )
}

function ScanHistory({ api, go }: Pick<PageProps, 'api' | 'go'>) {
  const scans = usePaged((after) => api<Paged<Scan>>('GET', `/api/v1/iac/scans?limit=8${after ? '&after=' + encodeURIComponent(after) : ''}`), [api])
  if (!scans.loading && scans.items.length === 0 && !scans.error) return null
  return (
    <Card title="Recent scans" actions={<Button size="sm" variant="ghost" onClick={scans.reload}>Refresh</Button>}>
      <DataTable rows={scans.items} loading={scans.loading} error={scans.error} onRetry={scans.reload}
        getRowId={(s) => s.id} onRowOpen={(s) => go('inventory', { scan: s.id })}
        rowTone={(s) => (s.status === 'failed' || s.status === 'dead' ? 'danger' : undefined)}
        columns={[
          { key: 'fixture', header: 'Fixture', cell: (s) => s.source_ref },
          { key: 'status', header: 'Status', cell: (s) => <StatusBadge value={s.status} /> },
          { key: 'plan', header: 'Planned', cell: (s) => <span className="text-fg-muted">{planText(s.plan_summary)}</span>, hideOnMobile: true },
          { key: 'when', header: 'Started', align: 'right', cell: (s) => <span className="text-fg-subtle" title={when(s.created_at)}>{ago(s.created_at)}</span> },
        ]} />
      <Pager mode="more" hasNext={!!scans.next} onNext={scans.more} loading={scans.loading} />
    </Card>
  )
}

function ResourceList({ api, go, params }: Pick<PageProps, 'api' | 'go' | 'params'>) {
  // Filters live in the URL, so a filtered view can be bookmarked and Back works.
  const type = params.get('type') ?? ''
  const env = params.get('environment') ?? ''
  const [cursor, setCursor] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const q = new URLSearchParams({ limit: '50', ...(type && { type }), ...(env && { environment: env }), ...(cursor && { cursor }) })
  const list = useLoad(() => api<{ items: Resource[]; next_cursor?: string }>('GET', `/api/v1/resources?${q}`), [api, type, env, cursor])
  const types = useLoad(() => api<{ items: TypeCount[] }>('GET', '/api/v1/resources/types'), [api])
  const setFilter = (k: string, v: string) => {
    setCursor('')
    setHistory([])
    go('inventory', patchParams(params, { [k]: v }))
  }
  return (
    <Card title="Cloud inventory" icon={<Boxes />} actions={
      <>
        <Select aria-label="Resource type" value={type} onChange={(e) => setFilter('type', e.target.value)}>
          <option value="">All types</option>
          {(types.data?.items ?? []).map((t) => <option key={t.resource_type} value={t.resource_type}>{t.resource_type} ({t.count})</option>)}
        </Select>
        <Select aria-label="Environment" value={env} onChange={(e) => setFilter('environment', e.target.value)}>
          <option value="">All environments</option>
          {['production', 'staging', 'development'].map((t) => <option key={t}>{t}</option>)}
        </Select>
      </>
    }>
      <DataTable rows={list.data?.items} loading={list.loading} error={list.error} onRetry={list.reload} getRowId={(r) => r.id}
        empty={<EmptyState icon={<Boxes />} title="No resources match">Import a snapshot, or clear the filters.</EmptyState>}
        columns={[
          { key: 'id', header: 'Resource', cell: (r) => <Mono value={r.resource_id} /> },
          { key: 'type', header: 'Type', cell: (r) => <span className="text-fg-muted">{r.resource_type}</span> },
          { key: 'env', header: 'Environment', cell: (r) => r.environment || '—', hideOnMobile: true },
          { key: 'region', header: 'Region', cell: (r) => r.region || '—', hideOnMobile: true },
          { key: 'owner', header: 'Owner', cell: (r) => r.owner || <StatusBadge value="unowned" />, hideOnMobile: true },
          { key: 'v', header: 'Version', align: 'right', cell: (r) => r.current_version, hideOnMobile: true },
          { key: 'go', header: <span className="sr-only">Actions</span>, align: 'right', cell: (r) => <Button size="sm" variant="ghost" onClick={() => go('investigate', { resource: r.resource_id, run: '1' })}>Investigate</Button> },
        ]} />
      <Pager mode="pages" hasPrev={history.length > 0} hasNext={!!list.data?.next_cursor} loading={list.loading} count={list.data?.items.length}
        onPrev={() => { setCursor(history[history.length - 1]); setHistory(history.slice(0, -1)) }}
        onNext={() => { setHistory([...history, cursor]); setCursor(list.data!.next_cursor!) }} />
    </Card>
  )
}

function ScanView({ api, go, params, id }: PageProps & { id: string }) {
  const rep = useLoad(() => api<ScanReport>('GET', `/api/v1/iac/scans/${id}`), [api, id])
  const source = params.get('source') ?? ''
  const severity = params.get('severity') ?? ''
  const set = (k: string, v: string) => go('inventory', patchParams(params, { [k]: v }))
  const r = rep.data
  const findings = (r?.findings ?? []).filter((f) => (!source || f.source === source) && (!severity || f.severity === severity))
  const total = (sev: string) => Object.values(r?.counts ?? {}).reduce((n, bySev) => n + (bySev[sev] ?? 0), 0)

  return (
    <div className="space-y-5">
      <BackLink onClick={() => go('inventory')}>Import & scan</BackLink>
      <ErrorState error={rep.error} onRetry={rep.reload} />
      {!r ? !rep.error && <Skeleton rows={6} /> : (
        <>
          <StatGrid>
            <StatCard label="Blocking (policy deny)" value={r.blocking} tone="auto" autoTone="danger" />
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <StatCard key={s} label={s[0].toUpperCase() + s.slice(1)} value={total(s)} tone="auto" autoTone={s === 'critical' ? 'danger' : s === 'high' ? 'high' : s === 'medium' ? 'warning' : 'info'} />
            ))}
          </StatGrid>
          <Card title={`Scan of ${r.source_ref}`} actions={<StatusBadge value={r.status} />}>
            <KeyValue items={[
              { label: 'Started', value: when(r.created_at) },
              { label: 'Finished', value: when(r.finished_at) },
              { label: 'Tools', value: Object.entries(r.tool_versions ?? {}).map(([k, v]) => `${k} ${String(v).split(':').pop()}`).join(' · ') || '—' },
            ]} />
            {r.last_error && <Callout tone="danger" className="mt-3">{r.last_error}</Callout>}
            <SectionTitle>Planned changes ({r.planned_changes.length})</SectionTitle>
            {r.planned_changes.length === 0 ? <p className="m-0 text-[13px] text-fg-muted">None.</p> : (
              <ul className="m-0 grid list-none gap-1 p-0 font-mono text-[12.5px] sm:grid-cols-2">
                {r.planned_changes.slice(0, 60).map((c) => (
                  <li key={c.address} className="flex items-center gap-2 truncate"><span className="text-fg-subtle">{c.action}</span> {c.address}{c.destructive && <StatusBadge value="destructive" />}</li>
                ))}
              </ul>
            )}
          </Card>
          <Card title={`Findings (${findings.length} of ${r.findings.length})`} actions={
            <>
              <Select aria-label="Source" value={source} onChange={(e) => set('source', e.target.value)}>
                <option value="">All sources</option>
                {Object.keys(r.counts).sort().map((s) => <option key={s}>{s}</option>)}
              </Select>
              <Select aria-label="Severity" value={severity} onChange={(e) => set('severity', e.target.value)}>
                <option value="">All severities</option>
                {SEVERITY_ORDER.map((s) => <option key={s}>{s}</option>)}
              </Select>
            </>
          }>
            <DataTable rows={findings} getRowId={(f) => f.fingerprint} empty="No findings match."
              rowTone={(f) => (f.decision === 'deny' ? 'danger' : f.severity === 'critical' ? 'danger' : f.severity === 'high' ? 'high' : undefined)}
              columns={[
                { key: 'sev', header: 'Severity', cell: (f) => <div className="flex flex-col items-start gap-1"><StatusBadge value={f.severity} />{f.decision === 'deny' && <StatusBadge value="blocking" />}</div> },
                { key: 'src', header: 'Source', cell: (f) => f.source },
                { key: 'rule', header: 'Rule', cell: (f) => <code className="font-mono text-[12px]">{f.rule_id}</code>, hideOnMobile: true },
                { key: 'res', header: 'Resource', cell: (f) => <><Mono value={f.resource_address || '—'} copy={false} />{f.file_path && <div className="text-xs text-fg-subtle">{f.file_path}{f.start_line ? `:${f.start_line}` : ''}</div>}</> },
                { key: 'title', header: 'Finding', cell: (f) => <span className="text-fg-muted">{f.title}</span> },
              ]} />
          </Card>
        </>
      )}
    </div>
  )
}
