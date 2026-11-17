import { useEffect, useState } from 'react'
import { can, type PageProps } from '../nav'
import type { ImportReport, Paged, Resource, Scan, ScanReport, TypeCount } from '../types'
import { Badge, Empty, ErrorBox, Panel, rowLink, Skeleton, Stat, useToast } from '../ui'
import { useAction, useLoad, usePaged, when } from '../hooks'

const DONE = ['succeeded', 'failed', 'dead']
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

export default function Inventory(props: PageProps) {
  const scan = props.params.get('scan')
  return scan ? <ScanView {...props} id={scan} /> : <InventoryHome {...props} />
}

function InventoryHome({ api, me, go, params }: PageProps) {
  // Filters live in the URL, so a filtered view can be bookmarked and Back works.
  const type = params.get('type') ?? ''
  const env = params.get('environment') ?? ''
  const [cursor, setCursor] = useState('')
  const [history, setHistory] = useState<string[]>([])
  const q = new URLSearchParams({ limit: '50', ...(type && { type }), ...(env && { environment: env }), ...(cursor && { cursor }) })
  const list = useLoad(() => api<{ items: Resource[]; next_cursor?: string }>('GET', `/api/v1/resources?${q}`), [api, type, env, cursor])
  const types = useLoad(() => api<{ items: TypeCount[] }>('GET', '/api/v1/resources/types'), [api])
  const imp = useAction()
  const toast = useToast()
  const [report, setReport] = useState<ImportReport | null>(null)
  const setFilter = (k: string, v: string) => go('inventory', { ...(type && { type }), ...(env && { environment: env }), [k]: v })

  async function onFile(f: File | undefined) {
    if (!f) return
    const text = await f.text()
    let snapshot: unknown
    try {
      snapshot = JSON.parse(text)
    } catch {
      imp.setError(new Error('The file is not valid JSON.'))
      return
    }
    const r = await imp.run(() => api<ImportReport>('POST', '/api/v1/inventory/import', snapshot))
    if (r) {
      setReport(r)
      toast(r.duplicate ? 'Snapshot already imported; nothing changed.' : `Imported ${r.resource_count} resources.`)
      list.reload()
      types.reload()
    }
  }

  return (
    <div className="stack">
      {can(me, 'operate') && (
        <div className="grid2">
          <Panel title="1. Import an inventory snapshot">
            <p className="muted small">
              JSON in the <code>aegis.inventory/v1</code> format (e.g. <code>datasets/inventory/sample/snapshot-v1.json</code>).
              Secrets are redacted on import; re-importing the same file changes nothing. Terraform state files can be imported
              through the API (<code>POST /api/v1/inventory/import/terraform-state</code>).
            </p>
            <input type="file" accept="application/json,.json" aria-label="Inventory snapshot file" disabled={imp.busy}
              onChange={(e) => onFile(e.target.files?.[0])} />
            <ErrorBox error={imp.error} />
            {report && (
              <p className="ok-text">
                {report.duplicate
                  ? `This exact snapshot (${report.resource_count} resources) was imported before; nothing changed.`
                  : `Imported ${report.resource_count} resources: ${report.created} new, ${report.updated} changed, ${report.deleted} deleted, ${report.unchanged} unchanged${report.warnings.length > 0 ? `, ${report.warnings.length} warnings` : ''}.`}
              </p>
            )}
          </Panel>
          <ScanPanel {...{ api, go }} />
        </div>
      )}

      <ScanHistory api={api} go={go} />

      <Panel title="Cloud inventory" actions={
        <>
          <select aria-label="Resource type" value={type} onChange={(e) => { setCursor(''); setHistory([]); setFilter('type', e.target.value) }}>
            <option value="">All types</option>
            {(types.data?.items ?? []).map((t) => <option key={t.resource_type} value={t.resource_type}>{t.resource_type} ({t.count})</option>)}
          </select>
          <select aria-label="Environment" value={env} onChange={(e) => { setCursor(''); setHistory([]); setFilter('environment', e.target.value) }}>
            <option value="">All environments</option>
            {['production', 'staging', 'development'].map((t) => <option key={t}>{t}</option>)}
          </select>
        </>
      }>
        <ErrorBox error={list.error} />
        {list.loading && !list.data ? <Skeleton rows={6} /> : list.data && list.data.items.length === 0 ? <Empty>No resources match. Import a snapshot, or clear the filters.</Empty> : (
          <table className="table">
            <thead>
              <tr><th>Resource</th><th>Type</th><th>Environment</th><th>Region</th><th>Owner</th><th className="num">Version</th><th /></tr>
            </thead>
            <tbody>
              {(list.data?.items ?? []).map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.resource_id}</td>
                  <td>{r.resource_type}</td>
                  <td>{r.environment || '—'}</td>
                  <td>{r.region || '—'}</td>
                  <td>{r.owner || <Badge value="unowned" />}</td>
                  <td className="num">{r.current_version}</td>
                  <td><button className="link" onClick={() => go('investigate', { resource: r.resource_id, run: '1' })}>Investigate</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="pager">
          {history.length > 0 && <button onClick={() => { setCursor(history[history.length - 1]); setHistory(history.slice(0, -1)) }}>← Previous page</button>}
          {list.data?.next_cursor && <button onClick={() => { setHistory([...history, cursor]); setCursor(list.data!.next_cursor!) }}>Next page →</button>}
        </div>
      </Panel>
    </div>
  )
}

function ScanPanel({ api, go }: Pick<PageProps, 'api' | 'go'>) {
  const fixtures = useLoad(() => api<{ items: string[] }>('GET', '/api/v1/iac/fixtures'), [api])
  const [chosen, setChosen] = useState('')
  const fixture = chosen || fixtures.data?.items.find((f) => f === 'insecure-storage') || fixtures.data?.items[0] || ''
  const [scan, setScan] = useState<Scan | null>(null)
  const act = useAction()

  useEffect(() => {
    if (!scan || DONE.includes(scan.status)) return
    const id = window.setTimeout(async () => {
      const s = await act.run(() => api<Scan>('GET', `/api/v1/iac/scans/${scan.id}`))
      if (s) setScan(s)
    }, 2000)
    return () => window.clearTimeout(id)
  }, [scan, api, act])

  return (
    <Panel title="2. Scan Terraform before it is applied">
      <p className="muted small">
        Runs an offline Terraform plan in a sandbox, then Trivy, Checkov and the Aegis OPA rules. Needs the IaC worker running
        (<code>go run ./cmd/aegis-worker</code>).
      </p>
      <div className="row">
        <select aria-label="Terraform fixture" value={fixture} onChange={(e) => setChosen(e.target.value)} disabled={!fixtures.data}>
          {(fixtures.data?.items ?? []).map((f) => <option key={f}>{f}</option>)}
        </select>
        <button className="primary" disabled={act.busy || !fixture}
          onClick={async () => {
            const s = await act.run(() => api<Scan>('POST', '/api/v1/iac/scans', { source: { type: 'fixture', ref: fixture } }))
            if (s) setScan(s)
          }}>Scan</button>
      </div>
      <ErrorBox error={act.error ?? fixtures.error} />
      {fixtures.data?.items.length === 0 && <Empty>The API lists no fixtures (AEGIS_FIXTURES_DIR).</Empty>}
      {scan && (
        <div className="scan">
          <p>Scan <code>{scan.id.slice(0, 8)}</code> of <b>{scan.source_ref}</b>: <Badge value={scan.status} />{' '}
            {!DONE.includes(scan.status) && <span className="muted small">checking every 2 s…</span>}</p>
          {scan.plan_summary && (
            <p className="small">Planned: {Object.entries(scan.plan_summary).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') || 'no changes'}</p>
          )}
          {scan.last_error && <p className="error">{scan.last_error}</p>}
          {scan.status === 'succeeded' && <button className="link" onClick={() => go('inventory', { scan: scan.id })}>View findings →</button>}
          {scan.finished_at && <p className="muted small">Finished {when(scan.finished_at)}. Evaluate it under Compliance to map findings to controls.</p>}
        </div>
      )}
    </Panel>
  )
}

function ScanHistory({ api, go }: Pick<PageProps, 'api' | 'go'>) {
  const scans = usePaged((after) => api<Paged<Scan>>('GET', `/api/v1/iac/scans?limit=10${after ? '&after=' + encodeURIComponent(after) : ''}`), [api])
  if (!scans.loading && scans.items.length === 0 && !scans.error) return null
  return (
    <Panel title="Recent scans" actions={<button className="link" onClick={scans.reload}>Refresh</button>}>
      <ErrorBox error={scans.error} />
      {scans.loading && scans.items.length === 0 ? <Skeleton rows={2} /> : (
        <table className="table">
          <thead><tr><th>Fixture</th><th>Status</th><th>Planned</th><th>Started</th></tr></thead>
          <tbody>
            {scans.items.map((s) => (
              <tr key={s.id} {...rowLink(() => go('inventory', { scan: s.id }))}>
                <td>{s.source_ref}</td>
                <td><Badge value={s.status} /></td>
                <td className="small">{s.plan_summary ? Object.entries(s.plan_summary).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') || 'no changes' : '—'}</td>
                <td>{when(s.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {scans.next && <div className="pager"><button disabled={scans.loading} onClick={scans.more}>Load more</button></div>}
    </Panel>
  )
}

function ScanView({ api, go, params, id }: PageProps & { id: string }) {
  const rep = useLoad(() => api<ScanReport>('GET', `/api/v1/iac/scans/${id}`), [api, id])
  const source = params.get('source') ?? ''
  const severity = params.get('severity') ?? ''
  const set = (k: string, v: string) => go('inventory', { scan: id, ...(source && { source }), ...(severity && { severity }), [k]: v })
  const r = rep.data
  const findings = (r?.findings ?? []).filter((f) => (!source || f.source === source) && (!severity || f.severity === severity))
  const total = (sev: string) => Object.values(r?.counts ?? {}).reduce((n, bySev) => n + (bySev[sev] ?? 0), 0)

  return (
    <div className="stack">
      <button className="link" onClick={() => go('inventory')}>← Import & scan</button>
      <ErrorBox error={rep.error} />
      {!r ? <Skeleton rows={6} /> : (
        <>
          <div className="stats">
            <Stat label="blocking (policy deny)" value={r.blocking} tone={r.blocking > 0 ? 'bad' : 'ok'} />
            {['critical', 'high', 'medium', 'low'].map((s) => <Stat key={s} label={s} value={total(s)} tone={(s === 'critical' || s === 'high') && total(s) > 0 ? 'bad' : undefined} />)}
          </div>
          <Panel title={`Scan of ${r.source_ref}`} actions={<Badge value={r.status} />}>
            <p className="small muted">
              Started {when(r.created_at)}{r.finished_at && <>, finished {when(r.finished_at)}</>} · tools{' '}
              {Object.entries(r.tool_versions ?? {}).map(([k, v]) => `${k} ${String(v).split(':').pop()}`).join(', ') || '—'}
            </p>
            {r.last_error && <p className="error">{r.last_error}</p>}
            <h3>Planned changes ({r.planned_changes.length})</h3>
            {r.planned_changes.length === 0 ? <Empty>None.</Empty> : (
              <ul className="small mono">
                {r.planned_changes.slice(0, 50).map((c) => <li key={c.address}>{c.action} {c.address}{c.destructive && <> <Badge value="destructive" /></>}</li>)}
              </ul>
            )}
          </Panel>
          <Panel title={`Findings (${findings.length} of ${r.findings.length})`} actions={
            <>
              <select aria-label="Source" value={source} onChange={(e) => set('source', e.target.value)}>
                <option value="">All sources</option>
                {Object.keys(r.counts).sort().map((s) => <option key={s}>{s}</option>)}
              </select>
              <select aria-label="Severity" value={severity} onChange={(e) => set('severity', e.target.value)}>
                <option value="">All severities</option>
                {SEVERITY_ORDER.map((s) => <option key={s}>{s}</option>)}
              </select>
            </>
          }>
            {findings.length === 0 ? <Empty>No findings match.</Empty> : (
              <table className="table">
                <thead><tr><th>Severity</th><th>Source</th><th>Rule</th><th>Resource</th><th>Finding</th></tr></thead>
                <tbody>
                  {findings.map((f) => (
                    <tr key={f.fingerprint}>
                      <td><Badge value={f.severity} />{f.decision === 'deny' && <> <Badge value="blocking" /></>}</td>
                      <td>{f.source}</td>
                      <td className="mono small">{f.rule_id}</td>
                      <td className="mono small">{f.resource_address || '—'}{f.file_path && <div className="muted">{f.file_path}{f.start_line ? `:${f.start_line}` : ''}</div>}</td>
                      <td className="small">{f.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}
