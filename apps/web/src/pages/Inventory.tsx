import { useEffect, useState } from 'react'
import { can, type PageProps } from '../nav'
import type { ImportReport, Resource, Scan } from '../types'
import { Badge, Empty, ErrorBox, Panel } from '../ui'
import { useAction, useLoad, when } from '../hooks'

const FIXTURES = ['secure-baseline', 'insecure-storage', 'iam-wildcard', 'network-exposure', 'missing-logging-tags', 'unapproved-region']

export default function Inventory({ api, me, go }: PageProps) {
  const [type, setType] = useState('')
  const [env, setEnv] = useState('')
  const [cursor, setCursor] = useState('')
  const q = new URLSearchParams({ limit: '50', ...(type && { resource_type: type }), ...(env && { environment: env }), ...(cursor && { after: cursor }) })
  const list = useLoad(() => api<{ items: Resource[]; next_cursor?: string }>('GET', `/api/v1/resources?${q}`), [api, type, env, cursor])
  const imp = useAction()
  const [report, setReport] = useState<ImportReport | null>(null)

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
      list.reload()
    }
  }

  return (
    <div className="stack">
      {can(me, 'operate') && (
        <div className="grid2">
          <Panel title="1. Import an inventory snapshot">
            <p className="muted small">
              JSON in the <code>aegis.inventory/v1</code> format (e.g. <code>datasets/inventory/sample/snapshot-v1.json</code>).
              Secrets are redacted on import; re-importing the same file changes nothing.
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
          <ScanPanel {...{ api, me, go }} />
        </div>
      )}

      <Panel title="Cloud inventory" actions={
        <>
          <select aria-label="Resource type" value={type} onChange={(e) => { setType(e.target.value); setCursor('') }}>
            <option value="">All types</option>
            {['storage.bucket', 'database.instance', 'compute.instance', 'network.security_group', 'identity.policy', 'identity.role',
              'logging.trail', 'security.kms_key', 'network.subnet', 'network.vpc', 'network.load_balancer'].map((t) => <option key={t}>{t}</option>)}
          </select>
          <select aria-label="Environment" value={env} onChange={(e) => { setEnv(e.target.value); setCursor('') }}>
            <option value="">All environments</option>
            {['production', 'staging', 'development'].map((t) => <option key={t}>{t}</option>)}
          </select>
        </>
      }>
        <ErrorBox error={list.error} />
        {list.data && list.data.items.length === 0 ? <Empty>No resources. Import a snapshot first.</Empty> : (
          <table className="table">
            <thead>
              <tr><th>Resource</th><th>Type</th><th>Environment</th><th>Region</th><th>Owner</th><th>Version</th><th /></tr>
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
                  <td><button className="link" onClick={() => go('investigate', { resource: r.resource_id })}>Investigate</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="pager">
          {cursor && <button onClick={() => setCursor('')}>First page</button>}
          {list.data?.next_cursor && <button onClick={() => setCursor(list.data!.next_cursor!)}>Next page →</button>}
        </div>
      </Panel>
    </div>
  )
}

function ScanPanel({ api }: Pick<PageProps, 'api' | 'me' | 'go'>) {
  const [fixture, setFixture] = useState(FIXTURES[1])
  const [scan, setScan] = useState<Scan | null>(null)
  const act = useAction()

  useEffect(() => {
    if (!scan || ['succeeded', 'failed', 'dead'].includes(scan.status)) return
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
        <select aria-label="Terraform fixture" value={fixture} onChange={(e) => setFixture(e.target.value)}>
          {FIXTURES.map((f) => <option key={f}>{f}</option>)}
        </select>
        <button className="primary" disabled={act.busy}
          onClick={async () => {
            const s = await act.run(() => api<Scan>('POST', '/api/v1/iac/scans', { source: { type: 'fixture', ref: fixture } }))
            if (s) setScan(s)
          }}>Scan</button>
      </div>
      <ErrorBox error={act.error} />
      {scan && (
        <div className="scan">
          <p>Scan <code>{scan.id.slice(0, 8)}</code> of <b>{scan.source_ref}</b>: <Badge value={scan.status} />{' '}
            {!['succeeded', 'failed', 'dead'].includes(scan.status) && <span className="muted small">checking every 2 s…</span>}</p>
          {scan.plan_summary && (
            <p className="small">Planned: {Object.entries(scan.plan_summary).filter(([, v]) => v).map(([k, v]) => `${v} ${k}`).join(', ') || 'no changes'}</p>
          )}
          {scan.last_error && <p className="error">{scan.last_error}</p>}
          {scan.finished_at && <p className="muted small">Finished {when(scan.finished_at)}. Evaluate it under Compliance to map findings to controls.</p>}
        </div>
      )}
    </Panel>
  )
}
