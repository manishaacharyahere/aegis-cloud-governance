import { useState } from 'react'
import { can, type PageProps } from '../nav'
import type { Account, DriftBaseline, DriftReport, Paged } from '../types'
import { Badge, ConfirmButton, Empty, ErrorBox, Panel, rowLink, Skeleton, Stat, useToast } from '../ui'
import { useAction, useLoad, usePaged, when } from '../hooks'

const CATEGORIES = ['security', 'deleted', 'unmanaged', 'cost', 'configuration', 'tagging']
const SEVERITIES = ['critical', 'high', 'medium', 'low']

export default function Drift(props: PageProps) {
  const id = props.params.get('id')
  return id ? <ReportView {...props} id={id} /> : <DriftHome {...props} />
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
    <div className="stack">
      <div className="grid2">
        <Panel title="Approved baseline" actions={acctList.length > 1 && (
          <select aria-label="Account" value={account} onChange={(e) => setChosen(e.target.value)}>
            {acctList.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.external_id}, {a.resource_count} resources)</option>)}
          </select>
        )}>
          <p className="muted small">
            A baseline is an approved copy of an account's latest inventory. Drift is any difference between it and a later
            import, with the policy rules that newly fail or now pass.
          </p>
          {(baselines.loading && !baselines.data) || (accounts.loading && !accounts.data) ? <Skeleton rows={2} /> : acctList.length === 0 ? (
            <Empty>No inventory yet. Import a snapshot under Import & scan first.</Empty>
          ) : active ? (
            <p>
              <Badge value="active" /> {active.resource_count} resources in <b>{name(account)}</b>, approved by <b>{active.approved_by}</b> {when(active.created_at)}
              {active.note && <span className="muted small"> · “{active.note}”</span>}
            </p>
          ) : <Empty>No baseline for {name(account)} yet. Approve its latest import as the baseline.</Empty>}
          <ErrorBox error={accounts.error ?? baselines.error ?? act.error} />
          {acctList.length > 0 && (
            <div className="row">
              {can(me, 'approve') && (
                <>
                  <input aria-label="Baseline note" placeholder="Note (optional)" value={note} onChange={(e) => setNote(e.target.value)} />
                  <ConfirmButton label="Approve latest import" confirm={`Make the latest import of ${name(account)} the baseline?`} disabled={act.busy}
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
                <button className="primary" disabled={act.busy || !active} onClick={async () => {
                  const r = await act.run(() => api<DriftReport>('POST', '/api/v1/drift/compare', { account_id: account }))
                  if (r) {
                    toast(`Drift check done: ${r.counts.total ?? r.items.length} differences.`)
                    go('drift', { id: r.id })
                  }
                }}>Check for drift now</button>
              )}
            </div>
          )}
        </Panel>
        <Panel title="Baseline history">
          {mine.length === 0 ? <Empty>None for this account.</Empty> : (
            <ul className="small">
              {mine.slice(0, 8).map((b) => (
                <li key={b.id}><Badge value={b.status} /> {b.resource_count} resources · {b.approved_by} · {when(b.created_at)}</li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel title="Drift reports">
        <ErrorBox error={reports.error} />
        {reports.loading && reports.items.length === 0 ? <Skeleton /> : reports.items.length === 0 ? <Empty>No drift checks yet.</Empty> : (
          <table className="table">
            <thead><tr><th>When</th><th>Account</th><th>By</th><th className="num">Differences</th><th>By severity</th><th>By category</th></tr></thead>
            <tbody>
              {reports.items.map((r) => (
                <tr key={r.id} {...rowLink(() => go('drift', { id: r.id }))}>
                  <td>{when(r.created_at)}</td>
                  <td>{name(r.account_id)}</td>
                  <td>{r.actor}</td>
                  <td className="num">{r.counts.total ?? 0}</td>
                  <td className="small">{fmtCounts(r.counts.by_severity, SEVERITIES)}</td>
                  <td className="small">{fmtCounts(r.counts.by_category, CATEGORIES)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {reports.next && <div className="pager"><button disabled={reports.loading} onClick={reports.more}>Load more</button></div>}
      </Panel>
    </div>
  )
}

function fmtCounts(c: Record<string, number> | undefined, order: string[]): string {
  if (!c) return '—'
  return order.filter((k) => c[k]).map((k) => `${c[k]} ${k}`).join(', ') || 'none'
}

function ReportView({ api, go, params, id }: PageProps & { id: string }) {
  const category = params.get('category') ?? ''
  const severity = params.get('min_severity') ?? ''
  const q = new URLSearchParams({ ...(category && { category }), ...(severity && { min_severity: severity }) })
  const rep = useLoad(() => api<DriftReport>('GET', `/api/v1/drift/reports/${id}?${q}`), [api, id, category, severity])
  const set = (k: string, v: string) => go('drift', { id, ...(category && { category }), ...(severity && { min_severity: severity }), [k]: v })
  const r = rep.data

  return (
    <div className="stack">
      <button className="link" onClick={() => go('drift')}>← All drift reports</button>
      <ErrorBox error={rep.error} />
      {!r ? <Skeleton rows={5} /> : (
        <>
          <div className="stats">
            <Stat label="differences" value={r.counts.total ?? 0} tone={(r.counts.total ?? 0) > 0 ? 'warn' : 'ok'} />
            {SEVERITIES.map((s) => <Stat key={s} label={s} value={r.counts.by_severity?.[s] ?? 0} tone={s === 'critical' || s === 'high' ? 'bad' : undefined} />)}
          </div>
          <Panel title={`Drift found ${when(r.created_at)} by ${r.actor}`} actions={
            <>
              <select aria-label="Category" value={category} onChange={(e) => set('category', e.target.value)}>
                <option value="">All categories</option>
                {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
              </select>
              <select aria-label="Minimum severity" value={severity} onChange={(e) => set('min_severity', e.target.value)}>
                <option value="">Any severity</option>
                {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
              </select>
            </>
          }>
            {r.items.length === 0 ? <Empty>No drift matches these filters.</Empty> : (
              <table className="table">
                <thead><tr><th>Resource</th><th>Category</th><th>Severity</th><th>What changed</th><th /></tr></thead>
                <tbody>
                  {r.items.map((it) => (
                    <tr key={it.resource_id + it.category}>
                      <td className="mono">{it.resource_id}<div className="muted small">{it.resource_type}</div></td>
                      <td>{it.category}</td>
                      <td><Badge value={it.severity} /></td>
                      <td className="small">
                        {(it.changes ?? []).slice(0, 4).map((c) => (
                          <div key={c.path}><code>{c.path}</code>: {show(c.before)} → {show(c.after)}</div>
                        ))}
                        {(it.changes?.length ?? 0) > 4 && <div className="muted">and {it.changes!.length - 4} more</div>}
                        {(it.new_failures ?? []).length > 0 && <div className="error">Now failing: {it.new_failures!.join(', ')}</div>}
                        {(it.resolved ?? []).length > 0 && <div className="ok-text">Now passing: {it.resolved!.join(', ')}</div>}
                      </td>
                      <td><button className="link" onClick={() => go('investigate', { resource: it.resource_id })}>Investigate</button></td>
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

function show(v: unknown): string {
  if (v === undefined || v === null) return '—'
  const s = typeof v === 'string' ? v : JSON.stringify(v)
  return s.length > 60 ? s.slice(0, 57) + '…' : s
}
