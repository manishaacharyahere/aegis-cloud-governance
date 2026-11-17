import { useState } from 'react'
import { fetchReadiness, fetchVersion } from '../api'
import { can, type PageProps } from '../nav'
import type { Binding } from '../types'
import { Badge, ConfirmButton, ErrorBox, Panel } from '../ui'
import { useAction, useLoad, when } from '../hooks'

export function Access({ api, me }: PageProps) {
  const list = useLoad(() => api<{ items: Binding[] }>('GET', '/api/v1/access/bindings'), [api])
  const [subject, setSubject] = useState('')
  const [role, setRole] = useState('viewer')
  const act = useAction()
  if (!can(me, 'admin')) return <Panel title="Access"><p className="muted">Managing access needs the admin role.</p></Panel>
  const change = async (method: string, s: string, r: string) => {
    await act.run(() => api(method, '/api/v1/access/bindings', { subject: s, role: r }))
    list.reload()
  }
  return (
    <Panel title={`Who can do what in tenant ${me.tenant}`}>
      <p className="muted small">viewer: read · analyst: read and operate · approver: read and approve · admin: everything. Every change is audited.</p>
      <form className="row" onSubmit={(e) => { e.preventDefault(); void change('POST', subject.trim().toLowerCase(), role) }}>
        <input aria-label="Email" type="email" required placeholder="person@example.com" value={subject} onChange={(e) => setSubject(e.target.value)} />
        <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value)}>{['viewer', 'analyst', 'approver', 'admin'].map((r) => <option key={r}>{r}</option>)}</select>
        <button className="primary" disabled={act.busy}>Grant</button>
      </form>
      <ErrorBox error={act.error ?? list.error} />
      <table className="table">
        <tbody>
          {(list.data?.items ?? []).map((b) => (
            <tr key={b.subject + b.role}>
              <td className="mono">{b.subject}</td>
              <td><Badge value={b.role} /></td>
              <td className="small muted">granted by {b.granted_by} · {when(b.created_at)}</td>
              <td><ConfirmButton label="Revoke" confirm={`Remove ${b.role} from ${b.subject}?`} onConfirm={() => change('DELETE', b.subject, b.role)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </Panel>
  )
}

export function Health({ me }: PageProps) {
  const ready = useLoad(() => fetchReadiness(), [])
  const ver = useLoad(() => fetchVersion(), [])
  return (
    <div className="grid2">
      <Panel title="Dependencies">
        <p><Badge value={ready.data?.state === 'ready' ? 'passing' : 'failing'} /> {ready.data?.state}</p>
        <table className="table"><tbody>{Object.entries(ready.data?.checks ?? {}).map(([k, v]) => <tr key={k}><td>{k}</td><td><Badge value={v === 'ok' ? 'pass' : 'fail'} /></td></tr>)}</tbody></table>
        <p className="muted small">API version {ver.data?.version ?? '—'}. Metrics and traces: see docs/observability.md.</p>
        <ErrorBox error={ready.error} />
      </Panel>
      <Panel title="You">
        <p className="mono">{me.subject}</p>
        <p className="small">Signed in with {me.method === 'oidc' ? 'OIDC' : 'development headers (no real authentication)'} · tenant {me.tenant}</p>
        <p>{(me.roles ?? []).map((r) => <Badge key={r} value={r} />)}</p>
      </Panel>
    </div>
  )
}
