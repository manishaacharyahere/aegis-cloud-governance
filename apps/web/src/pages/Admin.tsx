import { useState } from 'react'
import { Activity, KeyRound, UserRound } from 'lucide-react'
import { fetchReadiness, fetchVersion } from '../api'
import { can, type PageProps } from '../nav'
import type { Binding, RequestBody } from '../types'
import { Button, Callout, Card, ConfirmAction, DataTable, ErrorState, Field, Input, KeyValue, Select, StatusBadge, useToast } from '@/components/ui'
import { ago, useAction, useLoad, when } from '../hooks'
import { humanize } from '@/lib/tones'

const ROLES = [
  { role: 'viewer', can: 'Read everything in the tenant.' },
  { role: 'analyst', can: 'Read, import, scan, evaluate, investigate and propose changes.' },
  { role: 'approver', can: 'Read, approve or reject exceptions, baselines and remediations, and release change sets.' },
  { role: 'admin', can: 'Everything, including granting and revoking roles.' },
]

export function Access({ api, me }: PageProps) {
  const list = useLoad(() => api<{ items: Binding[] }>('GET', '/api/v1/access/bindings'), [api])
  const [subject, setSubject] = useState('')
  const [role, setRole] = useState('viewer')
  const act = useAction()
  const toast = useToast()
  if (!can(me, 'admin')) {
    return <Callout tone="info" title="Admin role needed">Managing access needs the admin role in tenant {me.tenant}.</Callout>
  }
  const change = async (method: string, s: string, r: string) => {
    const body = { subject: s, role: r as RequestBody<'BindingChange'>['role'] }
    const ok = await act.attempt(() => api(method, '/api/v1/access/bindings', body))
    if (ok) toast(method === 'POST' ? `Granted ${r} to ${s}.` : `Removed ${r} from ${s}.`)
    list.reload()
  }
  return (
    <div className="grid gap-5 xl:grid-cols-[3fr_2fr]">
      <Card title={`Who can do what in tenant ${me.tenant}`} icon={<KeyRound />} description="Every change is recorded in the audit log.">
        <form className="mb-4 flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); void change('POST', canonicalSubject(subject), role) }}>
          <Field label="Email" className="min-w-[240px] flex-1">
            {(p) => <Input {...p} aria-label="Email" type="email" required placeholder="person@example.com" value={subject} onChange={(e) => setSubject(e.target.value)} />}
          </Field>
          <Field label="Role">
            {(p) => <Select {...p} aria-label="Role" value={role} onChange={(e) => setRole(e.target.value)}>{ROLES.map((r) => <option key={r.role}>{r.role}</option>)}</Select>}
          </Field>
          <Button type="submit" variant="primary" loading={act.busy}>Grant</Button>
        </form>
        <ErrorState error={act.error} className="mb-3" />
        <DataTable rows={list.data?.items} loading={list.loading} error={list.error} onRetry={list.reload} getRowId={(b) => b.subject + b.role}
          empty="No role bindings."
          columns={[
            { key: 'who', header: 'Person', cell: (b) => <span className="font-mono text-[12.5px]">{b.subject}</span> },
            { key: 'role', header: 'Role', cell: (b) => <StatusBadge value="info" icon={false} label={b.role} /> },
            { key: 'by', header: 'Granted', cell: (b) => <span className="text-fg-subtle" title={when(b.created_at)}>{b.granted_by} · {ago(b.created_at)}</span>, hideOnMobile: true },
            { key: 'act', header: <span className="sr-only">Actions</span>, align: 'right', cell: (b) => (
              <ConfirmAction size="sm" label="Revoke" title={`Remove ${b.role} from ${b.subject}?`}
                description={b.subject === me.subject ? 'This is your own role: you may lose access to this page.' : 'They lose these permissions at once.'}
                onConfirm={() => change('DELETE', b.subject, b.role)} />
            ) },
          ]} />
      </Card>
      <Card title="Roles">
        <DataTable rows={ROLES} getRowId={(r) => r.role} dense columns={[
          { key: 'role', header: 'Role', cell: (r) => <b>{r.role}</b> },
          { key: 'can', header: 'Can', cell: (r) => <span className="text-fg-muted">{r.can}</span> },
        ]} />
      </Card>
    </div>
  )
}

export function Health({ me }: PageProps) {
  const ready = useLoad(() => fetchReadiness(), [])
  const ver = useLoad(() => fetchVersion(), [])
  return (
    <div className="grid gap-5 xl:grid-cols-2">
      <Card title="Dependencies" icon={<Activity />} actions={<Button size="sm" variant="ghost" onClick={ready.reload}>Re-check</Button>}
        description={`API version ${ver.data?.version ?? '—'}. Metrics and traces: see docs/observability.md.`}>
        <ErrorState error={ready.error} onRetry={ready.reload} />
        <div className="mb-3 flex items-center gap-2"><StatusBadge value={ready.data?.state ?? 'queued'} label={ready.data ? humanize(ready.data.state) : 'Checking…'} /></div>
        <DataTable rows={Object.entries(ready.data?.checks ?? {})} loading={ready.loading} getRowId={([k]) => k} dense empty="No checks reported."
          columns={[
            { key: 'dep', header: 'Dependency', cell: ([k]) => k },
            { key: 'state', header: 'State', cell: ([, v]) => <StatusBadge value={v === 'ok' ? 'pass' : 'fail'} label={String(v)} /> },
          ]} />
      </Card>
      <Card title="You" icon={<UserRound />}>
        <KeyValue items={[
          { label: 'Identity', value: <span className="font-mono text-[12.5px]">{me.subject}</span> },
          { label: 'Signed in with', value: me.method === 'oidc' ? 'OIDC' : 'development headers (no real authentication)' },
          { label: 'Tenant', value: me.tenant ?? '—' },
          { label: 'Roles', value: <span className="flex flex-wrap gap-1">{(me.roles ?? []).map((r) => <StatusBadge key={r} value="info" icon={false} label={r} />)}</span> },
        ]} />
      </Card>
    </div>
  )
}

/** Emails are case-insensitive; "sub:" identifiers from the identity
 * provider are not (the API applies the same rule). */
function canonicalSubject(s: string): string {
  const t = s.trim()
  return t.startsWith('sub:') ? t : t.toLowerCase()
}
