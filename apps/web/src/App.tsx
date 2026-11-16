import { useEffect, useMemo, useState, type ComponentType } from 'react'
import { fetchReadiness, type Readiness } from './api'
import { DEV_USERS, beginLogin, completeLogin, devSession, fetchAuthConfig, loadSession, logout, renew, renewIn, type AuthConfig, type Session } from './auth'
import { describeError, makeClient } from './client'
import { hashFor, parseHash, type PageProps } from './nav'
import type { Me } from './types'
import { Access, Health } from './pages/Admin'
import Compliance from './pages/Compliance'
import Cost from './pages/Cost'
import Inventory from './pages/Inventory'
import Investigate from './pages/Investigate'
import Overview from './pages/Overview'
import Remediation from './pages/Remediation'
import Risk from './pages/Risk'

const PAGES: { route: string; label: string; page: ComponentType<PageProps> }[] = [
  { route: 'overview', label: 'Overview', page: Overview },
  { route: 'inventory', label: 'Import & scan', page: Inventory },
  { route: 'risk', label: 'Risk', page: Risk },
  { route: 'investigate', label: 'Investigate', page: Investigate },
  { route: 'compliance', label: 'Compliance evidence', page: Compliance },
  { route: 'cost', label: 'Cost', page: Cost },
  { route: 'remediation', label: 'Remediation', page: Remediation },
  { route: 'access', label: 'Access', page: Access },
  { route: 'health', label: 'System health', page: Health },
]

const TENANT_KEY = 'aegis.tenant'

function readTenant(): string {
  try {
    return localStorage.getItem(TENANT_KEY) || 'demo'
  } catch {
    return 'demo'
  }
}

export default function App() {
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const [error, setError] = useState<string | null>(null)
  const [tenant, setTenant] = useState(readTenant)
  const [me, setMe] = useState<Me | null>(null)
  const [hash, setHash] = useState(window.location.hash)
  const [ready, setReady] = useState<Readiness | null>(null)

  useEffect(() => {
    fetchAuthConfig()
      .then(async (c) => {
        setCfg(c)
        if (c.mode === 'oidc' && window.location.pathname === '/callback') {
          try {
            setSession(await completeLogin(new URLSearchParams(window.location.search), c, window.location.origin))
          } catch (e) {
            setError(describeError(e))
          }
          window.history.replaceState(null, '', '/#/overview')
          setHash('#/overview')
        }
      })
      .catch(() => setError('The Aegis API is not reachable on :8080.'))
    const onHash = () => setHash(window.location.hash)
    window.addEventListener('hashchange', onHash)
    const poll = () => fetchReadiness().then(setReady).catch(() => {})
    poll()
    const id = window.setInterval(poll, 15_000)
    return () => {
      window.removeEventListener('hashchange', onHash)
      window.clearInterval(id)
    }
  }, [])

  const signOut = () => {
    logout()
    setSession(null)
    setMe(null)
  }
  const api = useMemo(() => makeClient({ session, tenant, onUnauthenticated: signOut }), [session, tenant])

  useEffect(() => {
    if (!session) return
    api<Me>('GET', '/api/v1/me').then(setMe).catch((e) => setError(describeError(e)))
  }, [api, session])

  // Silent renewal: refresh the ID token two minutes before it expires. If
  // renewal fails, the next API call gets 401 and the user signs in again
  // (drafts of forms are kept).
  useEffect(() => {
    if (!session || cfg?.mode !== 'oidc') return
    const wait = renewIn(session)
    if (wait === null) return
    const id = window.setTimeout(() => {
      renew(session, cfg.client_id).then(setSession).catch(() => {})
    }, wait)
    return () => window.clearTimeout(id)
  }, [session, cfg])

  if (!cfg) return <div className="center">{error ?? 'Loading…'}</div>
  if (!session) return <Login cfg={cfg} error={error} onDev={(u) => setSession(devSession(u))} />
  if (!me) return <div className="center">{error ?? 'Signing in…'}</div>

  const { route, params } = parseHash(hash)
  const current = PAGES.find((p) => p.route === route) ?? PAGES[0]
  const Page = current.page
  const go = (r: string, p?: Record<string, string>) => {
    window.location.hash = hashFor(r, p)
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark" aria-hidden>◆</span> Aegis</div>
        <nav aria-label="Main">
          {PAGES.map((p) => (
            <a key={p.route} href={hashFor(p.route)} className={p.route === current.route ? 'nav-item active' : 'nav-item'}
              aria-current={p.route === current.route ? 'page' : undefined}>{p.label}</a>
          ))}
        </nav>
        <div className="whoami">
          <div className="mono small">{me.subject || '(no actor)'}</div>
          <div className="small muted">{(me.roles ?? []).join(', ') || 'no roles in this tenant'}</div>
          <label className="small muted">Tenant <input aria-label="Tenant" value={tenant} onChange={(e) => {
            const t = e.target.value.toLowerCase()
            setTenant(t)
            try { localStorage.setItem(TENANT_KEY, t) } catch { /* private mode: keep in memory */ }
          }} /></label>
          <button className="link" onClick={signOut}>Sign out</button>
        </div>
      </aside>
      <main className="content">
        <header className="topbar">
          <h1>{current.label}</h1>
          <div className={`status status-${ready?.state ?? 'loading'}`} role="status">
            <span className="dot" aria-hidden />{ready ? ({ ready: 'Operational', not_ready: 'Degraded', unreachable: 'API unreachable' })[ready.state] : 'Checking…'}
          </div>
        </header>
        {me.method === 'dev-headers' && <p className="notice small">Development mode: identities are not authenticated and every user has every permission.</p>}
        <Page key={current.route + hash} api={api} me={me} go={go} params={params} />
      </main>
    </div>
  )
}

function Login({ cfg, error, onDev }: { cfg: AuthConfig; error: string | null; onDev: (u: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  return (
    <div className="center">
      <div className="panel login">
        <div className="brand"><span className="brand-mark" aria-hidden>◆</span> Aegis</div>
        <p className="muted">Cloud governance, security, compliance and FinOps.</p>
        {cfg.mode === 'oidc' ? (
          <button className="primary" disabled={busy} onClick={async () => {
            setBusy(true)
            try {
              window.location.assign(await beginLogin(cfg, window.location.origin))
            } catch (e) {
              setErr(describeError(e))
              setBusy(false)
            }
          }}>Sign in with your identity provider</button>
        ) : (
          <>
            <p className="small">Development mode. Pick a demo identity:</p>
            <div className="stack-tight">
              {DEV_USERS.map((u) => <button key={u} onClick={() => onDev(u)}>{u}</button>)}
            </div>
          </>
        )}
        {(err ?? error) && <p className="error" role="alert">{err ?? error}</p>}
      </div>
    </div>
  )
}
