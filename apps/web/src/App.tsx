import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from 'react'
import {
  Activity, BadgeDollarSign, Boxes, ChevronDown, GitCompareArrows, KeyRound, LayoutDashboard, LogOut, Menu,
  Radar, ScanSearch, ShieldCheck, ShieldHalf, Wrench, X,
} from 'lucide-react'
import { fetchReadiness, type Readiness } from './api'
import { DEV_USERS, beginLogin, completeLogin, devSession, fetchAuthConfig, loadSession, logout, logoutURL, renew, renewIn, type AuthConfig, type Session } from './auth'
import { describeError, makeClient } from './client'
import { hashFor, parseHash, type PageProps } from './nav'
import type { Me, Membership } from './types'
import { Button, Callout, ErrorBoundary, Select, Skeleton, ThemeToggle, Toaster, type ThemeChoice } from '@/components/ui'
import { cn } from '@/lib/utils'

// Each page is its own chunk, loaded on first visit.
const Overview = lazy(() => import('./pages/Overview'))
const Inventory = lazy(() => import('./pages/Inventory'))
const Drift = lazy(() => import('./pages/Drift'))
const Risk = lazy(() => import('./pages/Risk'))
const Investigate = lazy(() => import('./pages/Investigate'))
const Compliance = lazy(() => import('./pages/Compliance'))
const Remediation = lazy(() => import('./pages/Remediation'))
const Cost = lazy(() => import('./pages/Cost'))
const Access = lazy(() => import('./pages/Admin').then((m) => ({ default: m.Access })))
const Health = lazy(() => import('./pages/Admin').then((m) => ({ default: m.Health })))

type PageDef = { route: string; label: string; icon: ReactNode; page: ComponentType<PageProps>; description: string }

const GROUPS: { label: string; pages: PageDef[] }[] = [
  { label: 'Operate', pages: [
    { route: 'overview', label: 'Overview', icon: <LayoutDashboard />, page: Overview, description: 'What needs attention across security, compliance and cost.' },
    { route: 'inventory', label: 'Import & scan', icon: <Boxes />, page: Inventory, description: 'Cloud inventory and pre-apply Terraform scans.' },
    { route: 'drift', label: 'Drift', icon: <GitCompareArrows />, page: Drift, description: 'Differences between the approved baseline and the latest import.' },
  ] },
  { label: 'Assess', pages: [
    { route: 'risk', label: 'Risk', icon: <Radar />, page: Risk, description: 'Failing findings ranked by contextual risk, and attack paths.' },
    { route: 'investigate', label: 'Investigate', icon: <ScanSearch />, page: Investigate, description: 'Evidence-cited investigation of one resource.' },
    { route: 'compliance', label: 'Compliance evidence', icon: <ShieldCheck />, page: Compliance, description: 'Control coverage, evidence and exceptions.' },
  ] },
  { label: 'Act', pages: [
    { route: 'remediation', label: 'Remediation', icon: <Wrench />, page: Remediation, description: 'Simulated, approved and signed change sets.' },
    { route: 'cost', label: 'Cost', icon: <BadgeDollarSign />, page: Cost, description: 'Spend, anomalies, forecast and savings.' },
  ] },
  { label: 'Admin', pages: [
    { route: 'access', label: 'Access', icon: <KeyRound />, page: Access, description: 'Who can do what in this tenant.' },
    { route: 'health', label: 'System health', icon: <Activity />, page: Health, description: 'Dependencies and your session.' },
  ] },
]
const PAGES = GROUPS.flatMap((g) => g.pages)

const TENANT_KEY = 'aegis.tenant'
const THEME_KEY = 'aegis.theme'

function readStore(key: string, fallback: string): string {
  try {
    return localStorage.getItem(key) || fallback
  } catch {
    return fallback
  }
}
function saveStore(key: string, value: string) {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* private mode: keep in memory */
  }
}

/** Applies the theme to <html data-theme>, following the system when asked. */
function useTheme(): [ThemeChoice, (t: ThemeChoice) => void] {
  const [choice, setChoice] = useState<ThemeChoice>(() => readStore(THEME_KEY, 'system') as ThemeChoice)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: light)')
    const apply = () => {
      document.documentElement.dataset.theme = choice === 'system' ? (mq.matches ? 'light' : 'dark') : choice
    }
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [choice])
  return [choice, (t) => { setChoice(t); saveStore(THEME_KEY, t) }]
}

export default function App() {
  return <Toaster><Shell /></Toaster>
}

function Shell() {
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const [error, setError] = useState<string | null>(null)
  const [tenant, setTenant] = useState(() => readStore(TENANT_KEY, 'demo'))
  const [me, setMe] = useState<Me | null>(null)
  const [meError, setMeError] = useState<unknown>(null)
  const [meTick, setMeTick] = useState(0)
  const [tenants, setTenants] = useState<Membership[] | null>(null)
  const [tenantsError, setTenantsError] = useState(false)
  const [hash, setHash] = useState(window.location.hash)
  const [ready, setReady] = useState<Readiness | null>(null)
  const [theme, setTheme] = useTheme()
  const [navOpen, setNavOpen] = useState(false)
  const callbackDone = useRef(false)
  const drawer = useRef<HTMLElement>(null)
  const openNav = useRef<HTMLButtonElement>(null)
  const closeNav = useRef<HTMLButtonElement>(null)

  // Mobile drawer: focus moves in when it opens, Escape closes it, Tab stays
  // inside, and focus returns to the menu button when it closes.
  const wasOpen = useRef(false)
  useEffect(() => {
    if (navOpen) {
      wasOpen.current = true
      closeNav.current?.focus()
      const onKey = (e: KeyboardEvent) => {
        if (e.key === 'Escape') setNavOpen(false)
        if (e.key !== 'Tab' || !drawer.current) return
        const items = drawer.current.querySelectorAll<HTMLElement>('a[href],button:not([disabled])')
        const first = items[0]
        const last = items[items.length - 1]
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last?.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first?.focus()
        }
      }
      document.addEventListener('keydown', onKey)
      return () => document.removeEventListener('keydown', onKey)
    }
    if (wasOpen.current) {
      wasOpen.current = false
      openNav.current?.focus()
    }
  }, [navOpen])

  useEffect(() => {
    fetchAuthConfig()
      .then(async (c) => {
        setCfg(c)
        // StrictMode runs effects twice in development; complete the login once.
        if (c.mode === 'oidc' && window.location.pathname === '/callback' && !callbackDone.current) {
          callbackDone.current = true
          try {
            setSession(await completeLogin(new URLSearchParams(window.location.search), c, window.location.origin))
            setError(null)
          } catch (e) {
            setError(describeError(e))
          }
          window.history.replaceState(null, '', '/#/overview')
          setHash('#/overview')
        }
      })
      .catch(() => setError('The Aegis API is not reachable on :8080.'))
    const onHash = () => {
      setHash(window.location.hash)
      setNavOpen(false)
    }
    window.addEventListener('hashchange', onHash)
    // Store only a changed state: every new object would re-render the page.
    const poll = () => fetchReadiness().then((r) => setReady((prev) => (prev && JSON.stringify(prev) === JSON.stringify(r) ? prev : r))).catch(() => {})
    poll()
    const id = window.setInterval(poll, 15_000)
    return () => {
      window.removeEventListener('hashchange', onHash)
      window.clearInterval(id)
    }
  }, [])

  // A 401 signs out locally; the Sign out button also ends the identity
  // provider's session, so the next sign-in asks for credentials again.
  const signOut = useCallback(() => {
    logout()
    setSession(null)
    setMe(null)
    setMeError(null)
    setTenants(null)
  }, [])
  const signOutEverywhere = useCallback(() => {
    const url = cfg?.mode === 'oidc' ? logoutURL(session, cfg.client_id, window.location.origin) : null
    signOut()
    if (url) window.location.assign(url)
  }, [cfg, session, signOut])
  // The client reads the session at call time, so a silent token renewal
  // does not create a new client (which would refetch every page).
  const [box] = useState(() => new SessionBox(session))
  useEffect(() => {
    box.set(session)
  })
  const who = session ? `${session.mode}:${session.subject}` : ''
  const api = useMemo(() => makeClient({ session: box.get, tenant, onUnauthenticated: signOut }),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- a new client per signed-in user and tenant
    [who, tenant, signOut])

  // Who am I in this tenant. A late response for a previous tenant is ignored.
  useEffect(() => {
    if (!session) return
    let live = true
    api<Me>('GET', '/api/v1/me').then(
      (m) => live && (setMe(m), setMeError(null)),
      (e) => live && setMeError(e),
    )
    return () => {
      live = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- api changes with the user and tenant
  }, [api, meTick])

  // The tenants this user holds a role in. If the remembered tenant is not one
  // of them, switch to the first, so nobody lands on an empty tenant.
  useEffect(() => {
    if (!session) return
    api<{ items: Membership[] }>('GET', '/api/v1/me/tenants').then((r) => {
      setTenants(r.items)
      setTenantsError(false)
      if (r.items.length > 0 && !r.items.some((m) => m.slug === tenant)) {
        setTenant(r.items[0].slug)
        saveStore(TENANT_KEY, r.items[0].slug)
      }
    }).catch(() => setTenantsError(true))
    // Only on sign-in: switching tenants or renewing the token must not refetch the list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [who])

  // Silent renewal: refresh the ID token two minutes before it expires.
  useEffect(() => {
    if (!session || cfg?.mode !== 'oidc') return
    const wait = renewIn(session)
    if (wait === null) return
    const id = window.setTimeout(() => {
      renew(session, cfg.client_id).then(setSession).catch(() => {})
    }, wait)
    return () => window.clearTimeout(id)
  }, [session, cfg])

  if (!cfg) return <Centered>{error ? <Callout tone="danger" title="Cannot reach Aegis">{error}</Callout> : <Brand muted />}</Centered>
  if (!session) return <Login cfg={cfg} error={error} onDev={(u) => setSession(devSession(u))} />
  if (!me) {
    return (
      <Centered>
        {meError ? (
          <div className="flex w-[min(420px,100%)] flex-col gap-3">
            <Callout tone="danger" title="Could not load your session">{describeError(meError)}</Callout>
            <div className="flex gap-2">
              <Button variant="primary" onClick={() => { setMeError(null); setMeTick((t) => t + 1) }}>Retry</Button>
              <Button onClick={signOutEverywhere}><LogOut />Sign out</Button>
            </div>
          </div>
        ) : <p className="text-fg-muted">Signing in…</p>}
      </Centered>
    )
  }

  const { route, params } = parseHash(hash)
  const current = PAGES.find((p) => p.route === route) ?? PAGES[0]
  const Page = current.page
  const go = (r: string, p?: Record<string, string>) => {
    window.location.hash = hashFor(r, p)
  }
  const switchTenant = (t: string) => {
    setTenant(t)
    saveStore(TENANT_KEY, t)
    setMe(null)
  }

  return (
    <div className="min-h-dvh bg-bg lg:grid lg:grid-cols-[232px_1fr]">
      <a href="#main" onClick={(e) => {
        e.preventDefault() // the hash is the route: do not navigate
        document.getElementById('main')?.focus()
      }} className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-surface focus:px-3 focus:py-2">Skip to content</a>
      {navOpen && <div className="fixed inset-0 z-30 bg-overlay lg:hidden" onClick={() => setNavOpen(false)} aria-hidden />}
      <aside className={cn('sidebar fixed inset-y-0 left-0 z-40 flex w-[232px] flex-col border-r border-border bg-surface transition-transform duration-200 lg:sticky lg:top-0 lg:h-dvh lg:translate-x-0',
        navOpen ? 'translate-x-0' : '-translate-x-full max-lg:invisible')}
        ref={drawer} aria-modal={navOpen || undefined} role={navOpen ? 'dialog' : undefined} aria-label={navOpen ? 'Navigation' : undefined}>
        <div className="flex h-14 items-center justify-between px-4">
          <Brand />
          <Button ref={closeNav} variant="ghost" size="icon" className="lg:hidden" onClick={() => setNavOpen(false)} aria-label="Close navigation"><X /></Button>
        </div>
        <nav aria-label="Main" className="flex-1 space-y-5 overflow-y-auto px-3 pb-4 pt-2">
          {GROUPS.map((g) => (
            <div key={g.label}>
              <div className="px-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-fg-subtle">{g.label}</div>
              <ul className="m-0 list-none space-y-0.5 p-0">
                {g.pages.map((p) => {
                  const on = p.route === current.route
                  return (
                    <li key={p.route}>
                      <a href={hashFor(p.route)} aria-current={on ? 'page' : undefined}
                        className={cn('nav-item relative flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13.5px] no-underline transition-colors [&_svg]:size-4',
                          on ? 'bg-accent-soft font-medium text-fg [&_svg]:text-accent' : 'text-fg-muted hover:bg-surface-2 hover:text-fg')}>
                        {on && <span className="absolute inset-y-1.5 -left-3 w-[3px] rounded-r-full bg-accent" aria-hidden />}
                        {p.icon}{p.label}
                      </a>
                    </li>
                  )
                })}
              </ul>
            </div>
          ))}
        </nav>
        <div className="border-t border-border px-4 py-3 text-[11.5px] text-fg-subtle">
          Local-first cloud governance
        </div>
      </aside>

      <div className="min-w-0">
        <header className="topbar sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur md:px-6">
          <Button ref={openNav} variant="ghost" size="icon" className="lg:hidden" onClick={() => setNavOpen(true)} aria-label="Open navigation"><Menu /></Button>
          <div className="min-w-0 flex-1">
            <h1 className="m-0 truncate text-[17px] font-semibold tracking-tight">{current.label}</h1>
          </div>
          <StatusPill ready={ready} />
          <ThemeToggle value={theme} onChange={setTheme} />
          <UserMenu me={me} tenant={tenant} tenants={tenants} tenantsError={tenantsError} onTenant={switchTenant} onSignOut={signOutEverywhere} />
        </header>
        <main id="main" tabIndex={-1} className="outline-none mx-auto w-full max-w-[1400px] px-4 py-5 md:px-6 md:py-6">
          <p className="mb-4 mt-0 text-[13px] text-fg-muted">{current.description}</p>
          {me.method === 'dev-headers' && (
            <Callout tone="warning" className="mb-4" title="Development mode">Identities are not authenticated and every user has every permission. Use OIDC mode for anything shared.</Callout>
          )}
          <ErrorBoundary key={current.route + tenant}>
            <Suspense fallback={<Skeleton rows={6} />}>
              <Page key={current.route + tenant} api={api} me={me} go={go} params={params} />
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}

function Brand({ muted }: { muted?: boolean }) {
  return (
    <div className={cn('brand flex items-center gap-2 text-[15px] font-semibold tracking-tight', muted && 'animate-pulse text-fg-muted')}>
      <span className="flex size-7 items-center justify-center rounded-md bg-accent-soft text-accent"><ShieldHalf className="size-4" aria-hidden /></span>
      Aegis
    </div>
  )
}

/** Holds the current session for the API client outside React state. */
class SessionBox {
  private s: Session | null
  constructor(s: Session | null) {
    this.s = s
  }
  set(s: Session | null) {
    this.s = s
  }
  get = () => this.s
}

function Centered({ children }: { children: ReactNode }) {
  return <div className="center flex min-h-dvh items-center justify-center bg-bg p-4">{children}</div>
}

function StatusPill({ ready }: { ready: Readiness | null }) {
  const state = ready?.state ?? 'loading'
  const text = ready ? ({ ready: 'Operational', not_ready: 'Degraded', unreachable: 'API unreachable' })[ready.state] : 'Checking…'
  const dot = { ready: 'bg-success', not_ready: 'bg-warning', unreachable: 'bg-danger', loading: 'bg-fg-subtle' }[state]
  return (
    <a href={hashFor('health')} className="hidden items-center gap-2 rounded-full border border-border px-2.5 py-1 text-xs text-fg-muted no-underline hover:border-border-strong sm:flex">
      <span className="relative flex size-2">
        {state === 'ready' && <span className="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-40 motion-reduce:animate-none" />}
        <span className={cn('relative inline-flex size-2 rounded-full', dot)} />
      </span>
      <span role="status">{text}</span>
    </a>
  )
}

function UserMenu({ me, tenant, tenants, tenantsError, onTenant, onSignOut }: {
  me: Me; tenant: string; tenants: Membership[] | null; tenantsError: boolean; onTenant: (t: string) => void; onSignOut: () => void
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !ref.current?.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])
  const initials = (me.subject || '?').slice(0, 2).toUpperCase()
  return (
    <div ref={ref} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="true"
        aria-label={`User menu: ${me.subject}, tenant ${tenant}`}
        className="flex items-center gap-2 rounded-md px-1.5 py-1 text-left hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <span className="flex size-7 items-center justify-center rounded-full bg-surface-3 text-[11px] font-semibold">{initials}</span>
        <span className="hidden min-w-0 md:block">
          <span className="block max-w-[180px] truncate text-[12.5px] font-medium leading-4">{me.subject}</span>
          <span className="block text-[11px] leading-4 text-fg-subtle">{tenant} · {(me.roles ?? []).join(', ') || 'no role'}</span>
        </span>
        <ChevronDown className="size-3.5 text-fg-subtle" aria-hidden />
      </button>
      <div hidden={!open} className="absolute right-0 top-full z-30 mt-1.5 w-[280px] rounded-lg border border-border bg-surface p-3 shadow-card">
        <div className="whoami">
          <div className="truncate text-[13px] font-medium">{me.subject || '(no actor)'}</div>
          <div className="text-xs text-fg-subtle">{(me.roles ?? []).join(', ') || 'no roles in this tenant'} · {me.method === 'oidc' ? 'OIDC' : 'development headers'}</div>
          <div className="mt-3">
            {tenants && tenants.length > 0 ? (
              <label className="block text-[12px] font-medium text-fg-muted">Tenant
                <Select aria-label="Tenant" className="mt-1 w-full" value={tenant} onChange={(e) => { setOpen(false); onTenant(e.target.value) }}>
                  {tenants.map((m) => <option key={m.slug} value={m.slug}>{m.name === m.slug ? m.slug : `${m.name} (${m.slug})`}</option>)}
                </Select>
              </label>
            ) : (
              <p className="m-0 text-xs text-fg-muted">
                {tenantsError ? 'Could not load your tenants; reload to try again.' : tenants ? 'You have no role in any tenant yet. Ask an administrator.' : 'Loading tenants…'}
              </p>
            )}
          </div>
          <Button className="mt-3 w-full" onClick={onSignOut}><LogOut />Sign out</Button>
        </div>
      </div>
    </div>
  )
}

function Login({ cfg, error, onDev }: { cfg: AuthConfig; error: string | null; onDev: (u: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  return (
    <Centered>
      <div className="w-[min(400px,100%)] rounded-xl border border-border bg-surface p-7 shadow-card">
        <Brand />
        <p className="mb-6 mt-3 text-[13.5px] text-fg-muted">Cloud governance, security, compliance and FinOps, from evidence you can verify.</p>
        {cfg.mode === 'oidc' ? (
          <Button variant="primary" size="lg" className="w-full" loading={busy} onClick={async () => {
            setBusy(true)
            try {
              window.location.assign(await beginLogin(cfg, window.location.origin))
            } catch (e) {
              setErr(describeError(e))
              setBusy(false)
            }
          }}>Sign in with your identity provider</Button>
        ) : (
          <>
            <p className="mb-2 mt-0 text-[12.5px] font-medium text-fg-muted">Development mode. Pick a demo identity:</p>
            <div className="grid gap-1.5">
              {DEV_USERS.map((u) => <Button key={u} className="justify-start" onClick={() => onDev(u)}>{u}</Button>)}
            </div>
          </>
        )}
        {(err ?? error) && <Callout tone="danger" className="mt-4">{err ?? error}</Callout>}
      </div>
    </Centered>
  )
}
