import { useEffect, useState } from 'react'
import { fetchReadiness, fetchVersion, type Readiness, type VersionInfo } from './api'

const NAV = [
  'Overview',
  'Cloud Inventory',
  'Infrastructure Scans',
  'Drift Detection',
  'Security Findings',
  'Compliance',
  'Cost Intelligence',
  'Recommendations',
  'Remediation',
  'System Health',
] as const

const POLL_MS = 10_000

const STATE_LABEL: Record<Readiness['state'], string> = {
  ready: 'Operational',
  not_ready: 'Degraded',
  unreachable: 'API unreachable',
}

export default function App() {
  const [active, setActive] = useState<(typeof NAV)[number]>('Overview')
  const [readiness, setReadiness] = useState<Readiness | null>(null)
  const [version, setVersion] = useState<VersionInfo | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    const load = () => {
      fetchReadiness(fetch, ctrl.signal).then(setReadiness).catch(() => {})
    }
    load()
    fetchVersion(fetch, ctrl.signal).then(setVersion).catch(() => {})
    const id = window.setInterval(load, POLL_MS)
    return () => {
      ctrl.abort()
      window.clearInterval(id)
    }
  }, [])

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden>◆</span> Aegis
        </div>
        <nav aria-label="Main">
          {NAV.map((item) => (
            <button
              key={item}
              className={item === active ? 'nav-item active' : 'nav-item'}
              aria-current={item === active ? 'page' : undefined}
              onClick={() => setActive(item)}
            >
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>{active}</h1>
          <div className={`status status-${readiness?.state ?? 'loading'}`} role="status">
            <span className="dot" aria-hidden />
            {readiness ? STATE_LABEL[readiness.state] : 'Checking…'}
            {version && <span className="version">v{version.version}</span>}
          </div>
        </header>

        {active === 'System Health' ? (
          <section className="panel">
            <h2>Dependencies</h2>
            {readiness && Object.keys(readiness.checks).length > 0 ? (
              <table>
                <tbody>
                  {Object.entries(readiness.checks).map(([name, state]) => (
                    <tr key={name}>
                      <td>{name}</td>
                      <td className={state === 'ok' ? 'ok' : 'bad'}>{state}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="muted">No dependency data. Is the API running on :8080?</p>
            )}
          </section>
        ) : (
          <section className="panel">
            <p className="muted">This module is not implemented yet.</p>
          </section>
        )}
      </main>
    </div>
  )
}
