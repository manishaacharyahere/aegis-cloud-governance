// Typed client for the Aegis API. Kept dependency-free on purpose.

export type ReadinessState = 'ready' | 'not_ready' | 'unreachable'

export interface Readiness {
  state: ReadinessState
  checks: Record<string, string>
}

export interface VersionInfo {
  service: string
  version: string
}

type Fetch = typeof fetch

function isRecordOfStrings(v: unknown): v is Record<string, string> {
  return (
    typeof v === 'object' &&
    v !== null &&
    Object.values(v).every((x) => typeof x === 'string')
  )
}

/** Fetches /readyz and never throws: network failures map to "unreachable". */
export async function fetchReadiness(
  fetchFn: Fetch = fetch,
  signal?: AbortSignal,
): Promise<Readiness> {
  try {
    const res = await fetchFn('/readyz', { signal, headers: { Accept: 'application/json' } })
    const body: unknown = await res.json()
    const checks =
      typeof body === 'object' && body !== null && isRecordOfStrings((body as { checks?: unknown }).checks)
        ? (body as { checks: Record<string, string> }).checks
        : {}
    return { state: res.ok ? 'ready' : 'not_ready', checks }
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    return { state: 'unreachable', checks: {} }
  }
}

export async function fetchVersion(fetchFn: Fetch = fetch, signal?: AbortSignal): Promise<VersionInfo | null> {
  try {
    const res = await fetchFn('/api/v1/version', { signal })
    if (!res.ok) return null
    const body: unknown = await res.json()
    if (
      typeof body === 'object' &&
      body !== null &&
      typeof (body as VersionInfo).service === 'string' &&
      typeof (body as VersionInfo).version === 'string'
    ) {
      return body as VersionInfo
    }
    return null
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    return null
  }
}
