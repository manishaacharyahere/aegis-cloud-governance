// Authenticated JSON client for the Aegis API.
import { identityHeaders, type Session } from './auth'

export class ApiError extends Error {
  status: number
  code: string
  details?: unknown
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

export interface ClientOptions {
  /** The session, or a function returning the current one (so a renewed
   * token is used without creating a new client). */
  session: Session | null | (() => Session | null)
  tenant: string
  fetchFn?: typeof fetch
  onUnauthenticated?: () => void
}

export type Client = <T>(method: string, path: string, body?: unknown) => Promise<T>

export function makeClient(o: ClientOptions): Client {
  const fetchFn = o.fetchFn ?? fetch
  return async <T,>(method: string, path: string, body?: unknown): Promise<T> => {
    const session = typeof o.session === 'function' ? o.session() : o.session
    const headers: Record<string, string> = { Accept: 'application/json', 'X-Aegis-Tenant': o.tenant, ...identityHeaders(session) }
    let payload: BodyInit | undefined
    if (typeof body === 'string') {
      payload = body
      headers['Content-Type'] = 'text/csv'
    } else if (body !== undefined) {
      payload = JSON.stringify(body)
      headers['Content-Type'] = 'application/json'
    }
    const res = await fetchFn(path, { method, headers, body: payload })
    if (res.status === 204) return undefined as T
    let data: unknown = null
    const text = await res.text()
    if (text) {
      try {
        data = JSON.parse(text)
      } catch {
        data = text
      }
    }
    if (!res.ok) {
      const err = (data as { error?: { code?: string; message?: string; issues?: unknown; rows?: unknown } } | null)?.error
      if (res.status === 401) o.onUnauthenticated?.()
      // issues: inventory validation; rows: cost import.
      throw new ApiError(res.status, err?.code ?? 'http_error', err?.message ?? `HTTP ${res.status}`, err?.issues ?? err?.rows)
    }
    return data as T
  }
}

/** A short, human explanation for an API error. */
export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.status) {
      case 401:
        return 'Your session has expired. Sign in again.'
      case 403:
        return `Not permitted: ${e.message}`
      case 503:
        return `Service unavailable: ${e.message}`
      default:
        return e.message
    }
  }
  return e instanceof Error ? e.message : String(e)
}

/** A query string from values that may come from the URL: encoded, empty
 * values left out. qs({ status: 'open', after: '' }) === '?status=open'. */
export function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') p.set(k, String(v))
  const s = p.toString()
  return s ? `?${s}` : ''
}

/** One encoded path segment (an id or name that may come from the URL). */
export const seg = (v: string) => encodeURIComponent(v)

/** Resolves to null when the API answers 404 (nothing recorded yet). */
export async function notFoundAsNull<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null
    throw e
  }
}
