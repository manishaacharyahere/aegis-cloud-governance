import type { Client } from './client'
import type { Me } from './types'

export interface PageProps {
  api: Client
  me: Me
  go: (route: string, params?: Record<string, string>) => void
  params: URLSearchParams
}

type Perm = 'read' | 'operate' | 'approve' | 'admin'

const GRANTS: Record<string, Perm[]> = {
  viewer: ['read'],
  analyst: ['read', 'operate'],
  approver: ['read', 'approve'],
  admin: ['read', 'operate', 'approve', 'admin'],
}

/** Mirrors the API's role table so buttons a user cannot use are hidden; the API still enforces it. */
export function can(me: Me | null, perm: Perm): boolean {
  if (!me) return false
  if (me.method === 'dev-headers') return true
  return (me.roles ?? []).some((r) => GRANTS[r]?.includes(perm))
}

/** Parses "#/route?x=y" into a route and its parameters. */
export function parseHash(hash: string): { route: string; params: URLSearchParams } {
  const h = hash.replace(/^#\/?/, '')
  const [route, query = ''] = h.split('?')
  return { route: route || 'overview', params: new URLSearchParams(query) }
}

export function hashFor(route: string, params?: Record<string, string>): string {
  const q = params ? new URLSearchParams(params).toString() : ''
  return `#/${route}${q ? '?' + q : ''}`
}

/** The URL parameters for route after applying patch to the current ones
 * (empty values are dropped), so filters live in the URL: bookmarkable, and
 * Back works. */
export function patchParams(params: URLSearchParams, patch: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  params.forEach((v, k) => {
    out[k] = v
  })
  for (const [k, v] of Object.entries(patch)) {
    if (v) out[k] = v
    else delete out[k]
  }
  return out
}
