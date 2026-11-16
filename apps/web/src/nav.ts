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
