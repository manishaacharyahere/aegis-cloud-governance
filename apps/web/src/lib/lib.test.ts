import { describe, expect, it } from 'vitest'
import { niceTicks } from './ticks'
import { humanize, severityRank, toneOf } from './tones'
import { can, hashFor, parseHash, patchParams } from '../nav'
import { ago } from '../hooks'
import type { Me } from '../types'

describe('tones', () => {
  it('maps domain values to one tone each', () => {
    expect(toneOf('critical')).toBe('danger')
    expect(toneOf('high')).toBe('high')
    expect(toneOf('pending_approval')).toBe('warning')
    expect(toneOf('verified')).toBe('success')
    expect(toneOf('something-new')).toBe('neutral')
  })
  it('orders severities and puts unknown last', () => {
    const s = ['low', 'bogus', 'critical', 'medium'].sort((a, b) => severityRank(a) - severityRank(b))
    expect(s).toEqual(['critical', 'medium', 'low', 'bogus'])
    expect(humanize('verification_failed')).toBe('verification failed')
  })
})

describe('niceTicks', () => {
  it('produces clean, covering ticks', () => {
    expect(niceTicks(0)).toEqual([0])
    expect(niceTicks(NaN)).toEqual([0])
    const t = niceTicks(873)
    expect(t[0]).toBe(0)
    expect(t[t.length - 1]).toBeGreaterThanOrEqual(873)
    expect(t.length).toBeLessThanOrEqual(6)
    const step = t[1] - t[0]
    expect([1, 2, 2.5, 5].some((m) => step / 10 ** Math.floor(Math.log10(step)) === m)).toBe(true)
  })
})

describe('nav', () => {
  it('round-trips routes and parameters', () => {
    const h = hashFor('drift', { id: 'r1', category: 'security' })
    const { route, params } = parseHash(h)
    expect(route).toBe('drift')
    expect(params.get('category')).toBe('security')
    expect(parseHash('').route).toBe('overview')
  })
  it('patches parameters, dropping empty values', () => {
    const p = new URLSearchParams('type=a&environment=prod')
    expect(patchParams(p, { type: '', page: '2' })).toEqual({ environment: 'prod', page: '2' })
  })
  it('mirrors the role table', () => {
    const me = (roles: string[], method = 'oidc'): Me => ({ subject: 'x', method, roles })
    expect(can(me(['viewer']), 'operate')).toBe(false)
    expect(can(me(['analyst']), 'operate')).toBe(true)
    expect(can(me(['approver']), 'approve')).toBe(true)
    expect(can(me(['approver']), 'admin')).toBe(false)
    expect(can(me([], 'dev-headers'), 'admin')).toBe(true)
    expect(can(null, 'read')).toBe(false)
  })
})

describe('ago', () => {
  it('formats relative times', () => {
    const now = Date.parse('2026-11-17T12:00:00Z')
    expect(ago('2026-11-17T11:59:30Z', now)).toBe('30 seconds ago')
    expect(ago('2026-11-17T09:00:00Z', now)).toBe('3 hours ago')
    expect(ago('2026-11-15T12:00:00Z', now)).toBe('2 days ago')
    expect(ago(undefined, now)).toBe('—')
  })
})
