import { describe, expect, it } from 'vitest'
import { fetchReadiness, fetchVersion } from './api'

const jsonResponse = (status: number, body: unknown) =>
  (async () => new Response(JSON.stringify(body), { status })) as unknown as typeof fetch

describe('fetchReadiness', () => {
  it('reports ready with checks', async () => {
    const r = await fetchReadiness(jsonResponse(200, { status: 'ready', checks: { database: 'ok' } }))
    expect(r).toEqual({ state: 'ready', checks: { database: 'ok' } })
  })

  it('reports not_ready on 503', async () => {
    const r = await fetchReadiness(jsonResponse(503, { status: 'not_ready', checks: { database: 'unavailable' } }))
    expect(r.state).toBe('not_ready')
    expect(r.checks.database).toBe('unavailable')
  })

  it('maps network errors to unreachable', async () => {
    const failing = (async () => {
      throw new TypeError('fetch failed')
    }) as unknown as typeof fetch
    expect(await fetchReadiness(failing)).toEqual({ state: 'unreachable', checks: {} })
  })

  it('ignores malformed check payloads', async () => {
    const r = await fetchReadiness(jsonResponse(200, { checks: { database: 42 } }))
    expect(r.checks).toEqual({})
  })
})

describe('fetchVersion', () => {
  it('parses a valid payload', async () => {
    expect(await fetchVersion(jsonResponse(200, { service: 'aegis-api', version: '1.2.3' }))).toEqual({
      service: 'aegis-api',
      version: '1.2.3',
    })
  })

  it('returns null for errors and bad shapes', async () => {
    expect(await fetchVersion(jsonResponse(500, {}))).toBeNull()
    expect(await fetchVersion(jsonResponse(200, { version: 1 }))).toBeNull()
  })
})
