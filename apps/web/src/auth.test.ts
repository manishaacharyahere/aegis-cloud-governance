import { describe, expect, it } from 'vitest'
import { beginLogin, codeChallenge, completeLogin, decodeJWT, identityHeaders, loadSession, renew, renewIn, type AuthConfig } from './auth'
import { ApiError, describeError, makeClient } from './client'
import { can, hashFor, parseHash } from './nav'

class MemStore {
  m = new Map<string, string>()
  getItem(k: string) { return this.m.get(k) ?? null }
  setItem(k: string, v: string) { this.m.set(k, v) }
  removeItem(k: string) { this.m.delete(k) }
}

const cfg: Extract<AuthConfig, { mode: 'oidc' }> = { mode: 'oidc', issuer: 'http://idp.test/dex', client_id: 'aegis-web' }
const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
const jwt = (claims: object) => `${b64({ alg: 'RS256' })}.${b64(claims)}.sig`

function idp(idToken: (nonce: string) => string) {
  const calls: { url: string; body?: string }[] = []
  let lastNonce = ''
  const fetchFn = (async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), body: init?.body?.toString() })
    if (String(url).endsWith('/.well-known/openid-configuration')) {
      return new Response(JSON.stringify({ authorization_endpoint: 'http://idp.test/dex/auth', token_endpoint: 'http://idp.test/dex/token' }))
    }
    return new Response(JSON.stringify({ id_token: idToken(lastNonce) }))
  }) as unknown as typeof fetch
  return { fetchFn, calls, setNonce: (n: string) => (lastNonce = n) }
}

describe('PKCE', () => {
  it('matches the RFC 7636 test vector', async () => {
    expect(await codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
  })
})

describe('sign-in', () => {
  it('builds an authorization request with PKCE, state and nonce', async () => {
    const store = new MemStore()
    const { fetchFn } = idp(() => '')
    const url = new URL(await beginLogin(cfg, 'http://app.test', store, fetchFn))
    expect(url.origin + url.pathname).toBe('http://idp.test/dex/auth')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('redirect_uri')).toBe('http://app.test/callback')
    const pending = JSON.parse(store.getItem('aegis.pending_login')!)
    expect(url.searchParams.get('state')).toBe(pending.state)
    expect(url.searchParams.get('nonce')).toBe(pending.nonce)
    expect(url.searchParams.get('code_challenge')).toBe(await codeChallenge(pending.verifier))
  })

  it('completes with matching state and nonce, sending the verifier', async () => {
    const store = new MemStore()
    const p = idp((n) => jwt({ email: 'alice@aegis.local', nonce: n, exp: Math.floor(Date.now() / 1000) + 3600 }))
    const url = new URL(await beginLogin(cfg, 'http://app.test', store, p.fetchFn))
    const pending = JSON.parse(store.getItem('aegis.pending_login')!)
    p.setNonce(pending.nonce)
    const s = await completeLogin(new URLSearchParams({ code: 'c1', state: url.searchParams.get('state')! }), cfg, 'http://app.test', store, p.fetchFn)
    expect(s.subject).toBe('alice@aegis.local')
    expect(p.calls[p.calls.length - 1].body).toContain(`code_verifier=${pending.verifier}`)
    expect(loadSession(store)?.token).toBe(s.token)
    expect(store.getItem('aegis.pending_login')).toBeNull()
  })

  it('rejects a state mismatch (CSRF), a nonce mismatch (replay) and a second use', async () => {
    const store = new MemStore()
    const p = idp(() => jwt({ email: 'x@y.zz', nonce: 'attacker' }))
    await beginLogin(cfg, 'http://app.test', store, p.fetchFn)
    await expect(completeLogin(new URLSearchParams({ code: 'c', state: 'forged' }), cfg, 'http://app.test', store, p.fetchFn)).rejects.toThrow(/state/)
    await expect(completeLogin(new URLSearchParams({ code: 'c', state: 'forged' }), cfg, 'http://app.test', store, p.fetchFn)).rejects.toThrow(/no sign-in/)

    const url = new URL(await beginLogin(cfg, 'http://app.test', store, p.fetchFn))
    await expect(completeLogin(new URLSearchParams({ code: 'c', state: url.searchParams.get('state')! }), cfg, 'http://app.test', store, p.fetchFn)).rejects.toThrow(/nonce/)
    expect(loadSession(store)).toBeNull()
  })

  it('surfaces identity provider errors', async () => {
    const store = new MemStore()
    store.setItem('aegis.pending_login', '{}')
    await expect(completeLogin(new URLSearchParams({ error: 'access_denied' }), cfg, 'http://app.test', store)).rejects.toThrow(/access_denied/)
  })

  it('renews silently with the refresh token, for the same person only', async () => {
    const store = new MemStore()
    const exp = Math.floor(Date.now() / 1000) + 3600
    let body = ''
    const fetchFn = (async (_u: string, init: RequestInit) => {
      body = String(init.body)
      return new Response(JSON.stringify({ id_token: jwt({ email: 'alice@aegis.local', exp }), refresh_token: 'r2' }))
    }) as unknown as typeof fetch
    const s = { mode: 'oidc' as const, token: 'old', subject: 'alice@aegis.local', refreshToken: 'r1', tokenEndpoint: 'http://idp.test/token', expiresAt: Date.now() + 60_000 }
    const next = await renew(s, 'aegis-web', store, fetchFn)
    expect(body).toContain('grant_type=refresh_token')
    expect(body).toContain('refresh_token=r1')
    expect(next.refreshToken).toBe('r2')
    expect(next.expiresAt).toBe(exp * 1000)
    expect(loadSession(store)?.token).toBe(next.token)

    const otherPerson = (async () => new Response(JSON.stringify({ id_token: jwt({ email: 'mallory@x.yz', exp }) }))) as unknown as typeof fetch
    await expect(renew(s, 'aegis-web', store, otherPerson)).rejects.toThrow(/different identity/)
    expect(renewIn(s, s.expiresAt - 600_000)).toBe(480_000)
    expect(renewIn({ mode: 'dev-headers', subject: 'x' })).toBeNull()
  })

  it('drops expired sessions', () => {
    const store = new MemStore()
    store.setItem('aegis.session', JSON.stringify({ mode: 'oidc', token: 't', subject: 's', expiresAt: 1000 }))
    expect(loadSession(store, 2000)).toBeNull()
    expect(store.getItem('aegis.session')).toBeNull()
  })

  it('decodes base64url JWT payloads', () => {
    expect(decodeJWT(jwt({ sub: 'a?b>c' })).sub).toBe('a?b>c')
  })
})

describe('client', () => {
  it('sends a bearer token in OIDC mode and the actor header only in dev mode', () => {
    expect(identityHeaders({ mode: 'oidc', token: 'T', subject: 's' })).toEqual({ Authorization: 'Bearer T' })
    expect(identityHeaders({ mode: 'dev-headers', actor: 'a@b.cc', subject: 'a@b.cc' })).toEqual({ 'X-Aegis-Actor': 'a@b.cc' })
    expect(identityHeaders(null)).toEqual({})
  })

  it('adds tenant and identity, and maps API errors', async () => {
    let seen: Headers | undefined
    let signedOut = false
    const fetchFn = (async (_u: string, init: RequestInit) => {
      seen = new Headers(init.headers)
      return new Response(JSON.stringify({ error: { code: 'forbidden', message: 'your roles do not allow this' } }), { status: 403 })
    }) as unknown as typeof fetch
    const api = makeClient({ session: { mode: 'oidc', token: 'T', subject: 's' }, tenant: 'demo', fetchFn, onUnauthenticated: () => (signedOut = true) })
    const err = await api('POST', '/api/v1/x', { a: 1 }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(403)
    expect(describeError(err)).toMatch(/Not permitted/)
    expect(seen?.get('Authorization')).toBe('Bearer T')
    expect(seen?.get('X-Aegis-Tenant')).toBe('demo')
    expect(seen?.get('Content-Type')).toBe('application/json')
    expect(signedOut).toBe(false)

    const unauth = makeClient({ session: null, tenant: 'demo', onUnauthenticated: () => (signedOut = true),
      fetchFn: (async () => new Response('{}', { status: 401 })) as unknown as typeof fetch })
    await unauth('GET', '/x').catch(() => {})
    expect(signedOut).toBe(true)
  })
})

describe('navigation and roles', () => {
  it('round-trips routes with parameters', () => {
    const h = hashFor('remediation', { propose: '1', rule: 'AEGIS-S3-001', resource: 'aws_s3_bucket.a' })
    const { route, params } = parseHash(h)
    expect(route).toBe('remediation')
    expect(params.get('resource')).toBe('aws_s3_bucket.a')
    expect(parseHash('').route).toBe('overview')
  })

  it('mirrors the API role table', () => {
    const me = (roles: string[]) => ({ subject: 's', method: 'oidc', roles })
    expect(can(me(['viewer']), 'operate')).toBe(false)
    expect(can(me(['analyst']), 'operate')).toBe(true)
    expect(can(me(['analyst']), 'approve')).toBe(false)
    expect(can(me(['approver']), 'approve')).toBe(true)
    expect(can(me(['approver']), 'operate')).toBe(false)
    expect(can(me(['admin']), 'admin')).toBe(true)
    expect(can({ subject: '', method: 'dev-headers' }, 'admin')).toBe(true)
    expect(can(null, 'read')).toBe(false)
  })
})
