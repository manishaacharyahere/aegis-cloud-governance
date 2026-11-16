// Sign-in for the dashboard.
//
// OIDC mode: authorization code flow with PKCE (S256), a random state (CSRF)
// and nonce (replay) per attempt. The ID token is kept in sessionStorage, so
// it is scoped to the tab and gone when the tab closes. The API verifies the
// token's signature, issuer, audience and expiry on every request; the
// dashboard only checks state and nonce.
//
// Development mode (the API's dev-headers mode): the user picks a demo
// identity, sent as X-Aegis-Actor. The API refuses this mode in production.

export type AuthConfig =
  | { mode: 'oidc'; issuer: string; client_id: string }
  | { mode: 'dev-headers' }

export interface Session {
  mode: 'oidc' | 'dev-headers'
  token?: string // OIDC ID token
  actor?: string // dev mode identity
  subject: string
  expiresAt?: number // epoch ms
  refreshToken?: string // used to renew the ID token silently
  tokenEndpoint?: string
}

const TOKEN_KEY = 'aegis.session'
const PENDING_KEY = 'aegis.pending_login'
export const DEV_USERS = ['admin@aegis.local', 'alice@aegis.local', 'bob@aegis.local', 'carol@aegis.local', 'viewer@aegis.local']

type Storage = Pick<globalThis.Storage, 'getItem' | 'setItem' | 'removeItem'>

export async function fetchAuthConfig(fetchFn: typeof fetch = fetch): Promise<AuthConfig> {
  const res = await fetchFn('/api/v1/auth/config')
  if (!res.ok) throw new Error(`auth config: HTTP ${res.status}`)
  const body = (await res.json()) as Partial<AuthConfig & { issuer: string; client_id: string }>
  if (body.mode === 'oidc' && typeof body.issuer === 'string' && typeof body.client_id === 'string') {
    return { mode: 'oidc', issuer: body.issuer, client_id: body.client_id }
  }
  return { mode: 'dev-headers' }
}

export function randomString(bytes = 32): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return base64url(buf)
}

export function base64url(buf: Uint8Array): string {
  let s = ''
  for (const b of buf) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** RFC 7636 S256 code challenge. */
export async function codeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

interface Discovery {
  authorization_endpoint: string
  token_endpoint: string
  end_session_endpoint?: string
}

async function discover(issuer: string, fetchFn: typeof fetch): Promise<Discovery> {
  const res = await fetchFn(issuer.replace(/\/$/, '') + '/.well-known/openid-configuration')
  if (!res.ok) throw new Error(`identity provider discovery failed: HTTP ${res.status}`)
  return (await res.json()) as Discovery
}

export function redirectURI(origin: string): string {
  return origin + '/callback'
}

/** Starts sign-in: stores verifier/state/nonce and returns the authorize URL. */
export async function beginLogin(cfg: Extract<AuthConfig, { mode: 'oidc' }>, origin: string, store: Storage = sessionStorage,
  fetchFn: typeof fetch = fetch): Promise<string> {
  const d = await discover(cfg.issuer, fetchFn)
  const verifier = randomString(48)
  const state = randomString(16)
  const nonce = randomString(16)
  store.setItem(PENDING_KEY, JSON.stringify({ verifier, state, nonce, token_endpoint: d.token_endpoint }))
  const u = new URL(d.authorization_endpoint)
  u.searchParams.set('response_type', 'code')
  u.searchParams.set('client_id', cfg.client_id)
  u.searchParams.set('redirect_uri', redirectURI(origin))
  u.searchParams.set('scope', 'openid email profile offline_access')
  u.searchParams.set('state', state)
  u.searchParams.set('nonce', nonce)
  u.searchParams.set('code_challenge', await codeChallenge(verifier))
  u.searchParams.set('code_challenge_method', 'S256')
  return u.toString()
}

export function decodeJWT(token: string): Record<string, unknown> {
  const part = token.split('.')[1]
  if (!part) throw new Error('malformed token')
  const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(json) as Record<string, unknown>
}

/** Completes sign-in on /callback. Rejects a missing or mismatched state or nonce. */
export async function completeLogin(params: URLSearchParams, cfg: Extract<AuthConfig, { mode: 'oidc' }>, origin: string,
  store: Storage = sessionStorage, fetchFn: typeof fetch = fetch): Promise<Session> {
  const raw = store.getItem(PENDING_KEY)
  store.removeItem(PENDING_KEY) // one attempt only
  if (params.get('error')) throw new Error(`sign-in failed: ${params.get('error_description') ?? params.get('error')}`)
  if (!raw) throw new Error('no sign-in in progress')
  const pending = JSON.parse(raw) as { verifier: string; state: string; nonce: string; token_endpoint: string }
  if (!params.get('state') || params.get('state') !== pending.state) throw new Error('sign-in state mismatch')
  const code = params.get('code')
  if (!code) throw new Error('no authorization code')
  const res = await fetchFn(pending.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: redirectURI(origin), client_id: cfg.client_id,
      code_verifier: pending.verifier,
    }),
  })
  if (!res.ok) throw new Error(`token exchange failed: HTTP ${res.status}`)
  const body = (await res.json()) as { id_token?: string; refresh_token?: string }
  if (!body.id_token) throw new Error('no ID token returned')
  const claims = decodeJWT(body.id_token)
  if (claims.nonce !== pending.nonce) throw new Error('sign-in nonce mismatch')
  const session: Session = {
    mode: 'oidc', token: body.id_token,
    subject: String(claims.email ?? claims.sub ?? ''),
    expiresAt: typeof claims.exp === 'number' ? claims.exp * 1000 : undefined,
    refreshToken: body.refresh_token, tokenEndpoint: pending.token_endpoint,
  }
  store.setItem(TOKEN_KEY, JSON.stringify(session))
  return session
}

/** Renews the ID token with the refresh token. The new token must be for the
 * same person; otherwise the renewal is refused. */
export async function renew(s: Session, clientID: string, store: Storage = sessionStorage, fetchFn: typeof fetch = fetch): Promise<Session> {
  if (s.mode !== 'oidc' || !s.refreshToken || !s.tokenEndpoint) throw new Error('this session cannot be renewed')
  const res = await fetchFn(s.tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: s.refreshToken, client_id: clientID }),
  })
  if (!res.ok) throw new Error(`renewal failed: HTTP ${res.status}`)
  const body = (await res.json()) as { id_token?: string; refresh_token?: string }
  if (!body.id_token) throw new Error('renewal returned no ID token')
  const claims = decodeJWT(body.id_token)
  const subject = String(claims.email ?? claims.sub ?? '')
  if (subject !== s.subject) throw new Error('renewal returned a different identity')
  const next: Session = {
    ...s, token: body.id_token, refreshToken: body.refresh_token ?? s.refreshToken,
    expiresAt: typeof claims.exp === 'number' ? claims.exp * 1000 : undefined,
  }
  store.setItem(TOKEN_KEY, JSON.stringify(next))
  return next
}

/** Milliseconds until a session should be renewed (two minutes early). */
export function renewIn(s: Session, now = Date.now()): number | null {
  if (s.mode !== 'oidc' || !s.refreshToken || !s.expiresAt) return null
  return Math.max(5_000, s.expiresAt - now - 120_000)
}

export function devSession(actor: string, store: Storage = sessionStorage): Session {
  const s: Session = { mode: 'dev-headers', actor, subject: actor }
  store.setItem(TOKEN_KEY, JSON.stringify(s))
  return s
}

export function loadSession(store: Storage = sessionStorage, now = Date.now()): Session | null {
  const raw = store.getItem(TOKEN_KEY)
  if (!raw) return null
  try {
    const s = JSON.parse(raw) as Session
    if (s.expiresAt && s.expiresAt <= now + 30_000) {
      store.removeItem(TOKEN_KEY)
      return null
    }
    return s
  } catch {
    store.removeItem(TOKEN_KEY)
    return null
  }
}

export function logout(store: Storage = sessionStorage): void {
  store.removeItem(TOKEN_KEY)
  store.removeItem(PENDING_KEY)
}

/** Headers that identify the caller to the API. */
export function identityHeaders(s: Session | null): Record<string, string> {
  if (!s) return {}
  if (s.mode === 'oidc' && s.token) return { Authorization: `Bearer ${s.token}` }
  if (s.mode === 'dev-headers' && s.actor) return { 'X-Aegis-Actor': s.actor }
  return {}
}
