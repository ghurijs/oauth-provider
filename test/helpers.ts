import {
  AuthConfig,
  AuthenticationMiddleware,
  authUrls,
  ContentType,
  ContentTypesConfig,
  PBKDF2PasswordHasher,
  SessionMiddleware,
  SessionsConfig,
  User,
} from '@ghuri/auth'
import {
  CsrfMiddleware,
  caches,
  createApp,
  defineSettings,
  type GhuriApp,
  include,
  path,
  type UrlEntry,
} from '@ghuri/core'
import { createTestClient, type TestClient } from '@ghuri/core/testing'
import { pkcePair, setProviderFetch } from '@ghuri/oauth'
import { setupTestDatabase, type TestBackend, type TestDatabase } from '@ghuri/orm/testing'
import { afterAll, beforeAll, beforeEach, expect } from 'vitest'
import { OAuth2ProviderConfig, oauth2ProviderUrls, oauth2WellKnownUrls } from '../src/index'

export const backends: TestBackend[] = (process.env.GHURI_TEST_BACKENDS?.split(',') as
  | TestBackend[]
  | undefined) ?? ['sqlite', 'pglite', 'd1']

export const ORIGIN = 'http://testserver'

export interface Harness {
  app: GhuriApp
  db: TestDatabase
  env: Record<string, unknown>
  /** Mutable OAUTH2_PROVIDER settings (reset before each test to `base()`). */
  oauth: Record<string, any>
  client: TestClient
}

export function useProvider(
  opts: { using?: TestBackend; base?: () => Record<string, any>; urls?: () => UrlEntry[] } = {},
): Harness {
  const h = { env: {}, oauth: {} } as Harness
  beforeAll(async () => {
    h.app = createApp(
      defineSettings(() => ({
        SECRET_KEY: 'oauth-provider-tests',
        ALLOWED_HOSTS: ['testserver'],
        INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, OAuth2ProviderConfig],
        MIDDLEWARE: [SessionMiddleware, CsrfMiddleware, AuthenticationMiddleware],
        ROOT_URLCONF: [
          path('accounts/', include(authUrls)),
          path('oauth/', include(oauth2ProviderUrls)),
          path('', include(oauth2WellKnownUrls)),
          ...(opts.urls?.() ?? []),
        ],
        PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 1000 })],
        OAUTH2_PROVIDER: h.oauth,
      })),
      { checks: false },
    )
    await h.app.setup(h.env)
    h.db = await setupTestDatabase({ using: opts.using ?? 'sqlite' })
  }, 60_000)
  afterAll(async () => {
    setProviderFetch(undefined)
    await h.db?.teardown()
  })
  beforeEach(async () => {
    ContentType.objects.clearCache()
    await h.db.flush()
    ContentType.objects.clearCache()
    for (const k of Object.keys(h.oauth)) delete h.oauth[k]
    Object.assign(h.oauth, {
      SCOPES: { 'theme:read': 'Read your theme', 'theme:write': 'Edit your theme' },
      REGISTRATION_RATE: null,
      ...(opts.base?.() ?? {}),
    })
    setProviderFetch(undefined)
    await caches.get('default').clear()
    h.client = createTestClient(h.app, { env: h.env })
  })
  return h
}

export async function loggedIn(h: Harness, username = 'ann'): Promise<any> {
  const user = await User.objects.createUser(username, `${username}@example.com`, 'pw')
  await h.client.forceLogin(user)
  return user
}

/** Serve JSON documents for URL client ids (stubs `fetch` of the provider). */
export function serveDocuments(docs: Record<string, unknown | ((req: Request) => Response)>): string[] {
  const fetched: string[] = []
  setProviderFetch(async (input) => {
    const req = new Request(input as any)
    fetched.push(req.url)
    const doc = docs[req.url]
    if (doc === undefined) return new Response('not found', { status: 404 })
    if (typeof doc === 'function') return (doc as (r: Request) => Response)(req)
    return new Response(JSON.stringify(doc), {
      headers: { 'content-type': 'application/json', 'cache-control': 'max-age=600' },
    })
  })
  return fetched
}

export interface AuthorizeParams {
  clientId: string
  redirectUri: string
  scope?: string
  resource?: string
  state?: string
  extra?: Record<string, string>
}

export async function authorizeUrl(p: AuthorizeParams) {
  const pkce = await pkcePair()
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    state: p.state ?? 'st-1',
    ...(p.scope !== undefined ? { scope: p.scope } : {}),
    ...(p.resource !== undefined ? { resource: p.resource } : {}),
    ...(p.extra ?? {}),
  })
  return { url: `/oauth/authorize/?${q}`, verifier: pkce.verifier }
}

/** Form field values of an HTML page. */
export function formField(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(html)
  if (!m) throw new Error(`No field ${name} in page`)
  return m[1]
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
}

/** Walk authorize → consent (Allow) → redirect; returns the redirect URL and the PKCE verifier. */
export async function authorize(h: Harness, p: AuthorizeParams) {
  const { url, verifier } = await authorizeUrl(p)
  let res = await h.client.get(url)
  if (res.status === 200) {
    const html = await res.text()
    res = await h.client.post(url, { form: { request: formField(html, 'request'), allow: '1' } })
  }
  expect(res.status).toBe(302)
  const location = new URL(res.headers.get('location')!)
  return { location, code: location.searchParams.get('code'), verifier }
}

export async function token(h: Harness, form: Record<string, string>, headers: Record<string, string> = {}) {
  const res = await h.client.post('/oauth/token/', { form, headers, csrf: false })
  return { status: res.status, body: (await res.json()) as any, res }
}

/** The full code flow: returns the token response. */
export async function obtainTokens(h: Harness, p: AuthorizeParams) {
  const { code, verifier } = await authorize(h, p)
  const t = await token(h, {
    grant_type: 'authorization_code',
    code: code!,
    code_verifier: verifier,
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    ...(p.resource ? { resource: p.resource } : {}),
  })
  expect(t.status).toBe(200)
  return t.body
}
