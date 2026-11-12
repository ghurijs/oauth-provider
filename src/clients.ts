// Clients: lookup, Client ID Metadata Documents (fetched with SSRF guards, cached as Application rows), client
// authentication at the token endpoint, and dynamic registration (RFC 7591).
import { providerFetch, randomToken, timingSafeEqual } from '@ghuri/oauth'
import type { Context } from 'hono'
import { OAuth2Error } from './errors'
import { Application } from './models'
import { providerSettings } from './settings'
import { hashToken, parseScope, redirectUriProblem } from './validation'

const GRANT_TYPES = ['authorization_code', 'refresh_token']
const decoder = new TextDecoder()
const AUTH_METHODS = ['none', 'client_secret_basic', 'client_secret_post']

// ---- metadata documents ----

/** Is `clientId` in the form of a Client ID Metadata Document URL (https with a path)? */
export function isMetadataDocumentUrl(clientId: string): boolean {
  if (!clientId.startsWith('https://')) return false
  try {
    const u = new URL(clientId)
    return u.pathname !== '/' && u.pathname !== ''
  } catch {
    return false
  }
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

/** Hosts we never fetch from: IP literals, localhost and internal-looking names (SSRF). */
function blockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, '')
  if (IPV4.test(h) || h.startsWith('[') || h.includes(':')) return true
  if (!h.includes('.')) return true
  return (
    h === 'localhost' ||
    /\.(localhost|local|internal|intranet|lan|home|corp|localdomain|home\.arpa)$/.test(h) ||
    h === 'metadata.google.internal'
  )
}

function hostAllowed(hostname: string, patterns: string[]): boolean {
  const h = hostname.toLowerCase()
  return patterns.some((p) => {
    const pat = p.toLowerCase()
    if (pat.startsWith('.')) return h === pat.slice(1) || h.endsWith(pat)
    if (pat.startsWith('*.')) return h.endsWith(pat.slice(1))
    return h === pat
  })
}

/** Why a URL may not be fetched as a client metadata document, or null. */
export function metadataUrlProblem(url: string): string | null {
  let u: URL
  try {
    u = new URL(url)
  } catch {
    return 'The client_id is not a URL.'
  }
  if (u.protocol !== 'https:') return 'Client metadata documents must be served over https.'
  if (u.username || u.password) return 'The client_id URL must not contain credentials.'
  if (u.hash || url.includes('#')) return 'The client_id URL must not contain a fragment.'
  if (u.pathname === '/' || /(^|\/)\.\.?(\/|$)/.test(u.pathname))
    return 'The client_id URL must have a path without dot segments.'
  if (u.port && u.port !== '443') return 'The client_id URL must use the default https port.'
  if (blockedHost(u.hostname)) return `Client metadata documents cannot be fetched from '${u.hostname}'.`
  const allowed = providerSettings().CLIENT_METADATA_ALLOWED_HOSTS
  if (allowed && !hostAllowed(u.hostname, allowed))
    return `Client metadata documents from '${u.hostname}' are not accepted.`
  return null
}

function cacheSeconds(res: Response): number {
  const s = providerSettings()
  const cc = (res.headers.get('cache-control') ?? '').toLowerCase()
  let ttl = s.CLIENT_METADATA_CACHE_DEFAULT_SECONDS
  const m = /max-age=(\d+)/.exec(cc)
  if (m) ttl = Number(m[1])
  if (/no-store|no-cache/.test(cc)) ttl = 0
  return Math.min(Math.max(ttl, s.CLIENT_METADATA_CACHE_MIN_SECONDS), s.CLIENT_METADATA_CACHE_MAX_SECONDS)
}

async function readCapped(res: Response, max: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0')
  if (declared > max) throw new OAuth2Error('invalid_client', 'The client metadata document is too large.')
  if (!res.body) return ''
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      await reader.cancel().catch(() => {})
      throw new OAuth2Error('invalid_client', 'The client metadata document is too large.')
    }
    chunks.push(value)
  }
  const all = new Uint8Array(size)
  let off = 0
  for (const ch of chunks) {
    all.set(ch, off)
    off += ch.byteLength
  }
  return decoder.decode(all)
}

/** Validate a metadata document for `url`; returns the application fields. Throws `invalid_client`. */
export function validateMetadataDocument(doc: unknown, url: string): Record<string, unknown> {
  const bad = (msg: string) => new OAuth2Error('invalid_client', `Invalid client metadata document: ${msg}`)
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw bad('not a JSON object.')
  const d = doc as Record<string, unknown>
  if (d.client_id !== url) throw bad('client_id does not equal the document URL.')
  const uris = d.redirect_uris
  if (!Array.isArray(uris) || !uris.length || !uris.every((u) => typeof u === 'string'))
    throw bad('redirect_uris must be a non-empty array of strings.')
  for (const u of uris as string[]) {
    const problem = redirectUriProblem(u)
    if (problem) throw bad(problem)
  }
  const method = d.token_endpoint_auth_method ?? 'none'
  if (method !== 'none')
    throw bad(`token_endpoint_auth_method '${String(method)}' is not supported (use 'none').`)
  if ('client_secret' in d || 'client_secret_expires_at' in d)
    throw bad('it must not contain a client secret.')
  const grantTypes = d.grant_types === undefined ? GRANT_TYPES : d.grant_types
  if (!Array.isArray(grantTypes) || !grantTypes.every((g) => GRANT_TYPES.includes(g as string)))
    throw bad('grant_types may only contain authorization_code and refresh_token.')
  if (d.response_types !== undefined) {
    const rt = d.response_types
    if (!Array.isArray(rt) || !rt.every((r) => r === 'code'))
      throw bad("response_types may only contain 'code'.")
  }
  const str = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : '')
  return {
    name: str('client_name').slice(0, 255),
    clientType: 'public',
    tokenEndpointAuthMethod: 'none',
    redirectUris: (uris as string[]).join(' '),
    grantTypes: (grantTypes as string[]).join(' '),
    scope: typeof d.scope === 'string' ? parseScope(d.scope).join(' ') : '',
    applicationType: d.application_type === 'native' ? 'native' : 'web',
    registrationType: 'metadata_document',
    clientUri: str('client_uri').slice(0, 2000),
    logoUri: str('logo_uri').slice(0, 2000),
    metadata: d,
  }
}

/** Fetch, validate and cache the metadata document of a URL `client_id`. */
export async function fetchMetadataDocument(url: string): Promise<Application> {
  const s = providerSettings()
  const problem = metadataUrlProblem(url)
  if (problem) throw new OAuth2Error('invalid_client', problem)
  let res: Response
  try {
    res = await providerFetch(url, {
      headers: { accept: 'application/json' },
      redirect: 'manual',
      signal: AbortSignal.timeout(s.CLIENT_METADATA_TIMEOUT),
    })
  } catch {
    throw new OAuth2Error('invalid_client', 'The client metadata document could not be fetched.')
  }
  if (res.status !== 200)
    throw new OAuth2Error('invalid_client', `The client metadata document answered ${res.status}.`)
  const text = await readCapped(res, s.CLIENT_METADATA_MAX_BYTES)
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    throw new OAuth2Error('invalid_client', 'The client metadata document is not JSON.')
  }
  const fields = validateMetadataDocument(doc, url)
  if (s.CLIENT_METADATA_POLICY && !(await s.CLIENT_METADATA_POLICY(doc as Record<string, unknown>, url)))
    throw new OAuth2Error('invalid_client', 'This client is not allowed.')
  const metadataExpires = new Date(Date.now() + cacheSeconds(res) * 1000)
  const [app] = await Application.objects.updateOrCreate(
    { clientId: url },
    { defaults: { ...fields, metadataExpires } },
  )
  return app as Application
}

/**
 * The client for `clientId`: a registered application, or (for URL client ids) the cached / freshly fetched
 * metadata document. Throws `invalid_client`.
 */
export async function resolveClient(clientId: unknown): Promise<Application> {
  if (typeof clientId !== 'string' || !clientId)
    throw new OAuth2Error('invalid_request', 'The client_id parameter is required.')
  const app = await Application.objects.filter({ clientId }).first()
  const s = providerSettings()
  if (app && app.registrationType !== 'metadata_document') return app
  if (isMetadataDocumentUrl(clientId) && s.ALLOW_CLIENT_ID_METADATA_DOCUMENTS) {
    if (app?.metadataExpires && new Date(app.metadataExpires).getTime() > Date.now()) return app
    return fetchMetadataDocument(clientId)
  }
  throw new OAuth2Error('invalid_client', 'Unknown client.', 401)
}

// ---- client authentication (token / revocation endpoints) ----

export async function hashSecret(secret: string): Promise<string> {
  return `sha256$${await hashToken(secret)}`
}

export async function checkSecret(app: Application, secret: string): Promise<boolean> {
  if (!app.clientSecret || !secret) return false
  return timingSafeEqual(app.clientSecret, await hashSecret(secret))
}

function basicCredentials(c: Context): [string, string] | null {
  const h = c.req.header('authorization') ?? ''
  const m = /^Basic\s+(.+)$/i.exec(h)
  if (!m) return null
  try {
    const raw = decoder.decode(Uint8Array.from(atob(m[1].trim()), (ch) => ch.charCodeAt(0)))
    const i = raw.indexOf(':')
    if (i < 0) return null
    return [decodeURIComponent(raw.slice(0, i)), decodeURIComponent(raw.slice(i + 1))]
  } catch {
    return null
  }
}

/** Authenticate the client of a token / revocation request. Throws `invalid_client` (401). */
export async function authenticateClient(c: Context, body: Record<string, string>): Promise<Application> {
  const basic = basicCredentials(c)
  const clientId = basic?.[0] ?? body.client_id
  if (!clientId) throw new OAuth2Error('invalid_client', 'Client authentication failed: no client_id.', 401)
  if (basic && body.client_id && body.client_id !== basic[0])
    throw new OAuth2Error('invalid_request', 'client_id does not match the authenticated client.')
  let app: Application
  try {
    app = await resolveClient(clientId)
  } catch (err) {
    if (err instanceof OAuth2Error) throw new OAuth2Error('invalid_client', err.description, 401)
    throw err
  }
  const secret = basic?.[1] ?? body.client_secret
  if (app.isPublic) {
    if (secret) throw new OAuth2Error('invalid_client', 'Public clients have no secret.', 401)
    return app
  }
  if (!secret || !(await checkSecret(app, secret)))
    throw new OAuth2Error('invalid_client', 'Client authentication failed.', 401)
  return app
}

// ---- registration ----

export interface CreateApplicationOptions {
  name?: string
  redirectUris: string[]
  /** `'public'` (default; PKCE only) or `'confidential'` (gets a secret). */
  clientType?: 'public' | 'confidential'
  tokenEndpointAuthMethod?: 'none' | 'client_secret_basic' | 'client_secret_post'
  grantTypes?: string[]
  scope?: string[]
  applicationType?: 'web' | 'native'
  skipAuthorization?: boolean
  clientId?: string
  user?: unknown
  registrationType?: 'manual' | 'dynamic'
  clientUri?: string
  logoUri?: string
  metadata?: Record<string, unknown>
}

/** Register a client. Returns it with the plain client secret (confidential clients only; it is not stored). */
export async function createApplication(
  opts: CreateApplicationOptions,
): Promise<{ application: Application; clientSecret?: string }> {
  for (const u of opts.redirectUris) {
    const problem = redirectUriProblem(u)
    if (problem) throw new OAuth2Error('invalid_redirect_uri', problem)
  }
  const clientType =
    opts.clientType ??
    (opts.tokenEndpointAuthMethod && opts.tokenEndpointAuthMethod !== 'none' ? 'confidential' : 'public')
  const method = opts.tokenEndpointAuthMethod ?? (clientType === 'public' ? 'none' : 'client_secret_basic')
  if ((method === 'none') !== (clientType === 'public'))
    throw new OAuth2Error(
      'invalid_client_metadata',
      "Public clients use 'none'; confidential clients a secret.",
    )
  const clientSecret = clientType === 'confidential' ? randomToken(32) : undefined
  const application = (await Application.objects.create({
    clientId: opts.clientId ?? randomToken(18),
    clientSecret: clientSecret ? await hashSecret(clientSecret) : '',
    name: opts.name ?? '',
    clientType,
    tokenEndpointAuthMethod: method,
    redirectUris: opts.redirectUris.join(' '),
    grantTypes: (opts.grantTypes ?? GRANT_TYPES).join(' '),
    scope: (opts.scope ?? []).join(' '),
    applicationType: opts.applicationType ?? 'web',
    registrationType: opts.registrationType ?? 'manual',
    skipAuthorization: opts.skipAuthorization ?? false,
    clientUri: opts.clientUri ?? '',
    logoUri: opts.logoUri ?? '',
    metadata: opts.metadata ?? {},
    user: opts.user ?? null,
  } as any)) as Application
  return { application, clientSecret }
}

/** RFC 7591: validate a registration request and create the client; returns the registration response. */
export async function registerClient(body: unknown): Promise<Record<string, unknown>> {
  const meta = (msg: string) => new OAuth2Error('invalid_client_metadata', msg)
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw meta('Send a JSON object.')
  const d = body as Record<string, unknown>
  const uris = d.redirect_uris
  if (!Array.isArray(uris) || !uris.length || !uris.every((u) => typeof u === 'string'))
    throw new OAuth2Error('invalid_redirect_uri', 'redirect_uris must be a non-empty array of strings.')
  const method = (d.token_endpoint_auth_method ?? 'client_secret_basic') as string
  if (!AUTH_METHODS.includes(method)) throw meta(`Unsupported token_endpoint_auth_method '${method}'.`)
  const grantTypes = (d.grant_types ?? GRANT_TYPES) as unknown
  if (!Array.isArray(grantTypes) || !grantTypes.length || !grantTypes.every((g) => GRANT_TYPES.includes(g)))
    throw meta('grant_types may only contain authorization_code and refresh_token.')
  if (!grantTypes.includes('authorization_code')) throw meta('grant_types must include authorization_code.')
  if (d.response_types !== undefined) {
    const rt = d.response_types
    if (!Array.isArray(rt) || !rt.every((r) => r === 'code'))
      throw meta("response_types may only contain 'code'.")
  }
  const applicationType = d.application_type === undefined ? 'web' : d.application_type
  if (applicationType !== 'web' && applicationType !== 'native')
    throw meta("application_type must be 'web' or 'native'.")
  const str = (k: string, max: number) => (typeof d[k] === 'string' ? (d[k] as string).slice(0, max) : '')
  const scope = typeof d.scope === 'string' ? parseScope(d.scope) : []
  const known = providerSettings().SCOPES
  for (const s of scope)
    if (known && !(s in known)) throw new OAuth2Error('invalid_scope', `Unknown scope '${s}'.`)
  const { application, clientSecret } = await createApplication({
    name: str('client_name', 255),
    redirectUris: uris as string[],
    clientType: method === 'none' ? 'public' : 'confidential',
    tokenEndpointAuthMethod: method as CreateApplicationOptions['tokenEndpointAuthMethod'],
    grantTypes: grantTypes as string[],
    scope,
    applicationType,
    registrationType: 'dynamic',
    clientUri: str('client_uri', 2000),
    logoUri: str('logo_uri', 2000),
    metadata: d,
  })
  const issuedAt = Math.floor(new Date(application.created as any).getTime() / 1000)
  return {
    client_id: application.clientId,
    client_id_issued_at: Number.isFinite(issuedAt) ? issuedAt : Math.floor(Date.now() / 1000),
    ...(clientSecret ? { client_secret: clientSecret, client_secret_expires_at: 0 } : {}),
    client_name: application.name || undefined,
    redirect_uris: application.redirectUriList,
    grant_types: application.grantTypeList,
    response_types: ['code'],
    token_endpoint_auth_method: application.tokenEndpointAuthMethod,
    application_type: application.applicationType,
    ...(application.scope ? { scope: application.scope } : {}),
    ...(application.clientUri ? { client_uri: application.clientUri } : {}),
    ...(application.logoUri ? { logo_uri: application.logoUri } : {}),
  }
}
