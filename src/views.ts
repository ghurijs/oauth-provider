// Endpoints: authorize (with consent), token, revoke (RFC 7009), register (RFC 7591), server metadata (RFC 8414),
// JWKS. Mount `oauth2ProviderUrls` under a prefix and `oauth2WellKnownUrls` at the root.
import { redirectToLogin } from '@ghuri/auth'
import {
  csrfExempt,
  escapeHtml,
  getUser,
  kwargs,
  path,
  type RequestUser,
  reverse,
  urlpatterns,
  type ViewFunction,
  wantsJson,
} from '@ghuri/core'
import { seal, unseal } from '@ghuri/oauth'
import type { Context } from 'hono'
import { authenticateClient, registerClient, resolveClient } from './clients'
import {
  type ApproveOptions,
  type AuthorizationRequest,
  type ConsentContext,
  type ConsentHandler,
  defaultConsentHandler,
  page,
} from './consent'
import { OAuth2Error } from './errors'
import { type Application, Grant } from './models'
import { providerSettings } from './settings'
import { throttle } from './throttle'
import {
  createAuthorizationCode,
  createGrant,
  grantForToken,
  issueTokens,
  publicJwk,
  redeemAuthorizationCode,
  revokeGrant,
  rotateRefreshToken,
} from './tokens'
import {
  issuerFor,
  parseScope,
  redirectUriMatches,
  requestOrigin,
  resolveResource,
  resolveScopes,
  sameResource,
  validPkceValue,
} from './validation'

const PENDING_PURPOSE = 'oauth2_provider.authorize'
const PENDING_SECONDS = 15 * 60

const CORS_HEADERS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'Authorization, Content-Type, MCP-Protocol-Version',
  'access-control-max-age': '86400',
}

function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(data === undefined ? null : JSON.stringify(data), {
    status,
    headers: {
      ...(data === undefined ? {} : { 'content-type': 'application/json' }),
      'cache-control': 'no-store',
      pragma: 'no-cache',
      ...CORS_HEADERS,
      ...headers,
    },
  })
}

function oauthErrorResponse(err: OAuth2Error, c?: Context): Response {
  const headers: Record<string, string> = {}
  if (err.status === 401 && /^Basic\s/i.test(c?.req.header('authorization') ?? ''))
    headers['www-authenticate'] = 'Basic realm="oauth2_provider"'
  return jsonResponse(err.toJSON(), err.status, headers)
}

function preflight(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS })
}

/** Absolute URL of an endpoint (`oauth2_provider:token`). */
export function endpointUrl(c: Context, name: string): string {
  return `${requestOrigin(c)}${reverse(`oauth2_provider:${name}`)}`
}

/** Read an `application/x-www-form-urlencoded` body; repeated parameters are refused. */
async function readForm(c: Context): Promise<Record<string, string>> {
  const type = c.req.header('content-type') ?? ''
  if (!type.toLowerCase().startsWith('application/x-www-form-urlencoded'))
    throw new OAuth2Error('invalid_request', 'Send the parameters as application/x-www-form-urlencoded.')
  const params = new URLSearchParams(await c.req.text())
  const out: Record<string, string> = {}
  for (const [k, v] of params) {
    if (k in out) throw new OAuth2Error('invalid_request', `The parameter '${k}' was sent more than once.`)
    out[k] = v
  }
  return out
}

// ---- authorize ----

function errorPage(c: Context, err: OAuth2Error): Response {
  if (wantsJson(c)) return jsonResponse(err.toJSON(), err.status === 401 ? 400 : err.status)
  return page(
    'Authorization failed',
    `<p>${escapeHtml(err.description)}</p><p><small>${escapeHtml(err.error)}</small></p>`,
    400,
  )
}

function redirectWith(c: Context, request: AuthorizationRequest, params: Record<string, string>): Response {
  const url = new URL(request.redirectUri)
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v)
  if (request.state !== undefined) url.searchParams.set('state', request.state)
  url.searchParams.set('iss', issuerFor(c))
  return new Response(null, {
    status: 302,
    headers: { location: url.toString(), 'cache-control': 'no-store' },
  })
}

function errorRedirect(c: Context, request: AuthorizationRequest, err: OAuth2Error): Response {
  return redirectWith(c, request, { error: err.error, error_description: err.description })
}

class RedirectError extends Error {
  constructor(
    readonly request: AuthorizationRequest,
    readonly oauth: OAuth2Error,
  ) {
    super(oauth.description)
  }
}

/** Validate an authorization request: client and redirect URI first (errors shown here), then the rest (redirected). */
async function parseAuthorizationRequest(
  c: Context,
  q: URLSearchParams,
): Promise<{ request: AuthorizationRequest; client: Application }> {
  for (const k of ['client_id', 'redirect_uri', 'response_type', 'state', 'code_challenge', 'scope']) {
    if (q.getAll(k).length > 1)
      throw new OAuth2Error('invalid_request', `The parameter '${k}' was sent more than once.`)
  }
  const client = await resolveClient(q.get('client_id'))
  const registered = client.redirectUriList
  const redirectUriParam = q.get('redirect_uri') ?? ''
  let redirectUri: string
  if (redirectUriParam) {
    if (!registered.some((r) => redirectUriMatches(r, redirectUriParam)))
      throw new OAuth2Error(
        'invalid_request',
        `The redirect_uri '${redirectUriParam}' is not registered for this client.`,
      )
    redirectUri = redirectUriParam
  } else if (registered.length === 1 && client.registrationType !== 'metadata_document') {
    redirectUri = registered[0]
  } else {
    throw new OAuth2Error('invalid_request', 'The redirect_uri parameter is required.')
  }
  const partial: AuthorizationRequest = {
    clientId: client.clientId,
    redirectUri,
    redirectUriParam,
    responseType: 'code',
    scopes: [],
    state: q.get('state') ?? undefined,
    codeChallenge: '',
    codeChallengeMethod: 'S256',
    resource: '',
    prompt: q.get('prompt') ?? undefined,
  }
  try {
    const responseType = q.get('response_type')
    if (responseType !== 'code')
      throw new OAuth2Error(
        responseType ? 'unsupported_response_type' : 'invalid_request',
        responseType ? `Unsupported response_type '${responseType}'.` : 'response_type is required.',
      )
    if (!client.grantTypeList.includes('authorization_code'))
      throw new OAuth2Error('unauthorized_client', 'This client may not use the authorization code grant.')
    const challenge = q.get('code_challenge')
    if (!challenge) throw new OAuth2Error('invalid_request', 'code_challenge is required (PKCE).')
    if ((q.get('code_challenge_method') ?? 'plain') !== 'S256')
      throw new OAuth2Error('invalid_request', "Only the 'S256' code_challenge_method is supported.")
    if (!validPkceValue(challenge)) throw new OAuth2Error('invalid_request', 'Invalid code_challenge.')
    const scopes = resolveScopes(parseScope(q.get('scope')), client.scope)
    const resource = await resolveResource(c, q.getAll('resource'))
    return { client, request: { ...partial, scopes, codeChallenge: challenge, resource } }
  } catch (err) {
    if (err instanceof OAuth2Error) throw new RedirectError(partial, err)
    throw err
  }
}

async function approve(
  c: Context,
  request: AuthorizationRequest,
  client: Application,
  user: RequestUser,
  opts: ApproveOptions = {},
): Promise<Response> {
  const scopes = opts.scope ?? request.scopes
  const extra = scopes.filter((s) => !request.scopes.includes(s))
  if (extra.length)
    throw new OAuth2Error('invalid_scope', `approve() cannot add scopes: ${extra.join(', ')}.`, 500)
  const grant = await createGrant({
    user,
    application: client,
    scopes,
    resource: request.resource,
    props: opts.props,
  })
  const code = await createAuthorizationCode(grant, {
    redirectUri: request.redirectUriParam,
    codeChallenge: request.codeChallenge,
    scopes,
  })
  return redirectWith(c, request, { code })
}

/** An active grant of `user` to `client` for the resource covering every requested scope (auto-approval). */
async function previousGrant(request: AuthorizationRequest, client: Application, user: RequestUser) {
  const grants = await Grant.objects
    .filter({ user: user.pk, application: client.pk, resource: request.resource, revoked__isnull: true })
    .orderBy('-created')
    .limit(5)
  for (const g of grants as Grant[]) {
    const have = g.scopeList
    if (request.scopes.every((s) => have.includes(s))) return g
  }
  return null
}

interface PendingRequest {
  r: AuthorizationRequest
  u: string
  e: number
}

function describeScopes(scopes: string[]): Array<{ name: string; description: string }> {
  const known = providerSettings().SCOPES ?? {}
  return scopes.map((name) => ({ name, description: known[name] ?? name }))
}

/**
 * The authorization endpoint. GET validates the request, logs the user in, auto-approves known grants, or shows
 * the consent step; POST receives the consent form. Pass `consent` to replace the consent page.
 */
export function authorizationView(opts: { consent?: ConsentHandler } = {}): ViewFunction {
  return async (c) => {
    const method = c.req.method
    if (method !== 'GET' && method !== 'POST')
      return new Response(null, { status: 405, headers: { allow: 'GET, POST' } })
    const handler = opts.consent ?? providerSettings().CONSENT_HANDLER ?? defaultConsentHandler
    let request: AuthorizationRequest
    let client: Application
    let form: Record<string, string> | undefined
    const user = getUser(c)
    try {
      if (method === 'GET') {
        ;({ request, client } = await parseAuthorizationRequest(c, new URL(c.req.url).searchParams))
      } else {
        const body = (await c.req.parseBody()) as Record<string, unknown>
        form = Object.fromEntries(Object.entries(body).filter(([, v]) => typeof v === 'string')) as Record<
          string,
          string
        >
        const raw = form.request ? await unseal(form.request, PENDING_PURPOSE) : null
        const pending = raw ? (JSON.parse(raw) as PendingRequest) : null
        if (!pending || pending.e < Date.now() / 1000)
          throw new OAuth2Error(
            'invalid_request',
            'The authorization request expired. Start again from the application.',
          )
        if (!user.isAuthenticated || String(user.pk) !== pending.u)
          throw new OAuth2Error('access_denied', 'The authorization request belongs to another user.')
        request = pending.r
        client = await resolveClient(request.clientId)
      }
    } catch (err) {
      if (err instanceof RedirectError) return errorRedirect(c, err.request, err.oauth)
      if (err instanceof OAuth2Error) return errorPage(c, err)
      throw err
    }

    try {
      if (!user.isAuthenticated) {
        if (request.prompt === 'none')
          return errorRedirect(c, request, new OAuth2Error('login_required', 'The user is not logged in.'))
        const u = new URL(c.req.url)
        return redirectToLogin(c, u.pathname + u.search)
      }
      if (method === 'GET') {
        if (client.skipAuthorization) return await approve(c, request, client, user)
        const s = providerSettings()
        if (s.REQUEST_APPROVAL_PROMPT === 'auto' && request.prompt !== 'consent') {
          const prior = await previousGrant(request, client, user)
          if (prior)
            return await approve(c, request, client, user, { props: prior.props as Record<string, unknown> })
        }
        if (request.prompt === 'none')
          return errorRedirect(
            c,
            request,
            new OAuth2Error('consent_required', 'The user has not approved this client.'),
          )
      }
      const pending = await seal(
        JSON.stringify({
          r: request,
          u: String(user.pk),
          e: Math.floor(Date.now() / 1000) + PENDING_SECONDS,
        }),
        PENDING_PURPOSE,
      )
      const ctx: ConsentContext = {
        c,
        request,
        client,
        user,
        scopes: describeScopes(request.scopes),
        pending,
        action: new URL(c.req.url).pathname,
        form,
        approve: (o) => approve(c, request, client, user, o),
        deny: (description) =>
          errorRedirect(
            c,
            request,
            new OAuth2Error('access_denied', description ?? 'The user denied the request.'),
          ),
      }
      return await handler(ctx)
    } catch (err) {
      if (err instanceof OAuth2Error && err.status < 500) return errorRedirect(c, request, err)
      throw err
    }
  }
}

// ---- token ----

/** The token endpoint: `authorization_code` (PKCE S256) and `refresh_token` (rotation, reuse detection). */
export const tokenView: ViewFunction = csrfExempt(async (c: Context) => {
  if (c.req.method === 'OPTIONS') return preflight()
  if (c.req.method !== 'POST') return jsonResponse(undefined, 405, { allow: 'POST' })
  try {
    const body = await readForm(c)
    const application = await authenticateClient(c, body)
    const issuer = issuerFor(c)
    const grantType = body.grant_type
    if (!grantType) throw new OAuth2Error('invalid_request', 'grant_type is required.')
    if (!['authorization_code', 'refresh_token'].includes(grantType))
      throw new OAuth2Error('unsupported_grant_type', `Unsupported grant_type '${grantType}'.`)
    if (!application.grantTypeList.includes(grantType))
      throw new OAuth2Error('unauthorized_client', `This client may not use the ${grantType} grant.`)
    if (grantType === 'authorization_code') {
      if (!body.code) throw new OAuth2Error('invalid_request', 'code is required.')
      const { grant, scopes } = await redeemAuthorizationCode({
        code: body.code,
        application,
        redirectUri: body.redirect_uri,
        codeVerifier: body.code_verifier,
        resource: body.resource,
      })
      return jsonResponse(await issueTokens(grant, application, { issuer, scopes }))
    }
    if (!body.refresh_token) throw new OAuth2Error('invalid_request', 'refresh_token is required.')
    const { grant, token } = await rotateRefreshToken({ refreshToken: body.refresh_token, application })
    const have = token.scope.split(' ').filter(Boolean)
    const requested = parseScope(body.scope)
    const extra = requested.filter((s) => !have.includes(s))
    if (extra.length)
      throw new OAuth2Error('invalid_scope', `The refresh token does not cover: ${extra.join(', ')}.`)
    if (body.resource !== undefined && !sameResource(body.resource, grant.resource))
      throw new OAuth2Error('invalid_target', 'The resource does not match the authorization.')
    const user = await (grant as any).user
    if (!user || user.isActive === false) {
      await revokeGrant(grant)
      throw new OAuth2Error('invalid_grant', 'The user is inactive.')
    }
    return jsonResponse(
      await issueTokens(grant, application, {
        issuer,
        scopes: requested.length ? requested : have,
        refreshScope: token.scope,
        previous: token,
        refresh: true,
      }),
    )
  } catch (err) {
    if (err instanceof OAuth2Error) return oauthErrorResponse(err, c)
    throw err
  }
})

// ---- revoke ----

/** RFC 7009 revocation: any refresh or access token of the client revokes its grant. Always 200. */
export const revokeTokenView: ViewFunction = csrfExempt(async (c: Context) => {
  if (c.req.method === 'OPTIONS') return preflight()
  if (c.req.method !== 'POST') return jsonResponse(undefined, 405, { allow: 'POST' })
  try {
    const body = await readForm(c)
    const application = await authenticateClient(c, body)
    if (!body.token) throw new OAuth2Error('invalid_request', 'token is required.')
    const grant = await grantForToken(body.token, application, body.token_type_hint)
    if (grant) await revokeGrant(grant)
    return jsonResponse(undefined, 200)
  } catch (err) {
    if (err instanceof OAuth2Error) return oauthErrorResponse(err, c)
    throw err
  }
})

// ---- registration ----

/** RFC 7591 dynamic client registration (`ALLOW_DYNAMIC_REGISTRATION`, rate limited by `REGISTRATION_RATE`). */
export const registrationView: ViewFunction = csrfExempt(async (c: Context) => {
  if (c.req.method === 'OPTIONS') return preflight()
  const s = providerSettings()
  if (!s.ALLOW_DYNAMIC_REGISTRATION) return jsonResponse({ error: 'not_found' }, 404)
  if (c.req.method !== 'POST') return jsonResponse(undefined, 405, { allow: 'POST' })
  try {
    if (!(c.req.header('content-type') ?? '').toLowerCase().includes('application/json'))
      throw new OAuth2Error('invalid_client_metadata', 'Send the client metadata as application/json.')
    const wait = await throttle(c, 'register', s.REGISTRATION_RATE)
    if (wait)
      return jsonResponse(
        { error: 'slow_down', error_description: 'Too many registrations. Try again later.' },
        429,
        { 'retry-after': String(wait) },
      )
    let body: unknown
    try {
      body = await c.req.json()
    } catch {
      throw new OAuth2Error('invalid_client_metadata', 'The body is not valid JSON.')
    }
    return jsonResponse(await registerClient(body), 201)
  } catch (err) {
    if (err instanceof OAuth2Error) return oauthErrorResponse(err, c)
    throw err
  }
})

// ---- metadata ----

/** RFC 8414 authorization server metadata for this request's issuer. */
export function serverMetadata(c: Context): Record<string, unknown> {
  const s = providerSettings()
  const jwk = publicJwk()
  return {
    issuer: issuerFor(c),
    authorization_endpoint: endpointUrl(c, 'authorize'),
    token_endpoint: endpointUrl(c, 'token'),
    revocation_endpoint: endpointUrl(c, 'revoke-token'),
    ...(s.ALLOW_DYNAMIC_REGISTRATION ? { registration_endpoint: endpointUrl(c, 'register') } : {}),
    ...(jwk ? { jwks_uri: `${requestOrigin(c)}/.well-known/jwks.json` } : {}),
    ...(s.SCOPES ? { scopes_supported: Object.keys(s.SCOPES) } : {}),
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    client_id_metadata_document_supported: s.ALLOW_CLIENT_ID_METADATA_DOCUMENTS,
    authorization_response_iss_parameter_supported: true,
  }
}

/** `/.well-known/oauth-authorization-server[/<issuer path>]`. */
export const serverMetadataView: ViewFunction = async (c: Context) => {
  if (c.req.method === 'OPTIONS') return preflight()
  const suffix = String(kwargs(c).issuerPath ?? '').replace(/^\/+|\/+$/g, '')
  const issuerPath = new URL(issuerFor(c)).pathname.replace(/^\/+|\/+$/g, '')
  if (suffix !== issuerPath) return jsonResponse({ error: 'not_found' }, 404)
  return jsonResponse(serverMetadata(c), 200, { 'cache-control': 'public, max-age=3600' })
}

/** `/.well-known/jwks.json` (asymmetric access tokens only). */
export const jwksView: ViewFunction = async (c: Context) => {
  if (c.req.method === 'OPTIONS') return preflight()
  const jwk = publicJwk()
  if (!jwk) return jsonResponse({ error: 'not_found' }, 404)
  return jsonResponse({ keys: [jwk] }, 200, { 'cache-control': 'public, max-age=3600' })
}

// ---- urls ----

/**
 * The endpoints, namespaced `oauth2_provider`: `path('oauth/', include(oauth2ProviderUrls))` → `authorize/`,
 * `token/`, `revoke_token/`, `register/`.
 */
export const oauth2ProviderUrls = urlpatterns('oauth2_provider', [
  path('authorize/', authorizationView(), { name: 'authorize' }),
  path('token/', tokenView, { name: 'token' }),
  path('revoke_token/', revokeTokenView, { name: 'revoke-token' }),
  path('register/', registrationView, { name: 'register' }),
])

/** Discovery documents; mount at the site root: `path('', include(oauth2WellKnownUrls))`. */
export const oauth2WellKnownUrls = urlpatterns(undefined, [
  path('.well-known/oauth-authorization-server', serverMetadataView, { name: 'oauth2_provider_metadata' }),
  path('.well-known/oauth-authorization-server/<path:issuerPath>', serverMetadataView),
  path('.well-known/jwks.json', jwksView, { name: 'oauth2_provider_jwks' }),
])
