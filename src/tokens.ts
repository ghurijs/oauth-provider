// Tokens: RFC 9068 JWT access tokens (audience = resource), hashed authorization codes and rotating refresh tokens.
import { getUserModel } from '@ghuri/auth'
import { ImproperlyConfigured, type RequestUser, tryGetContext } from '@ghuri/core'
import { b64url, decodeJwt, randomToken, signJwt, timingSafeEqual, utf8, verifyJwt } from '@ghuri/oauth'
import { OAuth2Error } from './errors'
import { type Application, AuthorizationCode, Grant, RefreshToken } from './models'
import { providerSettings } from './settings'
import { canonicalResource, hashToken, joinScope, sameResource } from './validation'

const nowSeconds = () => Math.floor(Date.now() / 1000)

// ---- signing keys ----

const hmacKeys = new Map<string, Promise<CryptoKey>>()

function hmacKey(secret: string): Promise<CryptoKey> {
  let k = hmacKeys.get(secret)
  if (!k) {
    k = (async () => {
      const base = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveKey'])
      return crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          salt: utf8('ghuri.oauth2_provider'),
          info: utf8('access_token'),
        },
        base,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify'],
      )
    })()
    if (hmacKeys.size > 32) hmacKeys.clear()
    hmacKeys.set(secret, k)
  }
  return k
}

function secretKeys(): string[] {
  const s = tryGetContext()?.settings
  const key = s?.SECRET_KEY as string | undefined
  if (!key) throw new ImproperlyConfigured('The SECRET_KEY setting must not be empty.')
  return [key, ...((s?.SECRET_KEY_FALLBACKS as string[] | undefined) ?? [])]
}

/** The public JWK of `ACCESS_TOKEN_SIGNING_KEY` (served at `.well-known/jwks.json`), or null for HS256. */
export function publicJwk(): (JsonWebKey & { kid?: string; alg?: string; use?: string }) | null {
  const s = providerSettings()
  const key = s.ACCESS_TOKEN_SIGNING_KEY
  if (!key || s.ACCESS_TOKEN_ALGORITHM === 'HS256') return null
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, key_ops: _ops, ...pub } = key as Record<string, any>
  return { ...pub, kid: key.kid ?? 'oauth2-provider-1', alg: s.ACCESS_TOKEN_ALGORITHM, use: 'sig' }
}

// ---- access tokens ----

export interface AccessTokenClaims {
  iss: string
  sub: string
  aud: string
  client_id: string
  scope: string
  jti: string
  iat: number
  exp: number
  /** The grant this token belongs to. */
  gid: string
}

/** Sign an RFC 9068 access token (`typ: at+jwt`). */
export async function signAccessToken(claims: AccessTokenClaims): Promise<string> {
  const s = providerSettings()
  if (s.ACCESS_TOKEN_ALGORITHM !== 'HS256') {
    const key = s.ACCESS_TOKEN_SIGNING_KEY
    if (!key)
      throw new ImproperlyConfigured(
        'OAUTH2_PROVIDER.ACCESS_TOKEN_SIGNING_KEY is required for asymmetric tokens.',
      )
    return signJwt(claims as any, key, s.ACCESS_TOKEN_ALGORITHM, { typ: 'at+jwt', kid: publicJwk()?.kid })
  }
  const header = b64url(utf8(JSON.stringify({ alg: 'HS256', typ: 'at+jwt' })))
  const payload = b64url(utf8(JSON.stringify(claims)))
  const key = await hmacKey(secretKeys()[0])
  const sig = await crypto.subtle.sign('HMAC', key, utf8(`${header}.${payload}`))
  return `${header}.${payload}.${b64url(sig)}`
}

/** Verify signature, type and lifetime; returns the claims or null. Audience / issuer are checked by callers. */
export async function decodeAccessToken(token: string): Promise<AccessTokenClaims | null> {
  let decoded: ReturnType<typeof decodeJwt>
  try {
    decoded = decodeJwt(token)
  } catch {
    return null
  }
  if (String(decoded.header.typ ?? '').toLowerCase() !== 'at+jwt') return null
  const s = providerSettings()
  let payload: Record<string, any>
  if (s.ACCESS_TOKEN_ALGORITHM === 'HS256') {
    if (decoded.header.alg !== 'HS256') return null
    let ok = false
    for (const secret of secretKeys()) {
      const key = await hmacKey(secret)
      if (await crypto.subtle.verify('HMAC', key, decoded.signature, utf8(decoded.signingInput))) {
        ok = true
        break
      }
    }
    if (!ok) return null
    payload = decoded.payload
    if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds()) return null
  } else {
    const jwk = publicJwk()
    if (!jwk) return null
    try {
      payload = await verifyJwt(token, {
        keys: [jwk as any],
        algorithms: [s.ACCESS_TOKEN_ALGORITHM],
        leeway: 0,
      })
    } catch {
      return null
    }
  }
  if (typeof payload.sub !== 'string' || typeof payload.aud !== 'string' || typeof payload.gid !== 'string')
    return null
  return payload as AccessTokenClaims
}

export interface AccessTokenInfo {
  /** The user the token acts for. */
  user: RequestUser
  /** Granted scopes. */
  scopes: string[]
  clientId: string
  /** The audience (canonical resource) the token was issued for. */
  resource: string
  grantId: string
  /** App-defined data stored at consent time (`approve({ props })`); `{}` with `CHECK_GRANT_ON_ACCESS: false`. */
  props: Record<string, unknown>
  expiresAt: Date
  claims: AccessTokenClaims
}

export interface VerifyAccessTokenOptions {
  /** The resource this server is: the token's `aud` must name it (RFC 8707). Required. */
  audience: string
  /** Expected issuer (default: any issuer this server signed for). */
  issuer?: string
}

/**
 * Verify an access token issued by this server for `audience`. Returns null for anything invalid: bad
 * signature, expired, another audience, revoked grant (unless `CHECK_GRANT_ON_ACCESS: false`), inactive user.
 */
export async function verifyAccessToken(
  token: string,
  opts: VerifyAccessTokenOptions,
): Promise<AccessTokenInfo | null> {
  if (!opts?.audience)
    throw new ImproperlyConfigured('verifyAccessToken() needs the audience (your resource URL).')
  const claims = await decodeAccessToken(token)
  if (!claims) return null
  if (!sameResource(claims.aud, opts.audience)) return null
  if (opts.issuer !== undefined && claims.iss !== opts.issuer.replace(/\/+$/, '')) return null
  let user: any
  let props: Record<string, unknown> = {}
  if (providerSettings().CHECK_GRANT_ON_ACCESS) {
    const grant = await Grant.objects
      .filter({ pk: claims.gid, revoked__isnull: true })
      .selectRelated('user')
      .first()
    if (!grant || String((grant as any).userId) !== claims.sub) return null
    user = (grant as any).user
    props = (grant.props as Record<string, unknown>) ?? {}
  } else {
    const User = getUserModel() as any
    user = await User._defaultManager.filter({ pk: claims.sub }).first()
  }
  if (!user || user.isActive === false) return null
  return {
    user,
    scopes: claims.scope.split(' ').filter(Boolean),
    clientId: claims.client_id,
    resource: claims.aud,
    grantId: claims.gid,
    props,
    expiresAt: new Date(claims.exp * 1000),
    claims,
  }
}

// ---- grants ----

/** Revoke a grant and every refresh token of it (its access tokens then fail `verifyAccessToken`). */
export async function revokeGrant(grant: Grant | number | string): Promise<void> {
  const id = typeof grant === 'object' ? grant.pk : grant
  const now = new Date()
  await Grant.objects.filter({ pk: id, revoked__isnull: true }).update({ revoked: now })
  await RefreshToken.objects.filter({ grant: id, revoked__isnull: true }).update({ revoked: now })
}

export interface TokenResponse {
  access_token: string
  token_type: 'Bearer'
  expires_in: number
  scope: string
  refresh_token?: string
}

async function newRefreshToken(grant: Grant, scope: string, previous?: RefreshToken): Promise<string> {
  const token = randomToken(32)
  await RefreshToken.objects.create({
    grant,
    tokenHash: await hashToken(token),
    scope,
    expires: new Date(Date.now() + providerSettings().REFRESH_TOKEN_EXPIRE_SECONDS * 1000),
    previous: previous ?? null,
  } as any)
  return token
}

/** Issue an access token (and a refresh token, when the client may refresh) for a grant. */
export async function issueTokens(
  grant: Grant,
  application: Application,
  opts: {
    issuer: string
    scopes: string[]
    refreshScope?: string
    previous?: RefreshToken
    refresh?: boolean
  },
): Promise<TokenResponse> {
  const s = providerSettings()
  const iat = nowSeconds()
  const scope = joinScope(opts.scopes)
  const access = await signAccessToken({
    iss: opts.issuer,
    sub: String(grant.userId),
    aud: grant.resource,
    client_id: application.clientId,
    scope,
    jti: randomToken(16),
    iat,
    exp: iat + s.ACCESS_TOKEN_EXPIRE_SECONDS,
    gid: String(grant.pk),
  })
  const out: TokenResponse = {
    access_token: access,
    token_type: 'Bearer',
    expires_in: s.ACCESS_TOKEN_EXPIRE_SECONDS,
    scope,
  }
  const refresh = opts.refresh ?? application.grantTypeList.includes('refresh_token')
  if (refresh)
    out.refresh_token = await newRefreshToken(grant, opts.refreshScope ?? grant.scope, opts.previous)
  await Grant.objects.filter({ pk: grant.pk }).update({ lastUsed: new Date() })
  return out
}

export interface GrantAccessOptions {
  user: RequestUser | { pk: unknown }
  application: Application
  scopes: string[]
  /** Canonical resource (token audience). */
  resource: string
  props?: Record<string, unknown>
}

/** Record a user's authorization of a client (the consent step's result). */
export async function createGrant(opts: GrantAccessOptions): Promise<Grant> {
  const resource = canonicalResource(opts.resource)
  if (!resource) throw new OAuth2Error('invalid_target', 'The resource must be an absolute URL.')
  return (await Grant.objects.create({
    user: opts.user,
    application: opts.application,
    scope: joinScope(opts.scopes),
    resource,
    props: opts.props ?? {},
  } as any)) as Grant
}

// ---- authorization codes ----

export async function createAuthorizationCode(
  grant: Grant,
  opts: { redirectUri: string; codeChallenge: string; scopes: string[] },
): Promise<string> {
  const code = randomToken(32)
  await AuthorizationCode.objects.create({
    grant,
    codeHash: await hashToken(code),
    redirectUri: opts.redirectUri,
    codeChallenge: opts.codeChallenge,
    codeChallengeMethod: 'S256',
    scope: joinScope(opts.scopes),
    expires: new Date(Date.now() + providerSettings().AUTHORIZATION_CODE_EXPIRE_SECONDS * 1000),
  } as any)
  return code
}

async function s256(verifier: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(verifier))))
}

/**
 * Exchange an authorization code. Single use: a second exchange revokes the grant (RFC 6749 §4.1.2).
 * Checks client, redirect URI, PKCE verifier and resource.
 */
export async function redeemAuthorizationCode(opts: {
  code: string
  application: Application
  redirectUri?: string
  codeVerifier?: string
  resource?: string
}): Promise<{ grant: Grant; scopes: string[] }> {
  const invalid = (msg: string) => new OAuth2Error('invalid_grant', msg)
  const row = await AuthorizationCode.objects
    .filter({ codeHash: await hashToken(opts.code) })
    .selectRelated('grant')
    .first()
  if (!row) throw invalid('The authorization code is invalid.')
  const grant = (row as any).grant as Grant
  if (grant.applicationId !== opts.application.pk)
    throw invalid('The authorization code was issued to another client.')
  if (row.used) {
    await revokeGrant(grant)
    throw invalid('The authorization code was already used.')
  }
  const claimed = await AuthorizationCode.objects
    .filter({ pk: row.pk, used__isnull: true })
    .update({ used: new Date() })
  if (claimed !== 1) {
    await revokeGrant(grant)
    throw invalid('The authorization code was already used.')
  }
  if (new Date(row.expires as any).getTime() <= Date.now()) throw invalid('The authorization code expired.')
  if (grant.revoked) throw invalid('The authorization was revoked.')
  if (row.redirectUri && opts.redirectUri !== row.redirectUri) throw invalid('redirect_uri does not match.')
  if (!row.redirectUri && opts.redirectUri !== undefined && opts.redirectUri !== '')
    throw invalid('redirect_uri was not part of the authorization request.')
  if (!opts.codeVerifier) throw new OAuth2Error('invalid_request', 'code_verifier is required (PKCE).')
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(opts.codeVerifier)) throw invalid('Invalid code_verifier.')
  if (!timingSafeEqual(await s256(opts.codeVerifier), row.codeChallenge))
    throw invalid('PKCE verification failed.')
  if (opts.resource !== undefined && !sameResource(opts.resource, grant.resource))
    throw new OAuth2Error('invalid_target', 'The resource does not match the authorization request.')
  return { grant, scopes: row.scope.split(' ').filter(Boolean) }
}

// ---- refresh tokens ----

/**
 * Rotate a refresh token. A token that was already rotated (outside the grace period) or revoked revokes its whole
 * grant: someone holds a copy (OAuth 2.1 §4.3.1 / RFC 9700 §4.14.2).
 */
export async function rotateRefreshToken(opts: {
  refreshToken: string
  application: Application
}): Promise<{ grant: Grant; token: RefreshToken }> {
  const invalid = (msg: string) => new OAuth2Error('invalid_grant', msg)
  const row = await RefreshToken.objects
    .filter({ tokenHash: await hashToken(opts.refreshToken) })
    .selectRelated('grant')
    .first()
  if (!row) throw invalid('The refresh token is invalid.')
  const grant = (row as any).grant as Grant
  if (grant.applicationId !== opts.application.pk)
    throw invalid('The refresh token was issued to another client.')
  if (grant.revoked || row.revoked) throw invalid('The refresh token was revoked.')
  if (new Date(row.expires as any).getTime() <= Date.now()) throw invalid('The refresh token expired.')
  const grace = providerSettings().REFRESH_TOKEN_GRACE_PERIOD_SECONDS
  if (row.used) {
    const usedAt = new Date(row.used as any).getTime()
    if (grace > 0 && Date.now() - usedAt <= grace * 1000) {
      // The client lost the previous response: retire the unused successor and rotate again.
      await RefreshToken.objects
        .filter({ previous: row.pk, used__isnull: true, revoked__isnull: true })
        .update({ revoked: new Date() })
      return { grant, token: row }
    }
    await revokeGrant(grant)
    throw invalid('The refresh token was already used; the authorization has been revoked.')
  }
  const claimed = await RefreshToken.objects
    .filter({ pk: row.pk, used__isnull: true })
    .update({ used: new Date() })
  if (claimed !== 1) {
    if (grace > 0) return { grant, token: row }
    await revokeGrant(grant)
    throw invalid('The refresh token was already used; the authorization has been revoked.')
  }
  return { grant, token: row }
}

/** The grant of a refresh token or access token issued to `application` (revocation), or null. */
export async function grantForToken(
  token: string,
  application: Application,
  hint?: string,
): Promise<Grant | null> {
  const viaRefresh = async () => {
    const row = await RefreshToken.objects
      .filter({ tokenHash: await hashToken(token) })
      .selectRelated('grant')
      .first()
    const grant = row ? ((row as any).grant as Grant) : null
    return grant && grant.applicationId === application.pk ? grant : null
  }
  const viaAccess = async () => {
    const claims = await decodeAccessToken(token)
    if (!claims || claims.client_id !== application.clientId) return null
    return Grant.objects.filter({ pk: claims.gid, application: application.pk }).first()
  }
  const order = hint === 'access_token' ? [viaAccess, viaRefresh] : [viaRefresh, viaAccess]
  for (const find of order) {
    const g = await find()
    if (g) return g
  }
  return null
}
