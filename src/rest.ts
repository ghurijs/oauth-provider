// @ghuri/oauth-provider/rest — protect REST views with this server's access tokens (django-oauth-toolkit's
// `OAuth2Authentication` and `TokenHasScope`).
import type { RequestUser } from '@ghuri/core'
import { type APIRequest, AuthenticationFailed, type BasePermission } from '@ghuri/rest'
import type { Context } from 'hono'
import { providerSettings } from './settings'
import { type AccessTokenInfo, verifyAccessToken } from './tokens'
import { canonicalResource, issuerFor, requestOrigin } from './validation'

function bearer(c: Context): string | null {
  const m = /^Bearer\s+(\S+)\s*$/i.exec(c.req.header('authorization') ?? '')
  return m ? m[1] : null
}

/**
 * Authenticates `Authorization: Bearer <access token>`. `request.auth` is the `AccessTokenInfo` (scopes, client,
 * props). The token's audience must be `audience` (default `OAUTH2_PROVIDER.DEFAULT_RESOURCE`, else the issuer).
 */
export class OAuth2Authentication {
  /** The resource this API is: a URL, or a function of the request (default: `DEFAULT_RESOURCE` / the issuer). */
  audience?: string | ((c: Context) => string)

  protected resolveAudience(c: Context): string {
    if (typeof this.audience === 'function') return this.audience(c)
    if (this.audience) return this.audience
    return canonicalResource(providerSettings().DEFAULT_RESOURCE ?? issuerFor(c)) ?? requestOrigin(c)
  }

  async authenticate(c: Context): Promise<[RequestUser, AccessTokenInfo] | null> {
    const token = bearer(c)
    if (!token) return null
    const info = await verifyAccessToken(token, { audience: this.resolveAudience(c) })
    if (!info) throw new AuthenticationFailed('Invalid or expired access token.')
    return [info.user, info]
  }

  authenticateHeader(): string {
    return 'Bearer realm="api"'
  }
}

/** Requires the access token to carry every scope in the view's `requiredScopes`. */
export class TokenHasScope implements BasePermission {
  message = 'You do not have the scopes required for this action.'

  hasPermission(request: APIRequest, view: any): boolean {
    const required: string[] = view?.requiredScopes ?? view?.constructor?.requiredScopes ?? []
    const info = request.auth as AccessTokenInfo | undefined
    if (!info || !Array.isArray(info.scopes)) return false
    return required.every((s) => info.scopes.includes(s))
  }

  hasObjectPermission(): boolean {
    return true
  }
}
