// `OAUTH2_PROVIDER` settings (django-oauth-toolkit names where they exist), with defaults applied.
import { tryGetContext } from '@ghuri/core'
import type { Context } from 'hono'
import type { ConsentHandler } from './consent'

export type AccessTokenAlgorithm = 'HS256' | 'ES256' | 'RS256' | 'EdDSA'

/** `OAUTH2_PROVIDER` settings. Every key is optional. */
export interface OAuth2ProviderSettings {
  /** The issuer identifier (default: the request origin, `https://example.com`). */
  ISSUER?: string
  /** Scopes this server grants, with the description shown on the consent page. Unset: any scope is accepted. */
  SCOPES?: Record<string, string>
  /** Scopes granted when a request names none (default: every key of `SCOPES`). */
  DEFAULT_SCOPES?: string[]
  /** Access token lifetime in seconds (default 3600). */
  ACCESS_TOKEN_EXPIRE_SECONDS?: number
  /** Refresh token lifetime in seconds (default 30 days). Each rotation starts a new lifetime. */
  REFRESH_TOKEN_EXPIRE_SECONDS?: number
  /** Authorization code lifetime in seconds (default 60). */
  AUTHORIZATION_CODE_EXPIRE_SECONDS?: number
  /**
   * Seconds during which the refresh token just rotated may be presented again (a client that lost the
   * response) without counting as reuse; it then rotates again (default 0: any reuse revokes the grant).
   */
  REFRESH_TOKEN_GRACE_PERIOD_SECONDS?: number
  /**
   * Resource indicators (RFC 8707) tokens may be issued for: exact URLs, `https://host/*` prefixes, or a
   * predicate. Default: any URL on the issuer's origin.
   */
  RESOURCES?: string[] | ((resource: string, c: Context) => boolean | Promise<boolean>)
  /** The token audience when a request names no `resource` (default: the issuer). */
  DEFAULT_RESOURCE?: string
  /** Refuse requests without a `resource` parameter (default false). */
  REQUIRE_RESOURCE?: boolean
  /** `'auto'` skips the consent page when the user already granted the same scopes to the client (default). */
  REQUEST_APPROVAL_PROMPT?: 'auto' | 'force'
  /** Replaces the default consent page. */
  CONSENT_HANDLER?: ConsentHandler
  /** Serve RFC 7591 dynamic client registration at `register/` (default true). */
  ALLOW_DYNAMIC_REGISTRATION?: boolean
  /** Registrations per client IP (default `'20/hour'`; `null` disables the limit). */
  REGISTRATION_RATE?: string | null
  /** Accept Client ID Metadata Documents: HTTPS URLs as `client_id` (default true). */
  ALLOW_CLIENT_ID_METADATA_DOCUMENTS?: boolean
  /** Only fetch client metadata documents from these hosts (`claude.ai`, `.openai.com`). Default: any public host. */
  CLIENT_METADATA_ALLOWED_HOSTS?: string[]
  /** Extra trust policy for metadata documents: return false to refuse a client. */
  CLIENT_METADATA_POLICY?: (document: Record<string, unknown>, url: string) => boolean | Promise<boolean>
  /** Cache bounds for metadata documents in seconds (defaults 300 / 3600 / 86400). */
  CLIENT_METADATA_CACHE_MIN_SECONDS?: number
  CLIENT_METADATA_CACHE_DEFAULT_SECONDS?: number
  CLIENT_METADATA_CACHE_MAX_SECONDS?: number
  /** Fetch timeout in milliseconds (default 5000) and size limit in bytes (default 5120). */
  CLIENT_METADATA_TIMEOUT?: number
  CLIENT_METADATA_MAX_BYTES?: number
  /** URI schemes allowed in redirect URIs besides `https` and loopback `http` (custom schemes of native apps). */
  ALLOWED_REDIRECT_URI_SCHEMES?: string[]
  /** `HS256` (default; key derived from `SECRET_KEY`) or an asymmetric algorithm used with `ACCESS_TOKEN_SIGNING_KEY`. */
  ACCESS_TOKEN_ALGORITHM?: AccessTokenAlgorithm
  /** Private JWK for ES256 / RS256 / EdDSA access tokens; its public part is served at `.well-known/jwks.json`. */
  ACCESS_TOKEN_SIGNING_KEY?: JsonWebKey & { kid?: string }
  /** `verifyAccessToken` checks the grant is still active (default true; revocation then takes effect at once). */
  CHECK_GRANT_ON_ACCESS?: boolean
}

declare module '@ghuri/core' {
  interface GhuriSettings {
    /** `@ghuri/oauth-provider` settings. */
    OAUTH2_PROVIDER?: OAuth2ProviderSettings
  }
}

export interface ResolvedProviderSettings {
  ISSUER?: string
  SCOPES?: Record<string, string>
  DEFAULT_SCOPES?: string[]
  ACCESS_TOKEN_EXPIRE_SECONDS: number
  REFRESH_TOKEN_EXPIRE_SECONDS: number
  AUTHORIZATION_CODE_EXPIRE_SECONDS: number
  REFRESH_TOKEN_GRACE_PERIOD_SECONDS: number
  RESOURCES?: OAuth2ProviderSettings['RESOURCES']
  DEFAULT_RESOURCE?: string
  REQUIRE_RESOURCE: boolean
  REQUEST_APPROVAL_PROMPT: 'auto' | 'force'
  CONSENT_HANDLER?: ConsentHandler
  ALLOW_DYNAMIC_REGISTRATION: boolean
  REGISTRATION_RATE: string | null
  ALLOW_CLIENT_ID_METADATA_DOCUMENTS: boolean
  CLIENT_METADATA_ALLOWED_HOSTS?: string[]
  CLIENT_METADATA_POLICY?: OAuth2ProviderSettings['CLIENT_METADATA_POLICY']
  CLIENT_METADATA_CACHE_MIN_SECONDS: number
  CLIENT_METADATA_CACHE_DEFAULT_SECONDS: number
  CLIENT_METADATA_CACHE_MAX_SECONDS: number
  CLIENT_METADATA_TIMEOUT: number
  CLIENT_METADATA_MAX_BYTES: number
  ALLOWED_REDIRECT_URI_SCHEMES: string[]
  ACCESS_TOKEN_ALGORITHM: AccessTokenAlgorithm
  ACCESS_TOKEN_SIGNING_KEY?: JsonWebKey & { kid?: string }
  CHECK_GRANT_ON_ACCESS: boolean
}

/** `OAUTH2_PROVIDER` with defaults applied. */
export function providerSettings(): ResolvedProviderSettings {
  const s = (tryGetContext()?.settings.OAUTH2_PROVIDER ?? {}) as OAuth2ProviderSettings
  return {
    ...s,
    ACCESS_TOKEN_EXPIRE_SECONDS: s.ACCESS_TOKEN_EXPIRE_SECONDS ?? 3600,
    REFRESH_TOKEN_EXPIRE_SECONDS: s.REFRESH_TOKEN_EXPIRE_SECONDS ?? 30 * 24 * 3600,
    AUTHORIZATION_CODE_EXPIRE_SECONDS: s.AUTHORIZATION_CODE_EXPIRE_SECONDS ?? 60,
    REFRESH_TOKEN_GRACE_PERIOD_SECONDS: s.REFRESH_TOKEN_GRACE_PERIOD_SECONDS ?? 0,
    REQUIRE_RESOURCE: s.REQUIRE_RESOURCE ?? false,
    REQUEST_APPROVAL_PROMPT: s.REQUEST_APPROVAL_PROMPT ?? 'auto',
    ALLOW_DYNAMIC_REGISTRATION: s.ALLOW_DYNAMIC_REGISTRATION ?? true,
    REGISTRATION_RATE: s.REGISTRATION_RATE === undefined ? '20/hour' : s.REGISTRATION_RATE,
    ALLOW_CLIENT_ID_METADATA_DOCUMENTS: s.ALLOW_CLIENT_ID_METADATA_DOCUMENTS ?? true,
    CLIENT_METADATA_CACHE_MIN_SECONDS: s.CLIENT_METADATA_CACHE_MIN_SECONDS ?? 300,
    CLIENT_METADATA_CACHE_DEFAULT_SECONDS: s.CLIENT_METADATA_CACHE_DEFAULT_SECONDS ?? 3600,
    CLIENT_METADATA_CACHE_MAX_SECONDS: s.CLIENT_METADATA_CACHE_MAX_SECONDS ?? 86400,
    CLIENT_METADATA_TIMEOUT: s.CLIENT_METADATA_TIMEOUT ?? 5000,
    CLIENT_METADATA_MAX_BYTES: s.CLIENT_METADATA_MAX_BYTES ?? 5120,
    ALLOWED_REDIRECT_URI_SCHEMES: s.ALLOWED_REDIRECT_URI_SCHEMES ?? [],
    ACCESS_TOKEN_ALGORITHM: s.ACCESS_TOKEN_ALGORITHM ?? (s.ACCESS_TOKEN_SIGNING_KEY ? 'ES256' : 'HS256'),
    CHECK_GRANT_ON_ACCESS: s.CHECK_GRANT_ON_ACCESS ?? true,
  }
}
