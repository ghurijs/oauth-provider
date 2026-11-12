// The authorization server's tables (django-oauth-toolkit's `oauth2_provider_*` names). Secrets, codes and
// refresh tokens are stored only as SHA-256 hashes; access tokens are signed JWTs and not stored at all.
import { getUserModel } from '@ghuri/auth'
import {
  BooleanField,
  CASCADE,
  CharField,
  DateTimeField,
  ForeignKey,
  JSONField,
  type Manager,
  Model,
  type ModelClass,
  SET_NULL,
  TextField,
} from '@ghuri/orm'

const userModel = () => getUserModel() as unknown as ModelClass

/** Default of the JSON fields (a named function, so migrations can reference it). */
export function emptyDict(): Record<string, unknown> {
  return {}
}

export const CLIENT_TYPES = [
  ['confidential', 'Confidential'],
  ['public', 'Public'],
] as const satisfies ReadonlyArray<readonly [string, string]>

export const TOKEN_ENDPOINT_AUTH_METHODS = [
  ['none', 'None (public client)'],
  ['client_secret_basic', 'Client secret (HTTP Basic)'],
  ['client_secret_post', 'Client secret (form body)'],
] as const satisfies ReadonlyArray<readonly [string, string]>

export const APPLICATION_TYPES = [
  ['web', 'Web'],
  ['native', 'Native'],
] as const satisfies ReadonlyArray<readonly [string, string]>

export const REGISTRATION_TYPES = [
  ['manual', 'Manual'],
  ['dynamic', 'Dynamic registration (RFC 7591)'],
  ['metadata_document', 'Client ID Metadata Document'],
] as const satisfies ReadonlyArray<readonly [string, string]>

const choices = (list: ReadonlyArray<readonly [string, string]>) =>
  list.map(([k, v]) => [k, v] as [string, string])

/**
 * An OAuth client. Registered by hand (admin / `createApplication()`), by dynamic registration, or cached from a
 * Client ID Metadata Document (`clientId` is then the document URL).
 */
export class Application extends Model({
  clientId: new CharField({ maxLength: 1024, unique: true, verboseName: 'client id' }),
  /** `sha256$<hash>` of the client secret; empty for public clients. */
  clientSecret: new CharField({ maxLength: 255, blank: true, default: '', verboseName: 'client secret' }),
  name: new CharField({ maxLength: 255, blank: true, default: '', verboseName: 'name' }),
  clientType: new CharField({ maxLength: 32, choices: choices(CLIENT_TYPES), default: 'public' }),
  tokenEndpointAuthMethod: new CharField({
    maxLength: 32,
    choices: choices(TOKEN_ENDPOINT_AUTH_METHODS),
    default: 'none',
  }),
  /** Allowed redirect URIs, separated by whitespace. */
  redirectUris: new TextField({ blank: true, default: '', verboseName: 'redirect uris' }),
  /** Allowed grant types, separated by spaces. */
  grantTypes: new CharField({ maxLength: 255, default: 'authorization_code refresh_token' }),
  /** Scopes this client may request, separated by spaces (empty: any). */
  scope: new TextField({ blank: true, default: '' }),
  applicationType: new CharField({ maxLength: 16, choices: choices(APPLICATION_TYPES), default: 'web' }),
  registrationType: new CharField({ maxLength: 32, choices: choices(REGISTRATION_TYPES), default: 'manual' }),
  /** Approve without showing the consent page (first-party clients). */
  skipAuthorization: new BooleanField({ default: false }),
  clientUri: new CharField({ maxLength: 2000, blank: true, default: '' }),
  logoUri: new CharField({ maxLength: 2000, blank: true, default: '' }),
  /** The registration request or metadata document. */
  metadata: new JSONField({ default: emptyDict, blank: true }),
  /** When a cached metadata document must be fetched again. */
  metadataExpires: new DateTimeField({ null: true, blank: true }),
  user: new ForeignKey(userModel, {
    onDelete: CASCADE,
    null: true,
    blank: true,
    relatedName: 'oauth2ProviderApplications',
  }),
  created: new DateTimeField({ autoNowAdd: true }),
  updated: new DateTimeField({ autoNow: true }),
}) {
  static Meta = {
    dbTable: 'oauth2_provider_application',
    verboseName: 'application',
    verboseNamePlural: 'applications',
  }
  declare static objects: Manager<Application>

  get redirectUriList(): string[] {
    return this.redirectUris.split(/\s+/).filter(Boolean)
  }

  get grantTypeList(): string[] {
    return this.grantTypes.split(/\s+/).filter(Boolean)
  }

  get isPublic(): boolean {
    return this.clientType === 'public'
  }

  override toString(): string {
    return this.name || this.clientId
  }
}

/**
 * A user's authorization of a client: the approved scopes, the resource (token audience) and app-defined
 * `props`. Every refresh token belongs to a grant; revoking the grant ends them and the access tokens.
 */
export class Grant extends Model({
  user: new ForeignKey(userModel, { onDelete: CASCADE, relatedName: 'oauth2Grants' }),
  application: new ForeignKey(() => Application, { onDelete: CASCADE, relatedName: 'grants' }),
  scope: new TextField({ blank: true, default: '' }),
  resource: new CharField({ maxLength: 2000 }),
  /** App-defined data from the consent step (`approve({ props })`), available to resource servers. */
  props: new JSONField({ default: emptyDict, blank: true }),
  created: new DateTimeField({ autoNowAdd: true }),
  lastUsed: new DateTimeField({ null: true, blank: true }),
  revoked: new DateTimeField({ null: true, blank: true, dbIndex: true }),
}) {
  static Meta = { dbTable: 'oauth2_provider_grant', verboseName: 'grant', verboseNamePlural: 'grants' }
  declare static objects: Manager<Grant>
  declare applicationId: number

  get scopeList(): string[] {
    return this.scope.split(/\s+/).filter(Boolean)
  }

  get isActive(): boolean {
    return !this.revoked
  }

  override toString(): string {
    return `Grant ${this.pk}`
  }
}

/** A single-use authorization code (hash only), valid for `AUTHORIZATION_CODE_EXPIRE_SECONDS`. */
export class AuthorizationCode extends Model({
  grant: new ForeignKey(() => Grant, { onDelete: CASCADE, relatedName: 'codes' }),
  codeHash: new CharField({ maxLength: 64, unique: true }),
  /** The `redirect_uri` parameter of the authorization request (empty when it was omitted). */
  redirectUri: new CharField({ maxLength: 2000, blank: true, default: '' }),
  codeChallenge: new CharField({ maxLength: 128 }),
  codeChallengeMethod: new CharField({ maxLength: 10, default: 'S256' }),
  scope: new TextField({ blank: true, default: '' }),
  expires: new DateTimeField(),
  used: new DateTimeField({ null: true, blank: true }),
  created: new DateTimeField({ autoNowAdd: true }),
}) {
  static Meta = {
    dbTable: 'oauth2_provider_authorizationcode',
    verboseName: 'authorization code',
    verboseNamePlural: 'authorization codes',
  }
  declare static objects: Manager<AuthorizationCode>
  declare grantId: number
}

/** A refresh token (hash only). Rotated on every use; presenting a used one revokes its grant. */
export class RefreshToken extends Model({
  grant: new ForeignKey(() => Grant, { onDelete: CASCADE, relatedName: 'refreshTokens' }),
  tokenHash: new CharField({ maxLength: 64, unique: true }),
  scope: new TextField({ blank: true, default: '' }),
  expires: new DateTimeField(),
  /** When it was exchanged for its successor. */
  used: new DateTimeField({ null: true, blank: true }),
  revoked: new DateTimeField({ null: true, blank: true }),
  previous: new ForeignKey('self', {
    onDelete: SET_NULL,
    null: true,
    blank: true,
    relatedName: 'successors',
  }),
  created: new DateTimeField({ autoNowAdd: true }),
}) {
  static Meta = {
    dbTable: 'oauth2_provider_refreshtoken',
    verboseName: 'refresh token',
    verboseNamePlural: 'refresh tokens',
  }
  declare static objects: Manager<RefreshToken>
  declare grantId: number
  declare previousId: number | null
}
