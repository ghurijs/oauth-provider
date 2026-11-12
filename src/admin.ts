// @ghuri/oauth-provider/admin — import from your project's admin module to manage OAuth clients and grants:
//   import '@ghuri/oauth-provider/admin'
import { action, ModelAdmin, site } from '@ghuri/admin'
import { Application, AuthorizationCode, Grant, RefreshToken } from './models'
import { revokeGrant } from './tokens'

export class ApplicationAdmin extends ModelAdmin<Application> {
  override listDisplay = ['name', 'clientId', 'clientType', 'registrationType', 'user', 'created']
  override listFilter = ['clientType', 'registrationType', 'skipAuthorization']
  override searchFields = ['name', 'clientId']
  // The secret is a hash; it is set by createApplication() / registration, never edited here.
  override exclude = ['clientSecret']
  override readonlyFields = ['metadata', 'metadataExpires', 'created', 'updated']
}

/** Revoke the selected grants: their refresh tokens stop working and their access tokens are refused at once. */
export const revokeGrants = action(
  { description: 'Revoke selected grants', permissions: ['change'] },
  async (_admin: unknown, _c: unknown, queryset: any) => {
    for (const grant of (await queryset) as Grant[]) await revokeGrant(grant)
  },
)

export class GrantAdmin extends ModelAdmin<Grant> {
  override listDisplay = ['pk', 'user', 'application', 'scope', 'resource', 'created', 'lastUsed', 'revoked']
  override listFilter = ['application', 'revoked']
  override searchFields = ['scope', 'resource']
  override readonlyFields = [
    'user',
    'application',
    'scope',
    'resource',
    'props',
    'created',
    'lastUsed',
    'revoked',
  ]
  override actions = [revokeGrants]
}

export class RefreshTokenAdmin extends ModelAdmin<RefreshToken> {
  override listDisplay = ['pk', 'grant', 'scope', 'expires', 'used', 'revoked', 'created']
  override listFilter = ['revoked', 'used']
  // Only hashes are stored; nothing here is a usable token.
  override exclude = ['tokenHash']
  override readonlyFields = ['grant', 'scope', 'expires', 'used', 'revoked', 'previous', 'created']
}

export class AuthorizationCodeAdmin extends ModelAdmin<AuthorizationCode> {
  override listDisplay = ['pk', 'grant', 'scope', 'expires', 'used']
  override exclude = ['codeHash', 'codeChallenge']
  override readonlyFields = [
    'grant',
    'redirectUri',
    'codeChallengeMethod',
    'scope',
    'expires',
    'used',
    'created',
  ]
}

site.register(Application, ApplicationAdmin)
site.register(Grant, GrantAdmin)
site.register(RefreshToken, RefreshTokenAdmin)
site.register(AuthorizationCode, AuthorizationCodeAdmin)
