import * as auth from '@ghuri/auth'
import { AppConfig, apps, BaseCommand, type CommandIO, ImproperlyConfigured } from '@ghuri/core'
import * as migrations from './migrations/index'
import { Application, AuthorizationCode, Grant, RefreshToken } from './models'

function appPath(): string | undefined {
  const meta = import.meta as ImportMeta & { dirname?: string; filename?: string }
  const dir = meta.dirname
  if (!dir || !/[\\/]src$/.test(dir) || !/\.[cm]?ts$/.test(meta.filename ?? '')) return undefined
  return dir
}

function migrationsModule(): Record<string, unknown> {
  const adapt = (auth as Record<string, any>).migrationsForUserModel
  return typeof adapt === 'function' ? adapt('oauth2_provider', migrations) : migrations
}

/**
 * Delete what can no longer be used: expired authorization codes, expired or revoked refresh tokens and revoked
 * grants. Rotated refresh tokens stay until they expire, so a replayed one is still recognised as reuse.
 */
export async function clearExpired(): Promise<{ codes: number; refreshTokens: number; grants: number }> {
  const now = new Date()
  const [codes] = await AuthorizationCode.objects.filter({ expires__lt: now }).delete()
  const [expired] = await RefreshToken.objects.filter({ expires__lt: now }).delete()
  const [revoked] = await RefreshToken.objects.filter({ revoked__isnull: false }).delete()
  const [grants] = await Grant.objects.filter({ revoked__isnull: false }).delete()
  return { codes, refreshTokens: expired + revoked, grants }
}

/** `ghuri cleartokens` (django-oauth-toolkit's): remove expired codes and dead refresh tokens and grants. */
export class ClearTokensCommand extends BaseCommand {
  static override help = 'Can be run as a cronjob or directly to clean out expired tokens.'

  async handle(_args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const n = await clearExpired()
    io.stdout(
      `Deleted ${n.codes} authorization codes, ${n.refreshTokens} refresh tokens and ${n.grants} revoked grants.`,
    )
  }
}

/** The `oauth2_provider` app (django-oauth-toolkit's): `Application`, `Grant`, `AuthorizationCode`, `RefreshToken`. */
export class OAuth2ProviderConfig extends AppConfig {
  name = '@ghuri/oauth-provider'
  override label = 'oauth2_provider'
  override verboseName = 'OAuth2 Provider'
  override path = appPath()
  override migrations = migrationsModule()
  override models = { Application, Grant, AuthorizationCode, RefreshToken }
  override commands = { cleartokens: ClearTokensCommand }

  override ready(): void {
    if (!apps.isInstalled('auth')) {
      throw new ImproperlyConfigured(
        "'oauth2_provider' requires '@ghuri/auth': add AuthConfig (and ContentTypesConfig) to INSTALLED_APPS.",
      )
    }
  }
}
