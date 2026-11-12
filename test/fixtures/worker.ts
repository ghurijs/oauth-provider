// The authorization server in workerd on D1: migrations, discovery, registration, tokens, refresh rotation.
import { AuthConfig, ContentTypesConfig, User } from '@ghuri/auth'
import { createApp, defineSettings, include, path } from '@ghuri/core'
import { d1 } from '@ghuri/orm'
import { migrate } from '@ghuri/orm/migrations'
import {
  Application,
  createGrant,
  issueTokens,
  OAuth2ProviderConfig,
  oauth2ProviderUrls,
  oauth2WellKnownUrls,
  verifyAccessToken,
} from '../../src/index'

export default createApp(
  defineSettings(() => ({
    SECRET_KEY: 'edge-secret',
    INSTALLED_APPS: [ContentTypesConfig, AuthConfig, OAuth2ProviderConfig],
    DATABASES: { default: d1('DB') },
    OAUTH2_PROVIDER: { SCOPES: { read: 'Read' } },
    ROOT_URLCONF: [
      path('oauth/', include(oauth2ProviderUrls)),
      path('', include(oauth2WellKnownUrls)),
      path('__setup/', async (c) => {
        await migrate({ interactive: false } as any)
        return c.json({ ok: true })
      }),
      // Stands in for the browser consent step: a grant and its first tokens.
      path('__grant/', async (c) => {
        const clientId = c.req.query('client_id')!
        const user = await User.objects.createUser(`u${Date.now()}`, 'edge@example.com', 'pw')
        const application = await Application.objects.get({ clientId })
        const grant = await createGrant({
          user,
          application,
          scopes: ['read'],
          resource: 'https://example.com/mcp',
        })
        return c.json(
          await issueTokens(grant, application, { issuer: 'https://example.com', scopes: ['read'] }),
        )
      }),
      path('mcp', async (c) => {
        const token = (c.req.header('authorization') ?? '').replace(/^Bearer /, '')
        const info = await verifyAccessToken(token, { audience: 'https://example.com/mcp' })
        return info ? c.json({ scopes: info.scopes, runtime: navigator.userAgent }) : c.json({}, 401)
      }),
    ],
  })),
  { checks: false },
)
