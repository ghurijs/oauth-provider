// REST integration (OAuth2Authentication + TokenHasScope), the admin revoke action and `cleartokens`.
import { bufferIO, path } from '@ghuri/core'
import { APIResponse, APIView } from '@ghuri/rest'
import { describe, expect, it } from 'vitest'
import { revokeGrants } from '../src/admin'
import {
  AuthorizationCode,
  ClearTokensCommand,
  createApplication,
  Grant,
  RefreshToken,
  verifyAccessToken,
} from '../src/index'
import { OAuth2Authentication, TokenHasScope } from '../src/rest'
import { loggedIn, ORIGIN, obtainTokens, useProvider } from './helpers'

class ThemeAuth extends OAuth2Authentication {
  override audience = `${ORIGIN}/api`
}

class ThemeView extends APIView {
  override authenticationClasses = [ThemeAuth]
  override permissionClasses = [TokenHasScope]
  requiredScopes = ['theme:write']

  async get(request: any) {
    return new APIResponse({ user: request.user.username, props: request.auth.props })
  }
}

describe('extras', () => {
  const h = useProvider({ urls: () => [path('api/theme/', ThemeView.asView())] })

  async function tokens(scope: string, resource = `${ORIGIN}/api`) {
    const { application } = await createApplication({ redirectUris: ['https://app.example/cb'] })
    await loggedIn(h)
    return obtainTokens(h, {
      clientId: application.clientId,
      redirectUri: 'https://app.example/cb',
      resource,
      scope,
    })
  }

  it('authenticates REST views and checks scopes', async () => {
    const t = await tokens('theme:read theme:write')
    h.client.clearCookies()
    const ok = await h.client.get('/api/theme/', { headers: { authorization: `Bearer ${t.access_token}` } })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toEqual({ user: 'ann', props: {} })
    const anon = await h.client.get('/api/theme/')
    expect(anon.status).toBe(401)
    expect(anon.headers.get('www-authenticate')).toContain('Bearer')
    expect((await h.client.get('/api/theme/', { headers: { authorization: 'Bearer junk' } })).status).toBe(
      401,
    )
  })

  it('refuses tokens without the required scope or for another resource', async () => {
    const narrow = await tokens('theme:read')
    h.client.clearCookies()
    expect(
      (await h.client.get('/api/theme/', { headers: { authorization: `Bearer ${narrow.access_token}` } }))
        .status,
    ).toBe(403)
    await h.db.flush()
    const other = await tokens('theme:write', `${ORIGIN}/mcp`)
    h.client.clearCookies()
    expect(
      (await h.client.get('/api/theme/', { headers: { authorization: `Bearer ${other.access_token}` } }))
        .status,
    ).toBe(401)
  })

  it('revokes grants from the admin action', async () => {
    const t = await tokens('theme:read')
    await revokeGrants(null, null, Grant.objects.all())
    expect(await verifyAccessToken(t.access_token, { audience: `${ORIGIN}/api` })).toBeNull()
    expect(await RefreshToken.objects.filter({ revoked__isnull: true }).count()).toBe(0)
  })

  it('cleartokens deletes expired codes and dead tokens and grants', async () => {
    h.oauth.AUTHORIZATION_CODE_EXPIRE_SECONDS = -1
    const { application } = await createApplication({ redirectUris: ['https://app.example/cb'] })
    await loggedIn(h)
    const { authorize } = await import('./helpers')
    await authorize(h, { clientId: application.clientId, redirectUri: 'https://app.example/cb' })
    h.oauth.AUTHORIZATION_CODE_EXPIRE_SECONDS = 60
    const live = await obtainTokens(h, {
      clientId: application.clientId,
      redirectUri: 'https://app.example/cb',
    })
    expect(live.refresh_token).toBeTruthy()
    const io = bufferIO()
    await new ClearTokensCommand().handle({}, io)
    expect(io.out.join('\n')).toContain('Deleted 1 authorization codes')
    expect(await AuthorizationCode.objects.count()).toBe(1)
    expect(await RefreshToken.objects.count()).toBe(1)
  })
})
