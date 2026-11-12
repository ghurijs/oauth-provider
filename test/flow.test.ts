// The authorization server end to end through the real views: discovery, CIMD and DCR clients, authorize and
// consent, code → token with PKCE, refresh rotation and reuse detection, revocation, audience binding.
import { makeMigrations } from '@ghuri/orm/migrations'
import { describe, expect, it } from 'vitest'
import { Application, createApplication, Grant, RefreshToken, verifyAccessToken } from '../src/index'
import {
  authorize,
  authorizeUrl,
  backends,
  formField,
  loggedIn,
  ORIGIN,
  obtainTokens,
  serveDocuments,
  token,
  useProvider,
} from './helpers'

const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata'
const CLAUDE_CB = 'https://claude.ai/api/mcp/auth_callback'
const MCP = `${ORIGIN}/mcp`

const claudeDoc = {
  client_id: CLAUDE,
  client_name: 'Claude',
  redirect_uris: [CLAUDE_CB, 'https://claude.com/api/mcp/auth_callback'],
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  token_endpoint_auth_method: 'none',
}

for (const using of backends) {
  describe(`authorization server (${using})`, () => {
    const h = useProvider({ using })

    it('ships a migration that matches the models', async () => {
      const result = await makeMigrations({ appLabels: ['oauth2_provider'], check: true, interactive: false })
      expect(result.exitCode).toBe(0)
    })

    describe('discovery', () => {
      it('serves RFC 8414 metadata for MCP clients', async () => {
        const res = await h.client.get('/.well-known/oauth-authorization-server')
        expect(res.status).toBe(200)
        expect(res.headers.get('access-control-allow-origin')).toBe('*')
        const meta = (await res.json()) as any
        expect(meta).toMatchObject({
          issuer: ORIGIN,
          authorization_endpoint: `${ORIGIN}/oauth/authorize/`,
          token_endpoint: `${ORIGIN}/oauth/token/`,
          revocation_endpoint: `${ORIGIN}/oauth/revoke_token/`,
          registration_endpoint: `${ORIGIN}/oauth/register/`,
          scopes_supported: ['theme:read', 'theme:write'],
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          code_challenge_methods_supported: ['S256'],
          client_id_metadata_document_supported: true,
          authorization_response_iss_parameter_supported: true,
        })
        expect(meta.token_endpoint_auth_methods_supported).toContain('none')
        expect(meta.jwks_uri).toBeUndefined()
      })

      it('answers issuer-path variants only for a matching ISSUER', async () => {
        expect((await h.client.get('/.well-known/oauth-authorization-server/tenant1')).status).toBe(404)
        h.oauth.ISSUER = `${ORIGIN}/tenant1`
        const res = await h.client.get('/.well-known/oauth-authorization-server/tenant1')
        expect(res.status).toBe(200)
        expect(((await res.json()) as any).issuer).toBe(`${ORIGIN}/tenant1`)
        expect((await h.client.get('/.well-known/oauth-authorization-server')).status).toBe(404)
      })

      it('omits registration when dynamic registration is off', async () => {
        h.oauth.ALLOW_DYNAMIC_REGISTRATION = false
        const meta = (await (await h.client.get('/.well-known/oauth-authorization-server')).json()) as any
        expect(meta.registration_endpoint).toBeUndefined()
        expect((await h.client.post('/oauth/register/', { json: {}, csrf: false })).status).toBe(404)
      })
    })

    describe('client ID metadata documents', () => {
      it('runs the whole flow for a URL client_id and caches the document', async () => {
        const fetched = serveDocuments({ [CLAUDE]: claudeDoc })
        await loggedIn(h)
        const t = await obtainTokens(h, {
          clientId: CLAUDE,
          redirectUri: CLAUDE_CB,
          resource: MCP,
          scope: 'theme:read',
        })
        expect(t).toMatchObject({ token_type: 'Bearer', scope: 'theme:read', expires_in: 3600 })
        expect(t.refresh_token).toEqual(expect.any(String))
        const app = await Application.objects.get({ clientId: CLAUDE })
        expect(app).toMatchObject({
          name: 'Claude',
          registrationType: 'metadata_document',
          clientType: 'public',
        })
        // authorize + token resolved the client: one fetch thanks to the cache
        expect(fetched).toEqual([CLAUDE])
        const info = await verifyAccessToken(t.access_token, { audience: MCP })
        expect(info).toMatchObject({ clientId: CLAUDE, scopes: ['theme:read'], resource: MCP })
      })

      it('refuses documents whose client_id differs from the URL', async () => {
        serveDocuments({ [CLAUDE]: { ...claudeDoc, client_id: 'https://evil.example/client.json' } })
        await loggedIn(h)
        const { url } = await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })
        const res = await h.client.get(url)
        expect(res.status).toBe(400)
        expect(await res.text()).toContain('client_id does not equal the document URL')
      })

      it('refuses redirect URIs the document does not list (no redirect)', async () => {
        serveDocuments({ [CLAUDE]: claudeDoc })
        await loggedIn(h)
        const { url } = await authorizeUrl({ clientId: CLAUDE, redirectUri: 'https://evil.example/cb' })
        const res = await h.client.get(url)
        expect(res.status).toBe(400)
        expect(res.headers.get('location')).toBeNull()
      })

      it('never fetches private, loopback or IP-literal hosts', async () => {
        const fetched = serveDocuments({})
        await loggedIn(h)
        for (const id of [
          'https://127.0.0.1/client.json',
          'https://localhost/client.json',
          'https://[::1]/client.json',
          'https://metadata.internal/client.json',
          'https://169.254.169.254/latest',
          'https://intranet/client.json',
        ]) {
          const { url } = await authorizeUrl({ clientId: id, redirectUri: CLAUDE_CB })
          expect((await h.client.get(url)).status).toBe(400)
        }
        expect(fetched).toEqual([])
      })

      it('does not follow redirects and caps the size', async () => {
        serveDocuments({
          [CLAUDE]: () => new Response(null, { status: 302, headers: { location: 'http://10.0.0.1/x' } }),
          'https://big.example/client.json': () =>
            new Response(JSON.stringify({ ...claudeDoc, pad: 'x'.repeat(6000) }), {
              headers: { 'content-type': 'application/json' },
            }),
        })
        await loggedIn(h)
        let res = await h.client.get((await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })).url)
        expect(res.status).toBe(400)
        expect(await res.text()).toContain('answered 302')
        res = await h.client.get(
          (await authorizeUrl({ clientId: 'https://big.example/client.json', redirectUri: CLAUDE_CB })).url,
        )
        expect(await res.text()).toContain('too large')
      })

      it('honours CLIENT_METADATA_ALLOWED_HOSTS and can be turned off', async () => {
        serveDocuments({ [CLAUDE]: claudeDoc })
        await loggedIn(h)
        h.oauth.CLIENT_METADATA_ALLOWED_HOSTS = ['chatgpt.com']
        expect(
          (await h.client.get((await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })).url)).status,
        ).toBe(400)
        h.oauth.CLIENT_METADATA_ALLOWED_HOSTS = ['.claude.ai', 'claude.ai']
        expect(
          (await h.client.get((await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })).url)).status,
        ).toBe(200)
        h.oauth.ALLOW_CLIENT_ID_METADATA_DOCUMENTS = false
        await Application.objects.all().delete()
        expect(
          (await h.client.get((await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })).url)).status,
        ).toBe(400)
      })

      it('refuses documents asking for client secrets', async () => {
        serveDocuments({ [CLAUDE]: { ...claudeDoc, token_endpoint_auth_method: 'client_secret_basic' } })
        await loggedIn(h)
        const res = await h.client.get((await authorizeUrl({ clientId: CLAUDE, redirectUri: CLAUDE_CB })).url)
        expect(await res.text()).toContain('is not supported')
      })
    })

    describe('dynamic client registration', () => {
      it('registers a public client and uses it with a loopback redirect on any port', async () => {
        const reg = await h.client.post('/oauth/register/', {
          csrf: false,
          json: {
            client_name: 'Claude Code',
            redirect_uris: ['http://localhost/callback'],
            token_endpoint_auth_method: 'none',
            grant_types: ['authorization_code', 'refresh_token'],
            application_type: 'native',
          },
        })
        expect(reg.status).toBe(201)
        const body = (await reg.json()) as any
        expect(body).toMatchObject({
          client_name: 'Claude Code',
          token_endpoint_auth_method: 'none',
          redirect_uris: ['http://localhost/callback'],
          application_type: 'native',
        })
        expect(body.client_secret).toBeUndefined()
        await loggedIn(h)
        const t = await obtainTokens(h, {
          clientId: body.client_id,
          redirectUri: 'http://localhost:53682/callback',
          resource: MCP,
        })
        expect(t.scope).toBe('theme:read theme:write')
        // a different path is still refused
        const bad = await authorizeUrl({
          clientId: body.client_id,
          redirectUri: 'http://localhost:53682/other',
        })
        expect((await h.client.get(bad.url)).status).toBe(400)
      })

      it('issues a secret to confidential clients and checks it at the token endpoint', async () => {
        const reg = await h.client.post('/oauth/register/', {
          csrf: false,
          json: { redirect_uris: ['https://app.example/cb'] },
        })
        const body = (await reg.json()) as any
        expect(body).toMatchObject({
          token_endpoint_auth_method: 'client_secret_basic',
          client_secret_expires_at: 0,
        })
        await loggedIn(h)
        const { code, verifier } = await authorize(h, {
          clientId: body.client_id,
          redirectUri: 'https://app.example/cb',
        })
        const form = {
          grant_type: 'authorization_code',
          code: code!,
          code_verifier: verifier,
          redirect_uri: 'https://app.example/cb',
        }
        const wrong = await token(h, form, { authorization: `Basic ${btoa(`${body.client_id}:nope`)}` })
        expect(wrong.status).toBe(401)
        expect(wrong.body.error).toBe('invalid_client')
        expect(wrong.res.headers.get('www-authenticate')).toContain('Basic')
        const ok = await token(h, form, {
          authorization: `Basic ${btoa(`${body.client_id}:${body.client_secret}`)}`,
        })
        expect(ok.status).toBe(200)
      })

      it('validates registration metadata', async () => {
        const post = (json: unknown) => h.client.post('/oauth/register/', { csrf: false, json })
        let res = await post({ redirect_uris: ['http://app.example/cb'] })
        expect(res.status).toBe(400)
        expect(((await res.json()) as any).error).toBe('invalid_redirect_uri')
        res = await post({ redirect_uris: ['javascript:alert(1)'] })
        expect(((await res.json()) as any).error).toBe('invalid_redirect_uri')
        res = await post({ redirect_uris: ['https://a.example/cb'], grant_types: ['client_credentials'] })
        expect(((await res.json()) as any).error).toBe('invalid_client_metadata')
        res = await post({ redirect_uris: ['https://a.example/cb'], scope: 'admin' })
        expect(((await res.json()) as any).error).toBe('invalid_scope')
      })

      it('rate limits registrations per IP', async () => {
        h.oauth.REGISTRATION_RATE = '2/hour'
        const post = () =>
          h.client.post('/oauth/register/', {
            csrf: false,
            json: { redirect_uris: ['https://a.example/cb'], token_endpoint_auth_method: 'none' },
          })
        expect((await post()).status).toBe(201)
        expect((await post()).status).toBe(201)
        const res = await post()
        expect(res.status).toBe(429)
        expect(res.headers.get('retry-after')).toMatch(/^\d+$/)
      })
    })

    describe('authorize and consent', () => {
      async function publicClient(extra: Record<string, unknown> = {}) {
        const { application } = await createApplication({
          name: 'Test App',
          redirectUris: ['https://app.example/cb'],
          ...extra,
        })
        return application
      }

      it('sends anonymous users to the login page and back', async () => {
        const app = await publicClient()
        const { url } = await authorizeUrl({ clientId: app.clientId, redirectUri: 'https://app.example/cb' })
        const res = await h.client.get(url)
        expect(res.status).toBe(302)
        const loc = new URL(res.headers.get('location')!, ORIGIN)
        expect(loc.pathname).toBe('/accounts/login/')
        expect(loc.searchParams.get('next')).toBe(url)
      })

      it('shows the client, scopes and redirect host; Allow redirects with code, state and iss', async () => {
        const app = await publicClient()
        await loggedIn(h)
        const { url } = await authorizeUrl({
          clientId: app.clientId,
          redirectUri: 'https://app.example/cb',
          scope: 'theme:write',
          state: 'xyz',
        })
        const res = await h.client.get(url)
        expect(res.status).toBe(200)
        expect(res.headers.get('x-frame-options')).toBe('DENY')
        const html = await res.text()
        expect(html).toContain('Test App')
        expect(html).toContain('Edit your theme')
        expect(html).toContain('app.example')
        const done = await h.client.post(url, { form: { request: formField(html, 'request'), allow: '1' } })
        const loc = new URL(done.headers.get('location')!)
        expect(loc.origin + loc.pathname).toBe('https://app.example/cb')
        expect(loc.searchParams.get('code')).toEqual(expect.any(String))
        expect(loc.searchParams.get('state')).toBe('xyz')
        expect(loc.searchParams.get('iss')).toBe(ORIGIN)
      })

      it('Deny redirects with access_denied and iss', async () => {
        const app = await publicClient()
        await loggedIn(h)
        const { url } = await authorizeUrl({ clientId: app.clientId, redirectUri: 'https://app.example/cb' })
        const html = await (await h.client.get(url)).text()
        const res = await h.client.post(url, { form: { request: formField(html, 'request'), deny: '1' } })
        const loc = new URL(res.headers.get('location')!)
        expect(loc.searchParams.get('error')).toBe('access_denied')
        expect(loc.searchParams.get('iss')).toBe(ORIGIN)
        expect(loc.searchParams.get('state')).toBe('st-1')
      })

      it('refuses a consent form posted by another user or without CSRF', async () => {
        const app = await publicClient()
        await loggedIn(h, 'ann')
        const { url } = await authorizeUrl({ clientId: app.clientId, redirectUri: 'https://app.example/cb' })
        const pending = formField(await (await h.client.get(url)).text(), 'request')
        expect(
          (await h.client.post(url, { form: { request: pending, allow: '1' }, csrf: false })).status,
        ).toBe(403)
        await loggedIn(h, 'bob')
        const res = await h.client.post(url, { form: { request: pending, allow: '1' } })
        expect(res.status).toBe(400)
        expect(await Grant.objects.count()).toBe(0)
      })

      it('redirects protocol errors once the redirect URI is trusted', async () => {
        const app = await publicClient()
        await loggedIn(h)
        const base = new URLSearchParams({
          response_type: 'code',
          client_id: app.clientId,
          redirect_uri: 'https://app.example/cb',
          state: 's',
        })
        const go = async (extra: Record<string, string>) => {
          const q = new URLSearchParams(base)
          for (const [k, v] of Object.entries(extra)) q.set(k, v)
          const res = await h.client.get(`/oauth/authorize/?${q}`)
          expect(res.status).toBe(302)
          return new URL(res.headers.get('location')!).searchParams
        }
        let p = await go({})
        expect([p.get('error'), p.get('iss'), p.get('state')]).toEqual(['invalid_request', ORIGIN, 's'])
        p = await go({ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' })
        expect(p.get('error_description')).toContain('S256')
        p = await go({
          code_challenge: 'a'.repeat(43),
          code_challenge_method: 'S256',
          response_type: 'token',
        })
        expect(p.get('error')).toBe('unsupported_response_type')
        p = await go({ code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', scope: 'admin' })
        expect(p.get('error')).toBe('invalid_scope')
        p = await go({
          code_challenge: 'a'.repeat(43),
          code_challenge_method: 'S256',
          resource: 'https://other.example/mcp',
        })
        expect(p.get('error')).toBe('invalid_target')
      })

      it('shows unknown clients and redirect URIs as an error page, never a redirect', async () => {
        await loggedIn(h)
        const app = await publicClient()
        for (const p of [
          { clientId: 'nope', redirectUri: 'https://app.example/cb' },
          { clientId: app.clientId, redirectUri: 'https://app.example/other' },
          { clientId: app.clientId, redirectUri: 'https://app.example:8443/cb' },
        ]) {
          const res = await h.client.get((await authorizeUrl(p)).url)
          expect(res.status).toBe(400)
          expect(res.headers.get('location')).toBeNull()
        }
      })

      it('passes request, client and user to a consent hook, which approves with props', async () => {
        const app = await publicClient()
        const user = await loggedIn(h)
        const seen: any[] = []
        h.oauth.CONSENT_HANDLER = async (ctx: any) => {
          seen.push({
            client: ctx.client.clientId,
            user: ctx.user.pk,
            scopes: ctx.request.scopes,
            resource: ctx.request.resource,
          })
          if (!ctx.form)
            return new Response(`<input name="request" value="${ctx.pending}">`, {
              headers: { 'content-type': 'text/html' },
            })
          return ctx.approve({ scope: ['theme:read'], props: { storeId: ctx.form.store } })
        }
        const { url, verifier } = await authorizeUrl({
          clientId: app.clientId,
          redirectUri: 'https://app.example/cb',
          resource: MCP,
        })
        const html = await (await h.client.get(url)).text()
        const res = await h.client.post(url, {
          form: { request: formField(html, 'request'), store: 'st_42' },
        })
        const code = new URL(res.headers.get('location')!).searchParams.get('code')!
        expect(seen[0]).toEqual({
          client: app.clientId,
          user: user.pk,
          scopes: ['theme:read', 'theme:write'],
          resource: MCP,
        })
        const t = await token(h, {
          grant_type: 'authorization_code',
          client_id: app.clientId,
          code,
          code_verifier: verifier,
          redirect_uri: 'https://app.example/cb',
        })
        expect(t.body.scope).toBe('theme:read')
        const info = await verifyAccessToken(t.body.access_token, { audience: MCP })
        expect(info?.props).toEqual({ storeId: 'st_42' })
        expect(info?.user.pk).toBe(user.pk)

        // A second authorization for the same scopes is approved without asking, keeping the props.
        seen.length = 0
        const again = await authorize(h, {
          clientId: app.clientId,
          redirectUri: 'https://app.example/cb',
          resource: MCP,
          scope: 'theme:read',
        })
        expect(again.code).toEqual(expect.any(String))
        expect(seen).toEqual([])
        expect((await Grant.objects.orderBy('-id').first())!.props).toEqual({ storeId: 'st_42' })
      })

      it('skips consent for skipAuthorization clients; prompt=none reports consent_required', async () => {
        const app = await publicClient()
        await loggedIn(h)
        const { url } = await authorizeUrl({
          clientId: app.clientId,
          redirectUri: 'https://app.example/cb',
          extra: { prompt: 'none' },
        })
        const res = await h.client.get(url)
        expect(new URL(res.headers.get('location')!).searchParams.get('error')).toBe('consent_required')
        const trusted = await publicClient({ skipAuthorization: true })
        const ok = await h.client.get(
          (await authorizeUrl({ clientId: trusted.clientId, redirectUri: 'https://app.example/cb' })).url,
        )
        expect(new URL(ok.headers.get('location')!).searchParams.get('code')).toEqual(expect.any(String))
      })
    })

    describe('token endpoint', () => {
      async function setup() {
        const { application } = await createApplication({
          name: 'App',
          redirectUris: ['https://app.example/cb'],
        })
        const user = await loggedIn(h)
        return {
          app: application,
          user,
          p: { clientId: application.clientId, redirectUri: 'https://app.example/cb', resource: MCP },
        }
      }

      it('exchanges a code with the right PKCE verifier only', async () => {
        const { p } = await setup()
        const { code, verifier } = await authorize(h, p)
        const base = {
          grant_type: 'authorization_code',
          client_id: p.clientId,
          code: code!,
          redirect_uri: p.redirectUri,
        }
        const bad = await token(h, { ...base, code_verifier: `${verifier.slice(0, -1)}x` })
        expect(bad.status).toBe(400)
        expect(bad.body).toMatchObject({
          error: 'invalid_grant',
          error_description: 'PKCE verification failed.',
        })
        expect(bad.res.headers.get('cache-control')).toBe('no-store')
        // the code was burnt by the failed attempt
        const again = await token(h, { ...base, code_verifier: verifier })
        expect(again.body.error).toBe('invalid_grant')
      })

      it('requires a verifier, form encoding and the same redirect_uri and resource', async () => {
        const { p } = await setup()
        const a = await authorize(h, p)
        expect(
          (
            await token(h, {
              grant_type: 'authorization_code',
              client_id: p.clientId,
              code: a.code!,
              redirect_uri: p.redirectUri,
            })
          ).body.error,
        ).toBe('invalid_request')
        const json = await h.client.post('/oauth/token/', {
          csrf: false,
          json: { grant_type: 'authorization_code' },
        })
        expect(((await json.json()) as any).error).toBe('invalid_request')
        const b = await authorize(h, p)
        expect(
          (
            await token(h, {
              grant_type: 'authorization_code',
              client_id: p.clientId,
              code: b.code!,
              code_verifier: b.verifier,
              redirect_uri: 'https://app.example/x',
            })
          ).body.error,
        ).toBe('invalid_grant')
        const c = await authorize(h, p)
        const wrongResource = await token(h, {
          grant_type: 'authorization_code',
          client_id: p.clientId,
          code: c.code!,
          code_verifier: c.verifier,
          redirect_uri: p.redirectUri,
          resource: `${ORIGIN}/other`,
        })
        expect(wrongResource.body.error).toBe('invalid_target')
      })

      it('revokes the grant when a code is replayed', async () => {
        const { p } = await setup()
        const { code, verifier } = await authorize(h, p)
        const form = {
          grant_type: 'authorization_code',
          client_id: p.clientId,
          code: code!,
          code_verifier: verifier,
          redirect_uri: p.redirectUri,
        }
        const first = await token(h, form)
        expect(first.status).toBe(200)
        const replay = await token(h, form)
        expect(replay.body.error).toBe('invalid_grant')
        expect(await verifyAccessToken(first.body.access_token, { audience: MCP })).toBeNull()
        const refresh = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: first.body.refresh_token,
        })
        expect(refresh.body.error).toBe('invalid_grant')
      })

      it('rejects expired codes and codes of other clients', async () => {
        const { p } = await setup()
        const other = (await createApplication({ redirectUris: ['https://app.example/cb'] })).application
        const a = await authorize(h, p)
        const stolen = await token(h, {
          grant_type: 'authorization_code',
          client_id: other.clientId,
          code: a.code!,
          code_verifier: a.verifier,
          redirect_uri: p.redirectUri,
        })
        expect(stolen.body.error).toBe('invalid_grant')
        h.oauth.AUTHORIZATION_CODE_EXPIRE_SECONDS = -1
        const b = await authorize(h, p)
        const expired = await token(h, {
          grant_type: 'authorization_code',
          client_id: p.clientId,
          code: b.code!,
          code_verifier: b.verifier,
          redirect_uri: p.redirectUri,
        })
        expect(expired.body.error_description).toContain('expired')
      })

      it('rotates refresh tokens and revokes the grant on reuse', async () => {
        const { p } = await setup()
        const t1 = await obtainTokens(h, p)
        const r2 = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t1.refresh_token,
        })
        expect(r2.status).toBe(200)
        expect(r2.body.refresh_token).not.toBe(t1.refresh_token)
        expect(await verifyAccessToken(r2.body.access_token, { audience: MCP })).not.toBeNull()
        const r3 = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: r2.body.refresh_token,
        })
        expect(r3.status).toBe(200)
        // An attacker replays the first refresh token: the whole grant dies.
        const reuse = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t1.refresh_token,
        })
        expect(reuse.body).toMatchObject({ error: 'invalid_grant' })
        const after = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: r3.body.refresh_token,
        })
        expect(after.body.error).toBe('invalid_grant')
        expect(await verifyAccessToken(r3.body.access_token, { audience: MCP })).toBeNull()
        expect((await Grant.objects.first())!.revoked).not.toBeNull()
        expect(await RefreshToken.objects.filter({ revoked__isnull: true }).count()).toBe(0)
      })

      it('tolerates a lost refresh response within the grace period', async () => {
        const { p } = await setup()
        h.oauth.REFRESH_TOKEN_GRACE_PERIOD_SECONDS = 30
        const t1 = await obtainTokens(h, p)
        const r2 = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t1.refresh_token,
        })
        const retry = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t1.refresh_token,
        })
        expect(retry.status).toBe(200)
        // the lost successor is retired, the retry's token works
        expect(
          (
            await token(h, {
              grant_type: 'refresh_token',
              client_id: p.clientId,
              refresh_token: r2.body.refresh_token,
            })
          ).body.error,
        ).toBe('invalid_grant')
        expect(
          (
            await token(h, {
              grant_type: 'refresh_token',
              client_id: p.clientId,
              refresh_token: retry.body.refresh_token,
            })
          ).status,
        ).toBe(200)
      })

      it('narrows scope on refresh but never widens it; refuses dead refresh tokens', async () => {
        const { p } = await setup()
        const t1 = await obtainTokens(h, { ...p, scope: 'theme:read theme:write' })
        const narrow = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t1.refresh_token,
          scope: 'theme:read',
        })
        expect(narrow.body.scope).toBe('theme:read')
        // the new refresh token keeps the full scope
        const full = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: narrow.body.refresh_token,
        })
        expect(full.body.scope).toBe('theme:read theme:write')
        const t2 = await obtainTokens(h, { ...p, scope: 'theme:read' })
        const wide = await token(h, {
          grant_type: 'refresh_token',
          client_id: p.clientId,
          refresh_token: t2.refresh_token,
          scope: 'theme:write',
        })
        expect(wide.body.error).toBe('invalid_scope')
        expect(
          (await token(h, { grant_type: 'refresh_token', client_id: p.clientId, refresh_token: 'garbage' }))
            .body.error,
        ).toBe('invalid_grant')
        h.oauth.REFRESH_TOKEN_EXPIRE_SECONDS = -1
        const t3 = await obtainTokens(h, p)
        expect(
          (
            await token(h, {
              grant_type: 'refresh_token',
              client_id: p.clientId,
              refresh_token: t3.refresh_token,
            })
          ).body.error,
        ).toBe('invalid_grant')
      })

      it('refuses unsupported grant types and unknown clients', async () => {
        const { p } = await setup()
        expect((await token(h, { grant_type: 'password', client_id: p.clientId })).body.error).toBe(
          'unsupported_grant_type',
        )
        const unknown = await token(h, {
          grant_type: 'refresh_token',
          client_id: 'ghost',
          refresh_token: 'x',
        })
        expect(unknown.status).toBe(401)
        expect(unknown.body.error).toBe('invalid_client')
      })
    })

    describe('revocation and audience', () => {
      async function tokens(scope?: string) {
        const { application } = await createApplication({ redirectUris: ['https://app.example/cb'] })
        await loggedIn(h)
        const p = {
          clientId: application.clientId,
          redirectUri: 'https://app.example/cb',
          resource: MCP,
          scope,
        }
        return { p, t: await obtainTokens(h, p) }
      }

      it('revokes the grant from a refresh token (RFC 7009)', async () => {
        const { p, t } = await tokens()
        const res = await h.client.post('/oauth/revoke_token/', {
          csrf: false,
          form: { token: t.refresh_token, client_id: p.clientId },
        })
        expect(res.status).toBe(200)
        expect(await verifyAccessToken(t.access_token, { audience: MCP })).toBeNull()
        expect(
          (
            await token(h, {
              grant_type: 'refresh_token',
              client_id: p.clientId,
              refresh_token: t.refresh_token,
            })
          ).body.error,
        ).toBe('invalid_grant')
      })

      it('revokes from an access token; unknown tokens and other clients answer 200 without effect', async () => {
        const { p, t } = await tokens()
        const other = (await createApplication({ redirectUris: ['https://x.example/cb'] })).application
        const post = (form: Record<string, string>) =>
          h.client.post('/oauth/revoke_token/', { csrf: false, form })
        expect((await post({ token: t.access_token, client_id: other.clientId })).status).toBe(200)
        expect(await verifyAccessToken(t.access_token, { audience: MCP })).not.toBeNull()
        expect((await post({ token: 'nonsense', client_id: p.clientId })).status).toBe(200)
        expect(
          (await post({ token: t.access_token, client_id: p.clientId, token_type_hint: 'access_token' }))
            .status,
        ).toBe(200)
        expect(await verifyAccessToken(t.access_token, { audience: MCP })).toBeNull()
      })

      it('binds access tokens to the resource (RFC 8707)', async () => {
        const { t } = await tokens()
        const claims = JSON.parse(atob(t.access_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
        expect(claims).toMatchObject({
          aud: MCP,
          iss: ORIGIN,
          client_id: expect.any(String),
          scope: 'theme:read theme:write',
        })
        expect(JSON.parse(atob(t.access_token.split('.')[0]))).toMatchObject({ typ: 'at+jwt', alg: 'HS256' })
        expect(await verifyAccessToken(t.access_token, { audience: `${ORIGIN}/mcp/` })).not.toBeNull()
        expect(await verifyAccessToken(t.access_token, { audience: `${ORIGIN}/other` })).toBeNull()
        expect(await verifyAccessToken(t.access_token, { audience: 'https://testserver/mcp' })).toBeNull()
        expect(await verifyAccessToken(`${t.access_token}x`, { audience: MCP })).toBeNull()
      })

      it('allows foreign resources only through RESOURCES', async () => {
        h.oauth.RESOURCES = ['https://mcp.example.com/*']
        const { application } = await createApplication({ redirectUris: ['https://app.example/cb'] })
        await loggedIn(h)
        const t = await obtainTokens(h, {
          clientId: application.clientId,
          redirectUri: 'https://app.example/cb',
          resource: 'https://mcp.example.com/mcp',
        })
        expect(
          await verifyAccessToken(t.access_token, { audience: 'https://mcp.example.com/mcp' }),
        ).not.toBeNull()
        const r = await authorize(h, {
          clientId: application.clientId,
          redirectUri: 'https://app.example/cb',
          resource: MCP,
        })
        expect(r.location.searchParams.get('error')).toBe('invalid_target')
      })

      it('signs with an asymmetric key and serves the JWKS', async () => {
        const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
          'sign',
          'verify',
        ])) as CryptoKeyPair
        h.oauth.ACCESS_TOKEN_SIGNING_KEY = {
          ...(await crypto.subtle.exportKey('jwk', pair.privateKey)),
          kid: 'k1',
        }
        const jwks = (await (await h.client.get('/.well-known/jwks.json')).json()) as any
        expect(jwks.keys[0]).toMatchObject({ kid: 'k1', alg: 'ES256', use: 'sig', kty: 'EC' })
        expect(jwks.keys[0].d).toBeUndefined()
        const meta = (await (await h.client.get('/.well-known/oauth-authorization-server')).json()) as any
        expect(meta.jwks_uri).toBe(`${ORIGIN}/.well-known/jwks.json`)
        const { t } = await tokens()
        expect(JSON.parse(atob(t.access_token.split('.')[0]))).toMatchObject({
          alg: 'ES256',
          typ: 'at+jwt',
          kid: 'k1',
        })
        expect(await verifyAccessToken(t.access_token, { audience: MCP })).not.toBeNull()
      })

      it('stores only hashes', async () => {
        const { t } = await tokens()
        const row = await RefreshToken.objects.first()
        expect(row!.tokenHash).not.toBe(t.refresh_token)
        expect(row!.tokenHash).toHaveLength(43)
      })
    })
  })
}
