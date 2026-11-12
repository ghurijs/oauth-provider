// The provider bundle on workerd with D1: WebCrypto HKDF/HMAC tokens, hashed storage, rotation.
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { Miniflare } from 'miniflare'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

describe('oauth provider on workerd', () => {
  let mf: Miniflare
  beforeAll(async () => {
    const out = await build({
      entryPoints: [fileURLToPath(new URL('./fixtures/worker.ts', import.meta.url))],
      bundle: true,
      format: 'esm',
      platform: 'neutral',
      target: 'es2022',
      mainFields: ['module', 'main'],
      conditions: ['workerd', 'worker', 'browser', 'import'],
      external: ['node:*', 'cloudflare:*', 'postgres'],
      write: false,
      logLevel: 'silent',
    })
    mf = new Miniflare({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: '2025-06-01',
      compatibilityFlags: ['nodejs_compat'],
      d1Databases: { DB: `oauth-provider-${crypto.randomUUID()}` },
    })
  }, 60_000)
  afterAll(async () => {
    await mf?.dispose()
  })

  it('discovers, registers, issues, verifies and rotates', async () => {
    expect((await mf.dispatchFetch('https://example.com/__setup/')).status).toBe(200)
    const meta = (await (
      await mf.dispatchFetch('https://example.com/.well-known/oauth-authorization-server')
    ).json()) as any
    expect(meta.issuer).toBe('https://example.com')
    const reg = await mf.dispatchFetch(meta.registration_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: ['http://127.0.0.1/cb'], token_endpoint_auth_method: 'none' }),
    })
    expect(reg.status).toBe(201)
    const { client_id } = (await reg.json()) as any
    const t = (await (
      await mf.dispatchFetch(`https://example.com/__grant/?client_id=${client_id}`)
    ).json()) as any
    const mcp = await mf.dispatchFetch('https://example.com/mcp', {
      headers: { authorization: `Bearer ${t.access_token}` },
    })
    expect(await mcp.json()).toEqual({ scopes: ['read'], runtime: 'Cloudflare-Workers' })
    const refresh = (body: Record<string, string>) =>
      mf.dispatchFetch(meta.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(body).toString(),
      })
    const r2 = await refresh({ grant_type: 'refresh_token', client_id, refresh_token: t.refresh_token })
    expect(r2.status).toBe(200)
    const reuse = await refresh({ grant_type: 'refresh_token', client_id, refresh_token: t.refresh_token })
    expect(((await reuse.json()) as any).error).toBe('invalid_grant')
    const after = await mf.dispatchFetch('https://example.com/mcp', {
      headers: { authorization: `Bearer ${t.access_token}` },
    })
    expect(after.status).toBe(401)
  })
})
