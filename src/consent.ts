// The consent step: the default page, and the hook apps use to show their own (store pickers, account choosers).
import { escapeHtml, getCsrfToken, type RequestUser } from '@ghuri/core'
import type { Context } from 'hono'
import type { Application } from './models'
import { isLoopbackHost } from './validation'

/** A validated authorization request. */
export interface AuthorizationRequest {
  clientId: string
  /** The redirect URI the response goes to. */
  redirectUri: string
  /** The `redirect_uri` parameter as sent ('' when the request omitted it). */
  redirectUriParam: string
  responseType: 'code'
  /** Requested scopes (after `DEFAULT_SCOPES`). */
  scopes: string[]
  state?: string
  codeChallenge: string
  codeChallengeMethod: 'S256'
  /** Canonical resource indicator: the access token audience. */
  resource: string
  prompt?: string
}

export interface ApproveOptions {
  /** Scopes to grant: a subset of the requested ones (default: all requested). */
  scope?: string[]
  /** App-defined data stored on the grant and returned by `verifyAccessToken()` (a store id, a tenant…). */
  props?: Record<string, unknown>
}

export interface ConsentContext {
  c: Context
  request: AuthorizationRequest
  client: Application
  user: RequestUser
  /** Requested scopes with their `OAUTH2_PROVIDER.SCOPES` descriptions. */
  scopes: Array<{ name: string; description: string }>
  /** The sealed request: post it back as the `request` field of your form. */
  pending: string
  /** Where to post the consent form (the authorize URL). */
  action: string
  /** The submitted form fields on POST; undefined on GET. */
  form?: Record<string, string>
  /** Grant access and redirect back to the client with a code. */
  approve(opts?: ApproveOptions): Promise<Response>
  /** Redirect back with `error=access_denied`. */
  deny(description?: string): Response
}

/** Shows the consent page (GET) and handles its form (POST). Return any Response. */
export type ConsentHandler = (ctx: ConsentContext) => Response | Promise<Response>

function csrfInput(c: Context): string {
  try {
    return `<input type="hidden" name="csrfmiddlewaretoken" value="${escapeHtml(getCsrfToken(c))}">`
  } catch {
    return ''
  }
}

/** Response headers for pages that must never be framed or cached. */
export const PAGE_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'cache-control': 'no-store',
  'x-frame-options': 'DENY',
  'content-security-policy': "frame-ancestors 'none'",
}

export function page(title: string, body: string, status = 200): Response {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1rem;color:#111}h1{font-size:1.4rem}ul{padding-left:1.2rem}.host{font-family:ui-monospace,monospace;background:#f3f4f6;padding:.1rem .3rem;border-radius:.25rem}.warn{color:#92400e}.actions{display:flex;gap:.75rem;margin-top:1.5rem}button{font:inherit;padding:.5rem 1.2rem;cursor:pointer;border-radius:.4rem;border:1px solid #d1d5db;background:#fff}button.primary{background:#111;color:#fff;border-color:#111}@media (prefers-color-scheme:dark){body{background:#111;color:#eee}.host{background:#333}button{background:#222;color:#eee;border-color:#444}button.primary{background:#eee;color:#111}}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`
  return new Response(html, { status, headers: PAGE_HEADERS })
}

/** The default consent page and form handling. */
export const defaultConsentHandler: ConsentHandler = async (ctx) => {
  if (ctx.form) return 'allow' in ctx.form ? ctx.approve() : ctx.deny()
  const name = escapeHtml(ctx.client.name || ctx.client.clientId)
  const redirect = new URL(ctx.request.redirectUri)
  const host = redirect.host || redirect.protocol
  const loopback = isLoopbackHost(redirect.hostname)
  const scopes = ctx.scopes.length
    ? `<p>It will be able to:</p><ul>${ctx.scopes
        .map((s) => `<li>${escapeHtml(s.description || s.name)}</li>`)
        .join('')}</ul>`
    : ''
  const userName = escapeHtml((ctx.user as any).getUsername?.() ?? (ctx.user as any).username ?? '')
  const body = `<p><strong>${name}</strong> wants to access your account${userName ? ` (${userName})` : ''}.</p>
${scopes}
<p>You will be sent back to <span class="host">${escapeHtml(host)}</span>.</p>
${loopback ? '<p class="warn">This is an application running on your own computer. Only continue if you started it.</p>' : ''}
<form method="post" action="${escapeHtml(ctx.action)}">${csrfInput(ctx.c)}
<input type="hidden" name="request" value="${escapeHtml(ctx.pending)}">
<div class="actions"><button class="primary" type="submit" name="allow" value="1">Allow</button><button type="submit" name="deny" value="1">Deny</button></div>
</form>`
  return page(`Authorize ${ctx.client.name || 'application'}`, body)
}
