// Shared rules: issuer and endpoint URLs, scopes, resource indicators (RFC 8707), redirect URIs (RFC 8252 loopback).
import { getHost, isSecure } from '@ghuri/core'
import { b64url, sha256 } from '@ghuri/oauth'
import type { Context } from 'hono'
import { OAuth2Error } from './errors'
import { providerSettings } from './settings'

/** `b64url(sha256(value))`: how codes, refresh tokens and client secrets are stored. */
export async function hashToken(value: string): Promise<string> {
  return b64url(await sha256(value))
}

/** The request origin (`https://example.com`), honouring `SECURE_PROXY_SSL_HEADER` / `USE_X_FORWARDED_HOST`. */
export function requestOrigin(c: Context): string {
  return `${isSecure(c) ? 'https' : 'http'}://${getHost(c)}`
}

/** The issuer identifier: `OAUTH2_PROVIDER.ISSUER`, else the request origin. */
export function issuerFor(c: Context): string {
  const configured = providerSettings().ISSUER
  return (configured ?? requestOrigin(c)).replace(/\/+$/, '')
}

// ---- scopes ----

const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/

/** Split a `scope` parameter into unique scope tokens; `invalid_scope` on bad characters. */
export function parseScope(value: unknown): string[] {
  if (value === undefined || value === null || value === '') return []
  if (typeof value !== 'string')
    throw new OAuth2Error('invalid_scope', 'The scope parameter must be a string.')
  const out: string[] = []
  for (const s of value.split(' ').filter(Boolean)) {
    if (!SCOPE_TOKEN.test(s)) throw new OAuth2Error('invalid_scope', `Invalid scope '${s}'.`)
    if (!out.includes(s)) out.push(s)
  }
  return out
}

export function joinScope(scopes: string[]): string {
  return scopes.join(' ')
}

/**
 * The scopes to grant for a request: the requested ones (or `DEFAULT_SCOPES`), each known to `SCOPES` (when set)
 * and allowed for the client (when its `scope` is set).
 */
export function resolveScopes(requested: string[], clientScope: string): string[] {
  const s = providerSettings()
  const known = s.SCOPES
  const scopes = requested.length ? requested : (s.DEFAULT_SCOPES ?? (known ? Object.keys(known) : []))
  const allowed = clientScope.split(/\s+/).filter(Boolean)
  for (const scope of scopes) {
    if (known && !(scope in known)) throw new OAuth2Error('invalid_scope', `Unknown scope '${scope}'.`)
    if (allowed.length && !allowed.includes(scope))
      throw new OAuth2Error('invalid_scope', `The client may not request the scope '${scope}'.`)
  }
  return scopes
}

// ---- resource indicators ----

/**
 * Canonical form of a resource indicator (RFC 8707 / MCP): absolute http(s) URL without fragment, lowercase scheme
 * and host, no default port, no trailing slash. Null when the value is not an acceptable URL.
 */
export function canonicalResource(value: string): string | null {
  let u: URL
  try {
    u = new URL(value)
  } catch {
    return null
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.hash || value.includes('#')) return null
  if (u.username || u.password) return null
  const path = u.pathname.replace(/\/+$/, '')
  return `${u.protocol}//${u.host}${path}${u.search}`
}

/** Do two resource indicators name the same resource? */
export function sameResource(a: string, b: string): boolean {
  const ca = canonicalResource(a)
  return ca !== null && ca === canonicalResource(b)
}

/** Read and check the `resource` parameter(s): the canonical resource the token will be bound to. */
export async function resolveResource(c: Context, values: string[]): Promise<string> {
  const s = providerSettings()
  if (values.length > 1)
    throw new OAuth2Error('invalid_target', 'Request one resource at a time (several resource parameters).')
  const raw = values[0]
  if (!raw) {
    if (s.REQUIRE_RESOURCE) throw new OAuth2Error('invalid_target', 'The resource parameter is required.')
    return canonicalResource(s.DEFAULT_RESOURCE ?? issuerFor(c)) ?? issuerFor(c)
  }
  const resource = canonicalResource(raw)
  if (!resource)
    throw new OAuth2Error('invalid_target', 'The resource must be an absolute URL without a fragment.')
  if (!(await resourceAllowed(c, resource)))
    throw new OAuth2Error('invalid_target', `Tokens cannot be issued for the resource '${resource}'.`)
  return resource
}

async function resourceAllowed(c: Context, resource: string): Promise<boolean> {
  const rule = providerSettings().RESOURCES
  if (typeof rule === 'function') return !!(await rule(resource, c))
  if (Array.isArray(rule)) {
    return rule.some((r) => {
      if (r.endsWith('*')) return resource.startsWith(r.slice(0, -1))
      return sameResource(r, resource)
    })
  }
  return new URL(resource).origin === new URL(issuerFor(c)).origin
}

// ---- redirect URIs ----

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])
const FORBIDDEN_SCHEMES = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:', 'about:'])

export function isLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname.toLowerCase())
}

/**
 * Why a redirect URI cannot be registered, or null when it can: `https`, `http` on a loopback host, or a scheme
 * from `ALLOWED_REDIRECT_URI_SCHEMES` (native apps); never a fragment.
 */
export function redirectUriProblem(uri: string): string | null {
  let u: URL
  try {
    u = new URL(uri)
  } catch {
    return `'${uri}' is not an absolute URI.`
  }
  if (u.hash || uri.includes('#')) return `'${uri}' must not contain a fragment.`
  if (FORBIDDEN_SCHEMES.has(u.protocol)) return `The scheme of '${uri}' is not allowed.`
  if (u.protocol === 'https:') return null
  if (u.protocol === 'http:') return isLoopbackHost(u.hostname) ? null : `'${uri}' must use https.`
  const scheme = u.protocol.slice(0, -1)
  if (providerSettings().ALLOWED_REDIRECT_URI_SCHEMES.includes(scheme)) return null
  return `The scheme '${scheme}' of '${uri}' is not allowed.`
}

/**
 * Does the requested redirect URI match a registered one? Exact string comparison, except that loopback
 * `http(s)://localhost|127.0.0.1|[::1]` URIs match on any port (RFC 8252 §7.3; Claude Code, Codex).
 */
export function redirectUriMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true
  let r: URL
  let q: URL
  try {
    r = new URL(registered)
    q = new URL(requested)
  } catch {
    return false
  }
  if (!isLoopbackHost(r.hostname) || r.protocol !== q.protocol) return false
  if (r.protocol !== 'http:' && r.protocol !== 'https:') return false
  if (requested.includes('#')) return false
  return (
    r.hostname.toLowerCase() === q.hostname.toLowerCase() &&
    r.pathname === q.pathname &&
    r.search === q.search &&
    !q.username &&
    !q.password
  )
}

// ---- PKCE ----

const PKCE_VALUE = /^[A-Za-z0-9\-._~]{43,128}$/

export function validPkceValue(value: unknown): value is string {
  return typeof value === 'string' && PKCE_VALUE.test(value)
}
