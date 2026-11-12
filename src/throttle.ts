// A small per-IP rate limit on the default cache (no @ghuri/rest dependency), for dynamic registration.
import { caches, getRemoteAddr } from '@ghuri/core'
import type { Context } from 'hono'

function parseRate(rate: string): [number, number] {
  const [num, period] = rate.split('/')
  const m = /^(\d*)\s*([smhd])/i.exec((period ?? '').trim())
  const n = Number.parseInt(num, 10)
  if (!m || !Number.isFinite(n)) throw new Error(`Invalid rate '${rate}'.`)
  const mult = m[1] ? Number.parseInt(m[1], 10) : 1
  return [n, { s: 1, m: 60, h: 3600, d: 86400 }[m[2].toLowerCase() as 's']! * mult]
}

/** Count a request against `rate` for this client IP; returns the seconds to wait, or 0 when allowed. */
export async function throttle(c: Context, scope: string, rate: string | null): Promise<number> {
  if (!rate) return 0
  const [limit, duration] = parseRate(rate)
  let ip = ''
  try {
    ip = getRemoteAddr(c)
  } catch {
    ip = ''
  }
  const cache = caches.get('default')
  const key = `oauth2_provider_${scope}_${ip || 'unknown'}`
  const now = Date.now() / 1000
  const history = ((await cache.get<number[]>(key)) ?? []).filter((t) => t > now - duration)
  if (history.length >= limit) return Math.max(1, Math.ceil(history[history.length - 1] + duration - now))
  history.unshift(now)
  await cache.set(key, history, duration)
  return 0
}
