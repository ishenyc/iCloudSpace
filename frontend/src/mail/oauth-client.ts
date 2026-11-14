import type { FetchImplementation } from '../transport/types.ts'

export const oauthTokenPath = '/oauth/token'
export const oauthScopes = ['mail_read', 'mail_consume', 'raw_read', 'imap_login'] as const
export type OAuthScope = typeof oauthScopes[number]
export interface OAuthRefreshRequest { client_id: string; refresh_token: string; scope?: readonly OAuthScope[] }
export interface OAuthToken { access_token: string; token_type: 'Bearer'; expires_in: 3600; scope: string }
export interface OAuthTokenOptions { fetch?: FetchImplementation }
type OAuthCode = 'invalid_request' | 'unsupported_grant_type' | 'invalid_scope' | 'invalid_grant' | 'server_error' | 'temporarily_unavailable'
const codes: readonly string[] = ['invalid_request', 'unsupported_grant_type', 'invalid_scope', 'invalid_grant', 'server_error', 'temporarily_unavailable']

/** Carries no supplied credential, response text or native exception. An
 * unknown exchange is never retried automatically, including after body loss. */
export class OAuthTokenError extends Error {
  readonly category: 'input' | 'transport' | 'response' | 'oauth'
  readonly outcome: 'not_sent' | 'rejected' | 'unknown'
  readonly code?: OAuthCode
  readonly status?: number
  constructor(category: OAuthTokenError['category'], outcome: OAuthTokenError['outcome'], code?: OAuthCode, status?: number) {
    super(category === 'input' ? 'Invalid OAuth refresh request.' : 'OAuth refresh could not be completed.')
    this.name = 'OAuthTokenError'; this.category = category; this.outcome = outcome; this.code = code; this.status = status
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('shape')
  return value as Record<string, unknown>
}
function secret(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000\r\n]/.test(value) || new TextEncoder().encode(value).length > 4096) return false
  // TextEncoder replaces unpaired surrogates. Reject them instead of changing
  // the original long-lived bytes while constructing form data.
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)
}
function scopes(value: unknown): OAuthScope[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > oauthScopes.length) throw new Error('scope')
  const result: OAuthScope[] = []
  for (const scope of value) {
    if (typeof scope !== 'string' || !(oauthScopes as readonly string[]).includes(scope) || result.includes(scope as OAuthScope)) throw new Error('scope')
    result.push(scope as OAuthScope)
  }
  return result
}

async function readJSON(response: Response): Promise<unknown> {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || !response.body) throw new Error('media')
  const reader = response.body.getReader(), chunks: Uint8Array[] = []
  let size = 0
  try {
    for (;;) {
      const next = await reader.read()
      if (next.done) break
      size += next.value.byteLength
      if (size > 16384) { await reader.cancel().catch(() => {}); throw new Error('size') }
      chunks.push(next.value)
    }
  } finally { reader.releaseLock() }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown
}

/** One explicit, memory-only exchange. This client has no cookie/session/CSRF,
 * storage, fallback endpoint, refresh timer, redirect or retry mechanism. */
export class OAuthTokenClient {
  #fetch?: FetchImplementation
  constructor(options: OAuthTokenOptions = {}) { this.#fetch = options.fetch }
  async refresh(request: OAuthRefreshRequest, signal?: AbortSignal): Promise<OAuthToken> {
    let form: URLSearchParams, requested: OAuthScope[] | undefined
    try {
      const input = object(request)
      if (Object.keys(input).some(key => !['client_id', 'refresh_token', 'scope'].includes(key)) || !secret(input.client_id) || !secret(input.refresh_token)) throw new Error('input')
      requested = input.scope === undefined ? undefined : scopes(input.scope)
      form = new URLSearchParams({ grant_type: 'refresh_token', client_id: input.client_id, refresh_token: input.refresh_token })
      if (requested) form.set('scope', requested.join(' '))
      if (new TextEncoder().encode(form.toString()).length > 16384) throw new Error('size')
    } catch { throw new OAuthTokenError('input', 'not_sent') }
    if (signal?.aborted) throw new OAuthTokenError('transport', 'not_sent')
    let response: Response
    try {
      const fetcher = this.#fetch ?? globalThis.fetch
      if (typeof fetcher !== 'function') throw new Error('fetch')
      response = await fetcher(oauthTokenPath, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: form.toString(), credentials: 'omit', redirect: 'error', cache: 'no-store', signal })
    } catch { throw new OAuthTokenError('transport', 'unknown') }
    let data: Record<string, unknown>
    try { data = object(await readJSON(response)) } catch { throw new OAuthTokenError('response', 'unknown', undefined, response.status) }
    if (response.status !== 200) {
      if (typeof data.error !== 'string' || !codes.includes(data.error) || (data.error_description !== undefined && typeof data.error_description !== 'string')) throw new OAuthTokenError('response', 'unknown', undefined, response.status)
      const code = data.error as OAuthCode
      throw new OAuthTokenError('oauth', code === 'server_error' || code === 'temporarily_unavailable' ? 'unknown' : 'rejected', code, response.status)
    }
    try {
      if (!secret(data.access_token) || /[^\x21-\x7e]/.test(data.access_token) || data.token_type !== 'Bearer' || data.expires_in !== 3600 || typeof data.scope !== 'string') throw new Error('token')
      const actual = scopes(data.scope.split(' '))
      if (requested && actual.some(scope => !requested.includes(scope))) throw new Error('scope')
      return { access_token: data.access_token, token_type: 'Bearer', expires_in: 3600, scope: actual.join(' ') }
    } catch { throw new OAuthTokenError('response', 'unknown', undefined, response.status) }
  }
}
