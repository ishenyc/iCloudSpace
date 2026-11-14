import { ContractError, decodeIdentifier } from '../control/contracts.ts'
import { ControlError, HttpError, InvalidResponseError, RequestConfigurationError, TransportError } from '../transport/index.ts'
import type { ControlResult, FetchImplementation, RequestContext, ResponseMeta, SubmissionOutcome } from '../transport/index.ts'
import { decodeMailAccess, decodeMailAttachment, decodeMailClaimResult, decodeMailCodes, decodeMailMessage, decodeMailPage, decodeMailRender, decodeMailSnapshot,
  mailBounded, mailClaim, mailDownload, mailInput, mailInteger, mailObject, mailPageQuery, mailPart, mailPurpose, mailPurposes, mailRange, mailUID, sameMailRemote } from './contracts.ts'
import type { MailAccess, MailAttachment, MailClaim, MailClaimResult, MailCode, MailDerive, MailDownload, MailMessage, MailPage, MailPageQuery, MailRawOptions, MailReference, MailRefresh, MailSnapshot } from './contracts.ts'
import { readCodeText } from './code-text.ts'

export const publicMailBase = '/api/mail/v1'
export interface MailCredential { scheme: 'APIKey' | 'Bearer'; token: string }
export interface PublicMailOptions { credential?: MailCredential; fetch?: FetchImplementation }
const diagnostic = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/

/** An unknown consume keeps the exact original immutable facts needed by
 * queryClaim. Native transport exceptions and credential values are discarded. */
export class MailClaimError extends ControlError {
  readonly claimKey: string
  readonly reference: MailReference
  readonly status?: number
  readonly kind?: string
  readonly reason?: string
  constructor(error: ControlError, command: MailClaim) {
    super(error.category, error.code, error.message, { requestId: error.requestId, requestKey: command.claim_key,
      submissionKey: error.submissionKey, outcome: error.outcome, resource: error.resource })
    this.name = 'MailClaimError'; this.claimKey = command.claim_key; this.reference = command.reference
    if (error instanceof HttpError) { this.status = error.status; this.kind = error.kind }
    if (error instanceof TransportError) this.reason = error.reason
  }
}

/** Public authority is explicit and memory-only. No session cookie, CSRF,
 * storage, URL token, fallback endpoint, automatic refresh or replay exists. */
export class PublicMailClient {
  #credential?: MailCredential
  #fetch?: FetchImplementation
  constructor(options: PublicMailOptions = {}) {
    this.#fetch = options.fetch
    if (options.credential !== undefined) {
      this.#credential = mailInput(() => {
        const data = mailObject(options.credential)
        if (data.scheme !== 'APIKey' && data.scheme !== 'Bearer') throw new ContractError('mail_credential')
        const token = mailBounded(data.token, 4096, false)
        if (/[^\x20-\x7e]|^ | $/.test(token)) throw new ContractError('mail_credential')
        return { scheme: data.scheme, token }
      })
    }
  }
  latest(addressID: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> { return this.#snapshot(addressID, 'latest', signal) }
  recent(addressID: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> { return this.#snapshot(addressID, 'recent', signal) }
  message(addressID: string, uid: number, signal?: AbortSignal): Promise<ControlResult<MailMessage>> {
    uid = mailInput(() => mailUID(uid))
    return this.#json(addressID, '/messages/' + uid, { signal, decode: value => {
      const result = decodeMailMessage(value)
      if (result.metadata.uid !== uid) throw new ContractError('mail_message_scope')
      return result
    } })
  }
  codes(addressID: string, limit = 100, signal?: AbortSignal): Promise<ControlResult<MailCode[]>> {
    addressID = mailInput(() => decodeIdentifier(addressID)); limit = mailInput(() => mailInteger(limit, 1, 100))
    return this.#json(addressID, '/codes', { signal, search: { limit }, decode: value => { const result = decodeMailCodes(value); if (result.length > limit) throw new ContractError('mail_codes_limit'); return result } })
  }
  async latestCodeText(addressID: string, signal?: AbortSignal): Promise<string | null> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const context: RequestContext = { resource: { kind: 'address', id: addressID } }
    const response = await this.#send(addressID, '/codes/latest/text', { signal, accept: 'text/plain' }, context)
    const correlated = this.#context(response, context)
    if (!response.ok) await this.#envelope(response, correlated, value => value, signal)
    return readCodeText(response, correlated, signal)
  }
  messages(addressID: string, query: MailPageQuery = {}, signal?: AbortSignal): Promise<ControlResult<MailPage>> { return this.#page(addressID, '/messages', query, signal) }
  rawCandidates(addressID: string, query: MailPageQuery = {}, signal?: AbortSignal): Promise<ControlResult<MailPage>> { return this.#page(addressID, '/raw/messages', query, signal) }
  rawMessage(addressID: string, uid: number, signal?: AbortSignal): Promise<ControlResult<MailMessage>> {
    uid = mailInput(() => mailUID(uid))
    return this.#json(addressID, '/raw/messages/' + uid + '/view', { signal, decode: value => {
      const result = decodeMailMessage(value)
      if (result.metadata.uid !== uid || result.metadata.raw_state !== 'available') throw new ContractError('mail_raw_scope')
      return result
    } })
  }
  rawLatest(addressID: string, options: MailRawOptions = {}): Promise<MailDownload> { return this.#raw(addressID, '/raw/latest', options) }
  raw(addressID: string, uid: number, options: MailRawOptions = {}): Promise<MailDownload> {
    uid = mailInput(() => mailUID(uid)); return this.#raw(addressID, '/messages/' + uid + '/raw', options)
  }
  attachment(addressID: string, uid: number, part: string, signal?: AbortSignal): Promise<MailDownload> {
    uid = mailInput(() => mailUID(uid)); part = mailInput(() => mailPart(part))
    return this.#binary(addressID, '/messages/' + uid + '/attachments/' + part, 'attachment', signal)
  }
  render(addressID: string, uid: number, signal?: AbortSignal): Promise<ControlResult<{ html: string }>> {
    uid = mailInput(() => mailUID(uid)); return this.#json(addressID, '/messages/' + uid + '/render', { signal, decode: decodeMailRender })
  }
  consume(addressID: string, claim: MailClaim, signal?: AbortSignal): Promise<ControlResult<MailClaimResult>> { return this.#claim(addressID, claim, false, signal) }
  queryClaim(addressID: string, claim: MailClaim, signal?: AbortSignal): Promise<ControlResult<MailClaimResult>> { return this.#claim(addressID, claim, true, signal) }
  derive(addressID: string, value: MailDerive, signal?: AbortSignal): Promise<ControlResult<MailAccess>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const body = mailInput(() => { const data = mailObject(value), purpose = mailPurpose(data.purpose)
      if (purpose === 'imap_login' || this.#credential?.scheme !== 'APIKey') throw new ContractError('mail_derive')
      return { purpose, lifetime_seconds: mailInteger(data.lifetime_seconds, 1, 3600) } })
    return this.#json(addressID, '/access/derive', { method: 'POST', body, signal, decode: value => {
      const result = decodeMailAccess(value)
      if (result.address_id !== addressID || result.purposes.length !== 1 || result.purposes[0] !== body.purpose) throw new ContractError('mail_access_scope')
      return result
    } })
  }
  refresh(addressID: string, value: MailRefresh, signal?: AbortSignal): Promise<ControlResult<MailAccess>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const body = mailInput(() => { const data = mailObject(value), purposes = mailPurposes(data.purposes)
      if (purposes.length === 0) throw new ContractError('mail_refresh_scope')
      return { client_id: mailBounded(data.client_id, 4096, false), refresh_token: mailBounded(data.refresh_token, 4096, false), purposes } })
    return this.#json(addressID, '/access/refresh', { method: 'POST', body, signal, anonymous: true, decode: value => {
      const result = decodeMailAccess(value)
      if (result.address_id !== addressID || result.purposes.some(p => !body.purposes.includes(p))) throw new ContractError('mail_access_scope')
      return result
    } })
  }
  #snapshot(addressID: string, suffix: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    return this.#json(addressID, '/' + suffix, { signal, decode: value => {
      const result = decodeMailSnapshot(value)
      if (result.reference.view_scope_address_id !== null && result.reference.view_scope_address_id !== addressID) throw new ContractError('mail_snapshot_scope')
      return result
    } })
  }
  #page(addressID: string, suffix: string, query: MailPageQuery, signal?: AbortSignal): Promise<ControlResult<MailPage>> {
    const search = mailInput(() => mailPageQuery(query))
    return this.#json(addressID, suffix, { search, signal, decode: value => { const result = decodeMailPage(value)
      if (result.items.length > search.limit) throw new ContractError('mail_page_limit'); return result } })
  }
  #raw(addressID: string, suffix: string, options: MailRawOptions): Promise<MailDownload> {
    const range = mailInput(() => mailRange(options.range)); return this.#binary(addressID, suffix, 'raw', options.signal, range)
  }
  async #binary(addressID: string, suffix: string, kind: 'raw' | 'attachment', signal?: AbortSignal, range?: string): Promise<MailDownload> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const context: RequestContext = { resource: { kind: 'address', id: addressID } }
    const response = await this.#send(addressID, suffix, { signal, range, binary: true }, context)
    const correlated = this.#context(response, context)
    if (!response.ok) await this.#envelope(response, correlated, value => value, signal)
    return mailDownload(response, kind, correlated, signal, range)
  }
  #claim(addressID: string, value: MailClaim, query: boolean, signal?: AbortSignal): Promise<ControlResult<MailClaimResult>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const command = mailInput(() => mailClaim(value))
    if (command.reference.view_scope_address_id !== null && command.reference.view_scope_address_id !== addressID) throw new RequestConfigurationError('invalid_mail_scope', { outcome: 'not_sent' })
    return this.#json(addressID, query ? '/claims/query' : '/consume', { method: 'POST', body: command, signal, key: command.claim_key, decode: value => {
      const result = decodeMailClaimResult(value)
      if (result.claim_key !== command.claim_key || !sameMailRemote(result.remote, command.reference.remote)) throw new ContractError('mail_claim_scope')
      return result
    } }).catch(error => { if (error instanceof ControlError) throw new MailClaimError(error, command); throw error })
  }
  async #json<T>(addressID: string, suffix: string, options: MailJSONOptions<T>): Promise<ControlResult<T>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const context: RequestContext = { resource: { kind: 'address', id: addressID }, ...(options.key === undefined ? {} : { requestKey: options.key }),
      ...(options.method === 'POST' ? { outcome: 'not_sent' } : {}) }
    const response = await this.#send(addressID, suffix, options, context)
    return this.#envelope(response, this.#context(response, context), options.decode, options.signal)
  }
  async #send(addressID: string, suffix: string, options: MailSendOptions, context: RequestContext): Promise<Response> {
    if (options.signal?.aborted) throw new RequestConfigurationError('aborted_before_start', context)
    let body: string | undefined, headers: Headers
    try {
      headers = new Headers({ Accept: options.accept ?? (options.binary ? '*/*' : 'application/json') })
      if (!options.anonymous) {
        if (!this.#credential) throw new Error()
        headers.set('Authorization', this.#credential.scheme + ' ' + this.#credential.token)
      }
      if (options.range) headers.set('Range', options.range)
      if (options.body !== undefined) { body = JSON.stringify(options.body); headers.set('Content-Type', 'application/json') }
    } catch { throw new RequestConfigurationError('mail_authorization_unavailable', context) }
    const query = new URLSearchParams()
    for (const [key, value] of Object.entries(options.search ?? {})) if (value !== undefined) query.set(key, String(value))
    const url = publicMailBase + '/addresses/' + addressID + suffix + (query.size ? '?' + query : '')
    let fetch: FetchImplementation | undefined
    try { fetch = this.#fetch ?? globalThis.fetch } catch { /* Runtime support is checked below. */ }
    if (typeof fetch !== 'function') throw new RequestConfigurationError('fetch_unavailable', context)
    if (options.signal?.aborted) throw new RequestConfigurationError('aborted_before_start', context)
    if (options.method === 'POST') context.outcome = 'unknown'
    try { return await fetch(url, { method: options.method ?? 'GET', headers, body, signal: options.signal, mode: 'same-origin', credentials: 'omit', redirect: 'error', cache: 'no-store' }) }
    catch { throw new TransportError(options.signal?.aborted ? 'aborted' : 'network', context) }
  }
  #context(response: Response, context: RequestContext): RequestContext {
    const requestId = response.headers.get('X-Request-ID')
    return { ...context, ...(requestId && diagnostic.test(requestId) ? { requestId } : {}) }
  }
  async #envelope<T>(response: Response, context: RequestContext, decode: (value: unknown) => T, signal?: AbortSignal): Promise<ControlResult<T>> {
    if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
      try { await response.body?.cancel() } catch { /* Do not retain native errors. */ }
      if (!response.ok) throw new HttpError(response.status, context)
      throw new InvalidResponseError('expected_json', context)
    }
    let text: string
    try { text = await response.text() } catch { throw new TransportError(signal?.aborted ? 'aborted' : 'body_read', context) }
    let data: Record<string, unknown>, meta: ResponseMeta
    try {
      data = mailObject(JSON.parse(text)); const rawMeta = mailObject(data.meta)
      if (rawMeta.request_id !== undefined && (typeof rawMeta.request_id !== 'string' || !diagnostic.test(rawMeta.request_id))) throw new Error()
      meta = rawMeta.request_id === undefined ? {} : { request_id: rawMeta.request_id as string }
      if (Object.hasOwn(data, 'result') === Object.hasOwn(data, 'error')) throw new Error()
    } catch { throw new InvalidResponseError('invalid_envelope', context) }
    context = { ...context, ...(meta.request_id ? { requestId: meta.request_id } : {}) }
    if (Object.hasOwn(data, 'error')) {
      if (response.ok) throw new InvalidResponseError('unexpected_mail_error', context)
      let error: Record<string, unknown>
      try {
        error = mailObject(data.error)
        for (const name of ['kind', 'code']) if (typeof error[name] !== 'string' || !diagnostic.test(error[name] as string)) throw new Error()
        if (typeof error.message !== 'string') throw new Error()
        if (error.outcome !== undefined && !['accepted', 'rejected', 'not_sent', 'unknown'].includes(error.outcome as string)) throw new Error()
        if (error.submission_key !== undefined && (mailBounded(error.submission_key, 256, false) !== context.requestKey || context.requestKey === undefined)) throw new Error()
        if (error.resource !== undefined) { const resource = mailObject(error.resource)
          if (resource.kind !== 'address' || decodeIdentifier(resource.id) !== context.resource?.id) throw new Error() }
      } catch { throw new InvalidResponseError('mail_error_scope', context) }
      throw new HttpError(response.status, { ...context, submissionKey: error.submission_key as string | undefined, outcome: error.outcome as SubmissionOutcome | undefined ?? context.outcome }, { kind: error.kind as string, code: error.code as string })
    }
    if (!response.ok) throw new HttpError(response.status, context)
    try { return { result: decode(data.result), meta } } catch { throw new InvalidResponseError('invalid_mail_result', context) }
  }
}
interface MailSendOptions {
  method?: 'POST'; signal?: AbortSignal; body?: unknown; search?: Record<string, string | number | undefined>; range?: string; anonymous?: boolean; binary?: boolean; accept?: 'text/plain'
}
interface MailJSONOptions<T> extends MailSendOptions { decode: (value: unknown) => T; key?: string }

export interface InlineImageURL { url: string; documentSource?: string; revoke(): void }
/** Resolves exactly one CID against complete inline raster descriptors. It does
 * not parse or rewrite HTML, follow URLs, or expose authenticated endpoint URLs. */
export async function createInlineImageURL(cid: string, descriptors: readonly MailAttachment[], load: (part: string) => Promise<MailDownload>, maximumBytes = 10 << 20, options: { opaqueDocument?: boolean } = {}): Promise<InlineImageURL | null> {
  const selected = mailInput(() => {
    if (typeof cid !== 'string' || !/^cid:/i.test(cid)) throw new ContractError('mail_cid')
    let key: string
    try { key = decodeURIComponent(cid.slice(4)) } catch { throw new ContractError('mail_cid') }
    if (!key || /[\x00-\x20<>"']/.test(key) || new TextEncoder().encode(key).length > 256) throw new ContractError('mail_cid')
    const allowed = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp'])
    const parts = descriptors.map(decodeMailAttachment).filter(p => p.content_id === key)
    if (parts.length !== 1 || !parts[0].complete || !parts[0].inline || !allowed.has(parts[0].media_type)) return null
    mailInteger(maximumBytes, 1, 100 << 20)
    return BigInt(parts[0].byte_size) > BigInt(maximumBytes) ? null : parts[0]
  })
  if (!selected) return null
  let downloaded: MailDownload
  try { downloaded = await load(selected.part || 'root') } catch (error) { if (error instanceof ControlError) throw error; throw new TransportError('network') }
  if (downloaded.status !== 200 || downloaded.media_type !== selected.media_type || downloaded.byte_size !== selected.byte_size) { await downloaded.stream.cancel(); throw new InvalidResponseError('inline_image_metadata') }
  const reader = downloaded.stream.getReader(), chunks: Uint8Array[] = []; let size = 0
  try {
    for (;;) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength
      if (size > maximumBytes || BigInt(size) > BigInt(selected.byte_size)) throw new InvalidResponseError('inline_image_size'); chunks.push(part.value) }
    if (BigInt(size) !== BigInt(selected.byte_size)) throw new InvalidResponseError('inline_image_size')
  } catch (error) { try { await reader.cancel() } catch { /* No replacement download. */ } if (error instanceof ControlError) throw error; throw new TransportError('body_read') } finally { reader.releaseLock() }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
  const starts = (value: number[]) => value.every((byte, index) => bytes[index] === byte)
  const valid = selected.media_type === 'image/png' ? starts([137,80,78,71,13,10,26,10]) : selected.media_type === 'image/jpeg' ? starts([255,216,255]) :
    selected.media_type === 'image/gif' ? starts([71,73,70,56]) && (bytes[4] === 55 || bytes[4] === 57) && bytes[5] === 97 : starts([82,73,70,70]) && bytes[8] === 87 && bytes[9] === 69 && bytes[10] === 66 && bytes[11] === 80
  if (!valid) throw new InvalidResponseError('inline_image_type')
  // An opaque sandbox document has a different storage key and cannot rely
  // on its parent's blob URL. Only already verified raster bytes become an
  // inert data image there; script, SVG and network sources remain excluded.
  let documentSource: string | undefined
  if (options.opaqueDocument) {
    const chunks: string[] = []
    for (let offset = 0; offset < bytes.length; offset += 32768) chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32768)))
    documentSource = 'data:' + selected.media_type + ';base64,' + btoa(chunks.join(''))
  }
  const url = URL.createObjectURL(new Blob([bytes], { type: selected.media_type })); let revoked = false
  return { url, documentSource, revoke() { if (!revoked) { revoked = true; URL.revokeObjectURL(url) } } }
}
