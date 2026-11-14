import { ContractError, decodeIdentifier, decodeInstant } from '../control/contracts.ts'
import { InvalidResponseError, RequestConfigurationError, TransportError } from '../transport/index.ts'
import type { RequestContext, ResponseMeta } from '../transport/index.ts'

export interface Mailbox { name?: string; address: string }
export interface MailRemote { source_generation: string; mailbox: string; uid_validity: number; uid: number }
export interface MailMetadata {
  entry_id: string | null; message_id: string; uid: number | null; remote: MailRemote; rfc_message_id: string; subject: string
  from: Mailbox[]; to: Mailbox[]; cc: Mailbox[]; sent_at: string | null; received_at: string; visible_at: string | null; seen: boolean
  content_state: 'complete' | 'metadata_only' | 'over_budget' | 'malformed'
  raw_state: 'staged' | 'available' | 'evicted' | 'missing' | 'corrupt' | 'over_budget' | 'metadata_only'
  declared_body_size: string; declared_body_truncated: boolean; preview: string
}
export interface MailAttachment {
  part: string; filename: string; media_type: string; disposition: string; content_id: string; inline: boolean; byte_size: string; complete: boolean
}
export interface MailMessage { metadata: MailMetadata; text: string; html: string; attachments: MailAttachment[]; body_complete: boolean }
export interface MailReference {
  auth_generation: string; message_id: string; entry_id: string | null; uid: number | null; uid_validity: string
  view_key: string; view_scope_address_id: string | null; selected_at: string; remote: MailRemote
}
export interface MailSnapshot { reference: MailReference; message: MailMessage; consumed: boolean }
export interface MailCode { code: string; entry_id: string; uid: number; received_at: string }
export interface MailPage { items: MailMetadata[]; more: boolean; next_time: string | null; next_id: string | null }
export interface MailPageQuery { limit?: number; before_time?: string; before_id?: string }
export interface MailClaim { claim_key: string; reference: MailReference }
export interface MailClaimResult { claim_key: string; committed: true; remote: MailRemote; claimed_at: string; snippet?: string }
export type MailPurpose = 'latest_read' | 'mail_read' | 'mail_consume' | 'raw_read' | 'imap_login'
export type DerivablePurpose = Exclude<MailPurpose, 'imap_login'>
export interface MailAccess { access_token: string; token_type: 'Bearer'; expires_at: string; address_id: string; purposes: MailPurpose[] }
export interface MailRefresh { client_id: string; refresh_token: string; purposes: MailPurpose[] }
export interface MailDerive { purpose: DerivablePurpose; lifetime_seconds: number }
export type MailRange = { start: string; end?: string; suffix?: never } | { suffix: string; start?: never; end?: never }
export interface MailRawOptions { signal?: AbortSignal; range?: MailRange }
export interface MailDownload {
  stream: ReadableStream<Uint8Array>; status: 200 | 206; media_type: string; byte_size: string | null
  range: { start: string; end: string; total: string } | null; meta: ResponseMeta
}

export function mailObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('mail_object')
  return value as Record<string, unknown>
}
export function mailText(value: unknown): string { if (typeof value !== 'string') throw new ContractError('mail_text'); return value }
export function mailBoolean(value: unknown): boolean { if (typeof value !== 'boolean') throw new ContractError('mail_boolean'); return value }
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ContractError('mail_choice')
  return value as T
}
export function mailInteger(value: unknown, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new ContractError('mail_integer')
  return value as number
}
export function mailUID(value: unknown): number { return mailInteger(value, 1, 4294967295) }
export function mailCount(value: unknown): string { return decodeIdentifier(value, 'mail_count', true) }
export function mailBounded(value: unknown, maxBytes: number, empty = true): string {
  const text = mailText(value)
  if ((!empty && !text) || /[\x00\r\n]/.test(text) || new TextEncoder().encode(text).byteLength > maxBytes || [...text].some(c => c.codePointAt(0)! >= 0xd800 && c.codePointAt(0)! <= 0xdfff)) throw new ContractError('mail_text')
  return text
}
/** Calendar validation plus an exact signed-nanosecond range check. Date is
 * used only for whole milliseconds; the fractional nanoseconds remain BigInt. */
export function mailInstant(value: unknown): string {
  const text = decodeInstant(value), fraction = /\.(\d+)(?=Z|[+-]\d{2}:\d{2}$)/.exec(text)
  const base = fraction ? text.replace('.' + fraction[1], '') : text
  const milliseconds = Date.parse(base)
  if (!Number.isSafeInteger(milliseconds)) throw new ContractError('mail_instant')
  const ns = BigInt(milliseconds) * 1000000n + BigInt((fraction?.[1] ?? '').padEnd(9, '0'))
  if (ns < -9223372036854775808n || ns > 9223372036854775807n) throw new ContractError('mail_instant')
  return text
}
export function mailInstantNS(value: string): bigint {
  const text = mailInstant(value), fraction = /\.(\d+)(?=Z|[+-]\d{2}:\d{2}$)/.exec(text)
  return BigInt(Date.parse(fraction ? text.replace('.' + fraction[1], '') : text)) * 1000000n + BigInt((fraction?.[1] ?? '').padEnd(9, '0'))
}
const optionalInstant = (value: unknown): string | null => value === null ? null : mailInstant(value)
const optionalID = (value: unknown): string | null => value === null ? null : decodeIdentifier(value)
export function mailPart(value: unknown, empty = false): string {
  const text = mailText(value)
  if (empty && text === '' || text === 'root') return text
  if (text.length > 128 || !/^[1-9][0-9]*(?:\.[1-9][0-9]*)*$/.test(text)) throw new ContractError('mail_part')
  return text
}
function mailbox(value: unknown): Mailbox {
  const data = mailObject(value), address = mailText(data.address)
  return { ...(data.name === undefined ? {} : { name: mailText(data.name) }), address }
}
function mailboxes(value: unknown): Mailbox[] { if (!Array.isArray(value)) throw new ContractError('mail_addresses'); return value.map(mailbox) }
export function decodeMailRemote(value: unknown): MailRemote {
  const data = mailObject(value)
  return { source_generation: decodeIdentifier(data.source_generation), mailbox: mailBounded(data.mailbox, 1024, false), uid_validity: mailUID(data.uid_validity), uid: mailUID(data.uid) }
}
export function sameMailRemote(a: MailRemote, b: MailRemote): boolean {
  return a.source_generation === b.source_generation && a.mailbox === b.mailbox && a.uid_validity === b.uid_validity && a.uid === b.uid
}
export function decodeMailMetadata(value: unknown): MailMetadata {
  const data = mailObject(value), entry_id = optionalID(data.entry_id), uid = data.uid === null ? null : mailUID(data.uid), visible_at = optionalInstant(data.visible_at)
  if ((entry_id === null) !== (uid === null) || (entry_id === null) !== (visible_at === null)) throw new ContractError('mail_entry')
  return { entry_id, message_id: decodeIdentifier(data.message_id), uid, remote: decodeMailRemote(data.remote), rfc_message_id: mailText(data.rfc_message_id), subject: mailText(data.subject),
    from: mailboxes(data.from), to: mailboxes(data.to), cc: mailboxes(data.cc), sent_at: optionalInstant(data.sent_at), received_at: mailInstant(data.received_at), visible_at, seen: mailBoolean(data.seen),
    content_state: choice(data.content_state, ['complete', 'metadata_only', 'over_budget', 'malformed'] as const),
    raw_state: choice(data.raw_state, ['staged', 'available', 'evicted', 'missing', 'corrupt', 'over_budget', 'metadata_only'] as const),
    declared_body_size: mailCount(data.declared_body_size), declared_body_truncated: mailBoolean(data.declared_body_truncated), preview: mailText(data.preview) }
}
export function decodeMailAttachment(value: unknown): MailAttachment {
  const data = mailObject(value)
  return { part: mailPart(data.part, true), filename: mailText(data.filename), media_type: mailText(data.media_type), disposition: mailText(data.disposition),
    content_id: mailText(data.content_id), inline: mailBoolean(data.inline), byte_size: mailCount(data.byte_size), complete: mailBoolean(data.complete) }
}
export function decodeMailReference(value: unknown): MailReference {
  const data = mailObject(value), entry_id = optionalID(data.entry_id), uid = data.uid === null ? null : mailUID(data.uid), uid_validity = decodeIdentifier(data.uid_validity)
  if ((entry_id === null) !== (uid === null) || BigInt(uid_validity) > 4294967295n) throw new ContractError('mail_reference_uid')
  return { auth_generation: decodeIdentifier(data.auth_generation), message_id: decodeIdentifier(data.message_id), entry_id, uid, uid_validity,
    view_key: mailBounded(data.view_key, 256), view_scope_address_id: optionalID(data.view_scope_address_id), selected_at: mailInstant(data.selected_at), remote: decodeMailRemote(data.remote) }
}
export function decodeMailMessage(value: unknown): MailMessage {
  const message = mailObject(value)
  if (!Array.isArray(message.attachments)) throw new ContractError('mail_attachments')
  const metadata = decodeMailMetadata(message.metadata)
  return { metadata, text: mailText(message.text), html: mailText(message.html), attachments: message.attachments.map(decodeMailAttachment), body_complete: mailBoolean(message.body_complete) }
}
export function decodeMailSnapshot(value: unknown): MailSnapshot {
  const data = mailObject(value), reference = decodeMailReference(data.reference), message = decodeMailMessage(data.message), metadata = message.metadata
  if (reference.message_id !== metadata.message_id || reference.entry_id !== metadata.entry_id || reference.uid !== metadata.uid || !sameMailRemote(reference.remote, metadata.remote)) throw new ContractError('mail_snapshot')
  return { reference, message, consumed: mailBoolean(data.consumed) }
}
export function decodeMailCodes(value: unknown): MailCode[] {
  if (!Array.isArray(value) || value.length > 100) throw new ContractError('mail_codes')
  return value.map(item => { const data = mailObject(item), code = mailText(data.code); if (!/^[0-9]{6}$/.test(code)) throw new ContractError('mail_code')
    return { code, entry_id: decodeIdentifier(data.entry_id), uid: mailUID(data.uid), received_at: mailInstant(data.received_at) } })
}
export function decodeMailPage(value: unknown): MailPage {
  const data = mailObject(value), more = mailBoolean(data.more), next_time = optionalInstant(data.next_time), next_id = optionalID(data.next_id)
  if (!Array.isArray(data.items) || (next_time !== null) !== more || (next_id !== null) !== more) throw new ContractError('mail_page')
  const items = data.items.map(decodeMailMetadata)
  const seen = new Set<string>(); let previous: MailMetadata | undefined
  for (const item of items) {
    if (item.entry_id === null || item.visible_at === null || seen.has(item.entry_id)) throw new ContractError('mail_page_entry')
    if (previous && (mailInstantNS(item.visible_at) > mailInstantNS(previous.visible_at!) ||
      mailInstantNS(item.visible_at) === mailInstantNS(previous.visible_at!) && BigInt(item.entry_id) >= BigInt(previous.entry_id!))) throw new ContractError('mail_page_order')
    seen.add(item.entry_id); previous = item
  }
  if (more && (previous === undefined || next_id !== previous.entry_id || mailInstantNS(next_time!) !== mailInstantNS(previous.visible_at!))) throw new ContractError('mail_page_cursor')
  return { items, more, next_time, next_id }
}
export function mailClaim(value: unknown): MailClaim {
  const data = mailObject(value), reference = decodeMailReference(data.reference)
  Object.freeze(reference.remote); Object.freeze(reference)
  return Object.freeze({ claim_key: mailBounded(data.claim_key, 256, false), reference })
}
export function decodeMailClaimResult(value: unknown): MailClaimResult {
  const data = mailObject(value)
  if (data.committed !== true) throw new ContractError('mail_claim_unconfirmed')
  return { claim_key: mailBounded(data.claim_key, 256, false), committed: true, remote: decodeMailRemote(data.remote), claimed_at: mailInstant(data.claimed_at),
    ...(data.snippet === undefined ? {} : { snippet: mailText(data.snippet) }) }
}
export function mailPurpose(value: unknown): MailPurpose { return choice(value, ['latest_read', 'mail_read', 'mail_consume', 'raw_read', 'imap_login'] as const) }
export function mailPurposes(value: unknown): MailPurpose[] {
  if (!Array.isArray(value)) throw new ContractError('mail_purposes')
  const result = value.map(mailPurpose)
  if (new Set(result).size !== result.length) throw new ContractError('mail_purposes')
  return result
}
export function decodeMailAccess(value: unknown): MailAccess {
  const data = mailObject(value), purposes = mailPurposes(data.purposes)
  if (data.token_type !== 'Bearer' || purposes.length === 0) throw new ContractError('mail_access')
  return { access_token: mailBounded(data.access_token, 4096, false), token_type: 'Bearer', expires_at: mailInstant(data.expires_at), address_id: decodeIdentifier(data.address_id), purposes }
}
export function decodeMailRender(value: unknown): { html: string } { return { html: mailText(mailObject(value).html) } }
export function mailPageQuery(value: unknown = {}): { limit: number; before_time?: string; before_id?: string } {
  const data = mailObject(value), limit = data.limit === undefined ? 20 : mailInteger(data.limit, 1, 1000)
  if ((data.before_time === undefined) !== (data.before_id === undefined)) throw new ContractError('mail_page_query')
  return { limit, ...(data.before_time === undefined ? {} : { before_time: mailInstant(data.before_time), before_id: decodeIdentifier(data.before_id) }) }
}
export function mailRange(value: MailRange | undefined): string | undefined {
  if (value === undefined) return undefined
  const data = mailObject(value)
  if (data.suffix !== undefined) {
    if (data.start !== undefined || data.end !== undefined) throw new ContractError('mail_range')
    return 'bytes=-' + decodeIdentifier(data.suffix)
  }
  const start = mailCount(data.start), end = data.end === undefined ? undefined : mailCount(data.end)
  if (end !== undefined && BigInt(end) < BigInt(start)) throw new ContractError('mail_range')
  return 'bytes=' + start + '-' + (end ?? '')
}
export function mailInput<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_mail_input', { outcome: 'not_sent' }) }
}

/** Verifies response metadata before handing one stream to the caller. Stream
 * errors retain only safe protocol context; cancellation never opens a new FD. */
export async function mailDownload(response: Response, kind: 'raw' | 'attachment', context: RequestContext, signal?: AbortSignal, requestedRange?: string): Promise<MailDownload> {
  try {
    if (response.status !== 200 && response.status !== 206 || !response.body || response.status === 206 && (kind !== 'raw' || !requestedRange)) throw new Error()
    const media_type = response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()
    if (!media_type || !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(media_type) || kind === 'raw' && media_type !== 'message/rfc822') throw new Error()
    const declared = response.headers.get('Content-Length'), byte_size = declared === null ? null : mailCount(declared)
    let range: MailDownload['range'] = null
    const rangeHeader = response.headers.get('Content-Range')
    if (response.status === 206) {
      const match = /^bytes (0|[1-9][0-9]*)-(0|[1-9][0-9]*)\/(0|[1-9][0-9]*)$/.exec(rangeHeader ?? '')
      if (!match) throw new Error()
      range = { start: mailCount(match[1]), end: mailCount(match[2]), total: mailCount(match[3]) }
      if (BigInt(range.end) < BigInt(range.start) || BigInt(range.end) >= BigInt(range.total) || byte_size !== null && BigInt(byte_size) !== BigInt(range.end)-BigInt(range.start)+1n) throw new Error()
      const requested = /^bytes=(\d*)-(\d*)$/.exec(requestedRange!)!
      const last = BigInt(range.total)-1n
      const start = requested[1] ? BigInt(requested[1]) : BigInt(range.total)>BigInt(requested[2]) ? BigInt(range.total)-BigInt(requested[2]) : 0n
      const end = requested[1] && requested[2] && BigInt(requested[2])<last ? BigInt(requested[2]) : last
      if (BigInt(range.start) !== start || BigInt(range.end) !== end) throw new Error()
    } else if (rangeHeader !== null) throw new Error()
    const expectedBytes = byte_size !== null ? BigInt(byte_size) : range ? BigInt(range.end)-BigInt(range.start)+1n : null
    const reader = response.body.getReader(); let ended = false, bytes = 0n
    const release = () => { if (!ended) { ended = true; reader.releaseLock() } }
    const stream = new ReadableStream<Uint8Array>({
      pull: async controller => {
        try {
          const chunk = await reader.read()
          if (chunk.done) {
            release()
            if (expectedBytes !== null && bytes !== expectedBytes) throw new Error()
            controller.close()
          } else {
            bytes += BigInt(chunk.value.byteLength)
            if (expectedBytes !== null && bytes > expectedBytes) throw new Error()
            controller.enqueue(chunk.value)
          }
        } catch {
          try { await reader.cancel() } catch { /* Never retry a failed stream. */ }
          release(); controller.error(new TransportError(signal?.aborted ? 'aborted' : 'body_read', context))
        }
      },
      cancel: async () => { try { await reader.cancel() } catch { /* Caller cancellation keeps one request. */ } finally { release() } },
    })
    return { stream, status: response.status, media_type, byte_size, range, meta: context.requestId ? { request_id: context.requestId } : {} }
  } catch {
    try { await response.body?.cancel() } catch { /* Drop invalid wire data. */ }
    throw new InvalidResponseError('invalid_mail_download', context)
  }
}
