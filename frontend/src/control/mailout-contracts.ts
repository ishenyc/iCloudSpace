import { ContractError, decodeIdentifier } from './contracts.ts'

export type MailoutOutcome = 'accepted' | 'rejected' | 'not_sent' | 'unknown'
export type MailoutReferenceKind = 'incoming' | 'bootstrap_seed' | 'hme_route'
export interface MailoutAttachment { filename: string; media_type: string; content_id: string; inline: boolean; bytes: Uint8Array }
export interface MailoutDraft { recipient: string; subject: string; body: { format: 'text' | 'markdown' | 'html'; source: string }; attachments: MailoutAttachment[] }
export interface MailoutPreview { text: string; html: string; attachments: number }
export interface MailoutSend { request_key: string; draft: MailoutDraft }
export interface MailoutDiagnostic { stage: string; kind?: string; http_status?: number; provider_code?: string; operation?: string; attempts?: number; transport_phase?: string; transport_reason?: string }
export interface MailoutSubmission {
  key: string; address_id: string; state: 'reserved' | 'preparing' | 'submitting' | 'finished'; outcome: MailoutOutcome
  query_only: boolean; durable: boolean; code: string; fingerprint_version: string
  context_key?: string; rpc_id?: string; reference_id?: string; reference_kind?: MailoutReferenceKind; upstream_id?: string
  retryable?: boolean; route_outcome?: MailoutOutcome
  diagnostic?: MailoutDiagnostic
}
export interface MailoutContextRequest { context_key: string; recipient: string; authorize_bootstrap: boolean }
export interface MailoutContext {
  context_key: string; address_id: string; recipient: string
  request_key?: string
  state: 'reserved' | 'preparing' | 'candidate_unknown' | 'candidate_confirmed' | 'draft_ready' | 'seed_unknown' | 'ready' | 'failed'
  ready: boolean; query_only: boolean; candidate_id: string | null; candidate_uid_validity: string | null; seed_id: string | null
  append_outcome: MailoutOutcome | null; seed_outcome: MailoutOutcome | null; reference_id: string | null; reference_kind: MailoutReferenceKind | null; code: string
  diagnostic?: MailoutDiagnostic
}

export function mailoutObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('mailout_object')
  return value as Record<string, unknown>
}
export function mailoutText(value: unknown, maximum: number, required = false): string {
  if (typeof value !== 'string' || required && value.length === 0 || new TextEncoder().encode(value).byteLength > maximum) throw new ContractError('mailout_text')
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) { const next = value.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ContractError('mailout_unicode') }
    else if (unit >= 0xdc00 && unit <= 0xdfff) throw new ContractError('mailout_unicode')
  }
  return value
}
export function mailoutBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('mailout_boolean')
  return value
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) throw new ContractError('mailout_choice')
  return value as T
}
export function mailoutKey(value: unknown, mutation = false): string {
  const key = mailoutText(value, 16 << 10, true)
  if (key.includes('\0') || mutation && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(key)) throw new ContractError('mailout_key')
  return key
}
export function mailoutRecipient(value: unknown): string {
  const text = mailoutText(value, 4096, true)
  if (/[\p{Cc}]/u.test(text)) throw new ContractError('mailout_recipient')
  return text
}
function outcome(value: unknown): MailoutOutcome { return choice(value, ['accepted', 'rejected', 'not_sent', 'unknown'] as const) }
function referenceKind(value: unknown): MailoutReferenceKind { return choice(value, ['incoming', 'bootstrap_seed', 'hme_route'] as const) }
function nullableText(value: unknown): string | null { return value === null ? null : mailoutText(value, 2048, true) }
function base64(bytes: Uint8Array): string {
  const chunks: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 32768) chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + 32768)))
  return btoa(chunks.join(''))
}
function cid(value: unknown): string {
  const text = mailoutText(value, 256)
  if (text && (/[\s\p{Cc}<>"']/u.test(text) || /^cid:/i.test(text))) throw new ContractError('mailout_cid')
  return text
}
export function mailoutDraftInput(value: MailoutDraft) {
  const data = mailoutObject(value), body = mailoutObject(data.body)
  const subject = mailoutText(data.subject, 998)
  if (!subject.trim() || /[\p{Cc}]/u.test(subject) || !Array.isArray(data.attachments) || data.attachments.length > 10 || !mailoutText(body.source, 100 << 10).trim() && data.attachments.length === 0) throw new ContractError('mailout_draft')
  let total = 0
  const identifiers = new Set<string>()
  const attachments = data.attachments.map((value) => {
    const file = mailoutObject(value), filename = mailoutText(file.filename, 255, true), media_type = mailoutText(file.media_type, 4096, true)
    const content_id = cid(file.content_id), inline = mailoutBoolean(file.inline)
    if (filename === '.' || filename === '..' || filename.trim() !== filename || /[\/\\\p{Cc}]/u.test(filename) || /[\p{Cc}]/u.test(media_type) || !(file.bytes instanceof Uint8Array)) throw new ContractError('mailout_attachment')
    total += file.bytes.byteLength
    const declaredMedia = media_type.split(';', 1)[0].trim().toLowerCase()
    if (total > 10 << 20 || content_id && identifiers.has(content_id) || inline && (!content_id || !['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(declaredMedia))) throw new ContractError('mailout_attachment')
    if (content_id) identifiers.add(content_id)
    return { filename, media_type, content_id, inline, bytes: base64(file.bytes) }
  })
  return { recipient: mailoutRecipient(data.recipient), subject, body: { format: choice(body.format, ['text', 'markdown', 'html'] as const), source: mailoutText(body.source, 100 << 10) }, attachments }
}
export function mailoutPreviewInput(value: MailoutDraft) {
  const body = mailoutObject(mailoutObject(value).body)
  return { body: { format: choice(body.format, ['text', 'markdown', 'html'] as const), source: mailoutText(body.source, 100 << 10) } }
}
export function decodeMailoutPreview(value: unknown): MailoutPreview {
  const data = mailoutObject(value)
  if (!Number.isSafeInteger(data.attachments) || (data.attachments as number) < 0 || (data.attachments as number) > 10) throw new ContractError('mailout_preview')
  return { text: mailoutText(data.text, 512 << 10), html: mailoutText(data.html, 512 << 10), attachments: data.attachments as number }
}
function decodeMailoutDiagnostic(value: unknown): MailoutDiagnostic {
  const d = mailoutObject(value)
  const token = (v: unknown) => { const text = mailoutText(v, 128, true); if (!/^[A-Za-z0-9_.:-]+$/.test(text)) throw new ContractError('mailout_diagnostic'); return text }
  const result: MailoutDiagnostic = { stage: token(d.stage) }
  if (d.kind !== undefined) result.kind = token(d.kind)
  if (d.provider_code !== undefined) result.provider_code = token(d.provider_code)
  if (d.operation !== undefined) result.operation = token(d.operation)
  if (d.transport_phase !== undefined) result.transport_phase = token(d.transport_phase)
  if (d.transport_reason !== undefined) result.transport_reason = token(d.transport_reason)
  if (d.attempts !== undefined) { if (!Number.isInteger(d.attempts) || (d.attempts as number) < 1 || (d.attempts as number) > 3) throw new ContractError('mailout_diagnostic'); result.attempts = d.attempts as number }
  if (d.http_status !== undefined) { if (!Number.isInteger(d.http_status) || (d.http_status as number) < 100 || (d.http_status as number) > 599) throw new ContractError('mailout_diagnostic'); result.http_status = d.http_status as number }
  return result
}
export function decodeMailoutSubmission(value: unknown): MailoutSubmission {
  const data = mailoutObject(value), state = choice(data.state, ['reserved', 'preparing', 'submitting', 'finished'] as const), resultOutcome = outcome(data.outcome)
  const query_only = mailoutBoolean(data.query_only)
  if (state !== 'finished' && resultOutcome !== 'unknown' || resultOutcome === 'unknown' && !query_only) throw new ContractError('mailout_submission')
  const fingerprint_version = mailoutText(data.fingerprint_version, 128)
  if (!fingerprint_version && resultOutcome !== 'unknown') throw new ContractError('mailout_fingerprint')
  const result: MailoutSubmission = { key: mailoutKey(data.key), address_id: decodeIdentifier(data.address_id), state, outcome: resultOutcome, query_only, durable: mailoutBoolean(data.durable), code: mailoutText(data.code, 128), fingerprint_version }
  if (data.context_key !== undefined) result.context_key = mailoutKey(data.context_key)
  for (const field of ['rpc_id', 'reference_id', 'upstream_id'] as const) if (data[field] !== undefined) result[field] = mailoutText(data[field], 2048, true)
  if (data.reference_kind !== undefined) result.reference_kind = referenceKind(data.reference_kind)
  if (data.retryable !== undefined) result.retryable = mailoutBoolean(data.retryable)
  if (data.route_outcome !== undefined) result.route_outcome = outcome(data.route_outcome)
  if (data.diagnostic !== undefined) {
    result.diagnostic = decodeMailoutDiagnostic(data.diagnostic)
  }
  if ((result.reference_id === undefined) !== (result.reference_kind === undefined)) throw new ContractError('mailout_reference')
  return result
}
export function decodeMailoutContext(value: unknown): MailoutContext {
  const data = mailoutObject(value), state = choice(data.state, ['reserved', 'preparing', 'candidate_unknown', 'candidate_confirmed', 'draft_ready', 'seed_unknown', 'ready', 'failed'] as const)
  const query_only = mailoutBoolean(data.query_only)
  if (['preparing', 'candidate_unknown', 'seed_unknown'].includes(state) && !query_only) throw new ContractError('mailout_context')
  const candidate_uid_validity = data.candidate_uid_validity === null ? null : decodeIdentifier(data.candidate_uid_validity)
  if (candidate_uid_validity !== null && BigInt(candidate_uid_validity) > 4294967295n) throw new ContractError('mailout_uid')
  return { context_key: mailoutKey(data.context_key), ...(data.request_key === undefined ? {} : { request_key: mailoutKey(data.request_key) }), address_id: decodeIdentifier(data.address_id), recipient: mailoutRecipient(data.recipient), state,
    ready: mailoutBoolean(data.ready), query_only, candidate_id: nullableText(data.candidate_id), candidate_uid_validity, seed_id: nullableText(data.seed_id),
    append_outcome: data.append_outcome === null ? null : outcome(data.append_outcome), seed_outcome: data.seed_outcome === null ? null : outcome(data.seed_outcome),
    reference_id: nullableText(data.reference_id), reference_kind: data.reference_kind === null ? null : referenceKind(data.reference_kind), code: mailoutText(data.code, 128), ...(data.diagnostic===undefined?{}:{diagnostic:decodeMailoutDiagnostic(data.diagnostic)}) }
}
