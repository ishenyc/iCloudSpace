import { ControlClient, ControlError, InvalidResponseError, RequestConfigurationError, TransportError } from '../transport/index.ts'
import { decodeIdentifier } from './contracts.ts'
import { addressFilter } from './address-contracts.ts'
import type { AddressFilter } from './address-contracts.ts'
import { decodeCredentialBundle } from './credential-contracts.ts'
import type { CredentialBundle } from './credential-contracts.ts'
import { credentialCopyText, credentialCopyURL } from './credential-copy.ts'
import type { CredentialCopyFormat, CredentialCopyLinks } from './credential-copy.ts'

export type CredentialExportKind = 'api_key' | 'mailbox'
export type CredentialExportFormat = 'jsonl' | 'csv'
export type CredentialExportCommand = { kind: CredentialExportKind; format: CredentialExportFormat } &
  ({ filter: AddressFilter; selected_ids?: never } | { selected_ids: readonly string[]; filter?: never })
export interface CredentialExportRow {
  type: 'credential'; version: 1; kind: CredentialExportKind
  address_id: string; source_id: string; address: string; generation: string
  api?: { key: string; purposes: string[] }; bundle?: CredentialBundle
  links?: CredentialCopyLinks
}
export interface CredentialExportDownload {
  readonly kind: CredentialExportKind; readonly format: CredentialExportFormat
  readonly count: string; readonly blob: Blob; readonly filename: string
}
const purposes = new Set(['latest_read', 'mail_read', 'mail_consume', 'raw_read'])
const maxLine = 256 * 1024 // four 4096-byte secrets, including worst-case JSON escaping
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error()
  return value as Record<string, unknown>
}
function secret(value: unknown): string {
  if (typeof value !== 'string' || !value || /[\x00\r\n]/.test(value)) throw new Error()
  const bytes = new TextEncoder().encode(value)
  if (bytes.byteLength > 4096 || new TextDecoder('utf-8', { fatal: true }).decode(bytes) !== value) throw new Error()
  return value
}
function prepare(command: CredentialExportCommand): { body: object; selection?: Set<string> } {
  try {
    if (!command || !['api_key', 'mailbox'].includes(command.kind) || !['jsonl', 'csv'].includes(command.format)) throw new Error()
    const filter = command.filter !== undefined, selected = command.selected_ids !== undefined
    if (filter === selected) throw new Error()
    if (filter) return { body: { kind: command.kind, format: command.format, filter: addressFilter(command.filter!) } }
    if (!Array.isArray(command.selected_ids) || command.selected_ids.length < 1 || command.selected_ids.length > 1000) throw new Error()
    const ids = command.selected_ids.map(value => decodeIdentifier(value))
    if (new Set(ids).size !== ids.length) throw new Error()
    return { body: { kind: command.kind, format: command.format, selected_ids: ids }, selection: new Set(ids) }
  } catch { throw new RequestConfigurationError('invalid_credential_export', { outcome: 'not_sent' }) }
}
function csvCell(line: string): string {
  if (line[0] !== '"' || line[line.length - 1] !== '"') throw new Error()
  let value = ''
  for (let index = 1; index < line.length - 1; index++) {
    if (line[index] === '"') { if (line[++index] !== '"' || index >= line.length - 1) throw new Error() }
    value += line[index]
  }
  return value
}
/** One explicit request. No download is returned until EOF and the typed
 * terminal record prove completion; cancellation/failure never fetches again. */
export class CredentialExportsModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }
  async download(command: CredentialExportCommand, signal?: AbortSignal, copyFormat = false): Promise<CredentialExportDownload> {
    const request = prepare(command), kind = command.kind, format = command.format
    const response = await this.client.raw('/addresses/credential-exports', { method: 'POST', body: { ...request.body, ...(copyFormat ? { copy_format: true } : {}) }, signal })
    const context = { requestId: response.headers.get('X-Request-ID') ?? undefined, outcome: 'unknown' as const }
    const expectedType = format === 'csv' ? 'text/csv' : 'application/x-ndjson'
    if (response.headers.get('X-Space-Credential-Export') !== '1' || response.headers.get('Content-Type')?.split(';')[0] !== expectedType || !response.body) {
      await response.body?.cancel()
      throw new InvalidResponseError('credential_export_format', context)
    }
    const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true })
    const parts: Uint8Array<ArrayBuffer>[] = []
    let pending = '', header = format !== 'csv', terminal = false, count = 0n, previous = 0n
    let canceled = false
    const abort = () => { canceled = true; void reader.cancel().catch(() => {}) }
    signal?.addEventListener('abort', abort, { once: true })
    const line = (text: string) => {
      if (text.endsWith('\r')) text = text.slice(0, -1)
      if (text.length > maxLine || terminal || !text) throw new Error()
      if (!header) { if (text !== 'credential_record_json') throw new Error(); header = true; return }
      const record = object(JSON.parse(format === 'csv' ? csvCell(text) : text))
      const allowed = record.type === 'complete' ? ['type', 'version', 'kind', 'count'] : ['type', 'version', 'kind', 'address_id', 'source_id', 'address', 'generation', 'api', 'bundle', ...(copyFormat ? ['links'] : [])]
      if (Object.keys(record).some(key => !allowed.includes(key))) throw new Error()
      if (record.version !== 1 || record.kind !== kind) throw new Error()
      if (record.type === 'complete') {
        if (typeof record.count !== 'string' || !/^(0|[1-9][0-9]*)$/.test(record.count) || BigInt(record.count) !== count || !copyFormat && request.selection?.size || record.api !== undefined || record.bundle !== undefined) throw new Error()
        terminal = true; return
      }
      if (record.type !== 'credential') throw new Error()
      const id = decodeIdentifier(record.address_id), source = decodeIdentifier(record.source_id), generation = decodeIdentifier(record.generation)
      if (BigInt(id) <= previous || request.selection && !request.selection.delete(id)) throw new Error()
      previous = BigInt(id)
      if (typeof record.address !== 'string' || !record.address || /[\x00-\x20]/.test(record.address)) throw new Error()
      const decoded: CredentialExportRow = { type: 'credential', version: 1, kind, address_id: id, source_id: source, address: record.address, generation }
      if (kind === 'api_key') {
        if (record.bundle !== undefined) throw new Error()
        const api = object(record.api), key = secret(api.key)
        if (!Array.isArray(api.purposes) || api.purposes.length < 1 || api.purposes.length > 4 || api.purposes.some(value => typeof value !== 'string' || !purposes.has(value)) || new Set(api.purposes).size !== api.purposes.length) throw new Error()
        decoded.api = { key, purposes: api.purposes as string[] }
      } else {
        if (record.api !== undefined) throw new Error()
        decoded.bundle = decodeCredentialBundle(record.bundle)
      }
      if (copyFormat && kind === 'api_key') {
        const links = object(record.links)
        if (Object.keys(links).length !== 3) throw new Error()
        for (const name of ['otp', 'recent', 'raw']) {
          if (typeof links[name] !== 'string') throw new Error()
          credentialCopyURL(links[name], 'https://copy.invalid')
        }
      } else if (record.links !== undefined) throw new Error()
      count++
    }
    const accept = (text: string) => {
      pending += text
      let newline: number
      while ((newline = pending.indexOf('\n')) >= 0) { const next = pending.slice(0, newline); pending = pending.slice(newline + 1); line(next) }
      if (pending.length > maxLine) throw new Error()
    }
    try {
      for (;;) {
        if (signal?.aborted || canceled) throw new TransportError('aborted', context)
        let chunk: ReadableStreamReadResult<Uint8Array>
        try { chunk = await reader.read() } catch { throw new TransportError(signal?.aborted ? 'aborted' : 'body_read', context) }
        if (signal?.aborted || canceled) throw new TransportError('aborted', context)
        if (chunk.done) break
        if (!(chunk.value instanceof Uint8Array)) throw new InvalidResponseError('credential_export_invalid', context)
        parts.push(new Uint8Array(chunk.value))
        try { accept(decoder.decode(chunk.value, { stream: true })) } catch { throw new InvalidResponseError('credential_export_invalid', context) }
      }
      try { accept(decoder.decode()) } catch { throw new InvalidResponseError('credential_export_invalid', context) }
      if (!header || !terminal || pending !== '') throw new InvalidResponseError('credential_export_incomplete', context)
      return Object.freeze({ kind, format, count: count.toString(), blob: new Blob(parts, { type: expectedType + '; charset=utf-8' }), filename: 'address-credentials.' + format })
    } catch (error) {
      parts.length = 0
      try { await reader.cancel() } catch { /* no replacement request */ }
      throw error instanceof ControlError ? error : new InvalidResponseError('credential_export_invalid', context)
    } finally { signal?.removeEventListener('abort', abort); reader.releaseLock() }
  }
  async copy(format: CredentialCopyFormat, selection: { filter: AddressFilter; selected_ids?: never } | { selected_ids: readonly string[]; filter?: never }, origin: string, signal?: AbortSignal): Promise<{ text: string; count: number; links: readonly CredentialCopyLinks[] }> {
    if (format !== 'otp' && format !== 'imap') throw new RequestConfigurationError('invalid_credential_copy', { outcome: 'not_sent' })
    const complete = await this.download({ kind: format === 'otp' ? 'api_key' : 'mailbox', format: 'jsonl', ...selection }, signal, true)
    const rows = (await complete.blob.text()).trimEnd().split('\n').map(line => JSON.parse(line)).filter((row): row is CredentialExportRow => row.type === 'credential')
    rows.sort((left, right) => left.address < right.address ? -1 : left.address > right.address ? 1 : BigInt(left.address_id) < BigInt(right.address_id) ? -1 : BigInt(left.address_id) > BigInt(right.address_id) ? 1 : 0)
    signal?.throwIfAborted()
    return { text: credentialCopyText(rows, format, origin), count: rows.length, links: rows.flatMap(row => row.links ? [row.links] : []) }
  }
  async save(command: CredentialExportCommand, write: (download: CredentialExportDownload) => Promise<void>, signal?: AbortSignal): Promise<void> {
    const complete = await this.download(command, signal)
    await write(complete)
  }
}
