import { ContractError, decodeIdentifier } from '../control/contracts.ts'
import { ControlClient } from '../transport/index.ts'
import type { ControlResult, RequestContext } from '../transport/index.ts'
import { decodeMailCodes, decodeMailMessage, decodeMailPage, decodeMailRender, decodeMailSnapshot, mailDownload, mailInput, mailInteger, mailPageQuery, mailPart, mailRange, mailUID } from './contracts.ts'
import type { MailCode, MailDownload, MailMessage, MailPage, MailPageQuery, MailRawOptions, MailSnapshot } from './contracts.ts'
import { readCodeText } from './code-text.ts'

/** Operator-authorized reads use the existing management session directly.
 * This client has no reveal, consume, token derivation or OAuth mutation API. */
export class ManagementMailClient {
  #client: ControlClient
  constructor(client: ControlClient) { this.#client = client }
  latest(addressID: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> { return this.#snapshot(addressID, '/latest', signal) }
  recent(addressID: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> { return this.#snapshot(addressID, '/recent', signal) }
  message(addressID: string, uid: number, signal?: AbortSignal): Promise<ControlResult<MailMessage>> {
    addressID = mailInput(() => decodeIdentifier(addressID)); uid = mailInput(() => mailUID(uid))
    return this.#client.json(this.#base(addressID) + '/messages/' + uid, { signal, resource: { kind: 'address', id: addressID }, decodeResult: value => {
      const result = decodeMailMessage(value)
      if (result.metadata.uid !== uid) throw new ContractError('mail_message_scope')
      return result
    } })
  }
  codes(addressID: string, limit = 100, signal?: AbortSignal): Promise<ControlResult<MailCode[]>> {
    addressID = mailInput(() => decodeIdentifier(addressID)); limit = mailInput(() => mailInteger(limit, 1, 100))
    return this.#client.json(this.#base(addressID) + '/codes', { signal, search: { limit }, resource: { kind: 'address', id: addressID }, decodeResult: value => {
      const decoded = decodeMailCodes(value); if (decoded.length > limit) throw new ContractError('mail_codes_limit'); return decoded
    } })
  }
  async latestCodeText(addressID: string, signal?: AbortSignal): Promise<string | null> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const resource = { kind: 'address' as const, id: addressID }
    const response = await this.#client.raw(this.#base(addressID) + '/codes/latest/text', { signal, headers: { Accept: 'text/plain' }, resource })
    const context: RequestContext = { resource }, requestId = response.headers.get('X-Request-ID')
    if (requestId && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(requestId)) context.requestId = requestId
    return readCodeText(response, context, signal)
  }
  messages(addressID: string, query: MailPageQuery = {}, signal?: AbortSignal): Promise<ControlResult<MailPage>> { return this.#page(addressID, '/messages', query, signal) }
  rawCandidates(addressID: string, query: MailPageQuery = {}, signal?: AbortSignal): Promise<ControlResult<MailPage>> { return this.#page(addressID, '/raw/messages', query, signal) }
  rawLatest(addressID: string, options: MailRawOptions = {}): Promise<MailDownload> { return this.#raw(addressID, '/raw/latest', options) }
  raw(addressID: string, uid: number, options: MailRawOptions = {}): Promise<MailDownload> {
    uid = mailInput(() => mailUID(uid)); return this.#raw(addressID, '/messages/' + uid + '/raw', options)
  }
  attachment(addressID: string, uid: number, part: string, signal?: AbortSignal): Promise<MailDownload> {
    uid = mailInput(() => mailUID(uid)); part = mailInput(() => mailPart(part))
    return this.#binary(addressID, '/messages/' + uid + '/attachments/' + part, 'attachment', signal)
  }
  render(addressID: string, uid: number, signal?: AbortSignal): Promise<ControlResult<{ html: string }>> {
    addressID = mailInput(() => decodeIdentifier(addressID)); uid = mailInput(() => mailUID(uid))
    return this.#client.json(this.#base(addressID) + '/messages/' + uid + '/render', { signal, resource: { kind: 'address', id: addressID }, decodeResult: decodeMailRender })
  }
  #snapshot(addressID: string, suffix: string, signal?: AbortSignal): Promise<ControlResult<MailSnapshot>> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    return this.#client.json(this.#base(addressID) + suffix, { signal, resource: { kind: 'address', id: addressID }, decodeResult: value => {
      const decoded = decodeMailSnapshot(value)
      if (decoded.reference.view_scope_address_id !== null && decoded.reference.view_scope_address_id !== addressID) throw new ContractError('mail_snapshot_scope')
      return decoded
    } })
  }
  #page(addressID: string, suffix: string, query: MailPageQuery, signal?: AbortSignal): Promise<ControlResult<MailPage>> {
    addressID = mailInput(() => decodeIdentifier(addressID)); const search = mailInput(() => mailPageQuery(query))
    return this.#client.json(this.#base(addressID) + suffix, { signal, search, resource: { kind: 'address', id: addressID }, decodeResult: value => {
      const decoded = decodeMailPage(value); if (decoded.items.length > search.limit) throw new ContractError('mail_page_limit'); return decoded
    } })
  }
  #raw(addressID: string, suffix: string, options: MailRawOptions): Promise<MailDownload> {
    const range = mailInput(() => mailRange(options.range)); return this.#binary(addressID, suffix, 'raw', options.signal, range)
  }
  async #binary(addressID: string, suffix: string, kind: 'raw' | 'attachment', signal?: AbortSignal, range?: string): Promise<MailDownload> {
    addressID = mailInput(() => decodeIdentifier(addressID))
    const resource = { kind: 'address' as const, id: addressID }
    const response = await this.#client.raw(this.#base(addressID) + suffix, { signal, headers: range ? { Range: range } : {}, resource })
    const requestId = response.headers.get('X-Request-ID'), context: RequestContext = { resource }
    if (requestId && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(requestId)) context.requestId = requestId
    return mailDownload(response, kind, context, signal, range)
  }
  #base(addressID: string): string { return '/addresses/' + addressID + '/mail' }
}
