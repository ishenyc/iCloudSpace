import { ControlClient, ControlError, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { decodeMailoutContext, decodeMailoutPreview, decodeMailoutSubmission, mailoutBoolean, mailoutDraftInput, mailoutPreviewInput, mailoutKey, mailoutRecipient } from './mailout-contracts.ts'
import type { MailoutContext, MailoutContextRequest, MailoutDraft, MailoutPreview, MailoutSend, MailoutSubmission } from './mailout-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_mailout_input', { outcome: 'not_sent' }) }
}
function submitted(value: unknown, address: string, key: string): MailoutSubmission {
  const result = decodeMailoutSubmission(value)
  if (result.address_id !== address || result.key !== key) throw new ContractError('mailout_submission_scope')
  return result
}
function context(value: unknown, address: string, key?: string): MailoutContext {
  const result = decodeMailoutContext(value)
  if (result.address_id !== address || key !== undefined && (result.request_key === undefined ? result.context_key !== key : result.request_key !== key)) throw new ContractError('mailout_context_scope')
  return result
}
function original(error: unknown, address: string, key: string): boolean {
  return error instanceof ControlError && error.outcome === 'unknown' && error.resource?.kind === 'address' && error.resource.id === address &&
    (error.requestKey === key || error.submissionKey === key) && (error.requestKey === undefined || error.requestKey === key) && (error.submissionKey === undefined || error.submissionKey === key)
}

/** Caller owns draft state and original keys. No polling, retry, storage or
 * automatic bootstrap occurs; an unknown submission is only explicitly read. */
export class MailoutModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  preview(addressID: string, draft: MailoutDraft, signal?: AbortSignal): Promise<ControlResult<MailoutPreview>> {
    addressID = input(() => decodeIdentifier(addressID))
    // Preview is body-only: recipient/subject/attachment bytes are irrelevant.
    const body = input(() => mailoutPreviewInput(draft))
    return this.client.json(this.base(addressID) + '/mail-preview', { method: 'POST', body, signal, resource: { kind: 'address', id: addressID }, decodeResult: (value) => {
      const result = decodeMailoutPreview(value)
      return result
    } })
  }
  send(addressID: string, value: MailoutSend, signal?: AbortSignal): Promise<ControlResult<MailoutSubmission>> {
    addressID = input(() => decodeIdentifier(addressID))
    const body = input(() => ({ request_key: mailoutKey(value.request_key, true), draft: mailoutDraftInput(value.draft) })), key = body.request_key
    return this.client.json(this.base(addressID) + '/send-submissions', { method: 'POST', body, signal, requestKey: key, resource: { kind: 'address', id: addressID }, decodeResult: (value) => submitted(value, addressID, key) })
  }
  query(addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<MailoutSubmission>> {
    addressID = input(() => decodeIdentifier(addressID)); key = input(() => mailoutKey(key))
    return this.client.json(this.base(addressID) + '/send-submissions/query', { method: 'POST', body: { request_key: key }, signal, resource: { kind: 'address', id: addressID }, decodeResult: (value) => submitted(value, addressID, key) })
  }
  prepareContext(addressID: string, value: MailoutContextRequest, signal?: AbortSignal): Promise<ControlResult<MailoutContext>> {
    addressID = input(() => decodeIdentifier(addressID))
    const body = input(() => ({ context_key: mailoutKey(value.context_key, true), recipient: mailoutRecipient(value.recipient), authorize_bootstrap: mailoutBoolean(value.authorize_bootstrap) }))
    // An existing context for the same recipient may be returned instead of a
    // new key. Preserve its original key; never issue a replacement seed here.
    return this.client.json(this.base(addressID) + '/compose-contexts', { method: 'POST', body, signal, requestKey: body.context_key, resource: { kind: 'address', id: addressID }, decodeResult: (value) => {
      const result = context(value, addressID)
      if (result.request_key !== undefined && result.request_key !== body.context_key) throw new ContractError('mailout_context_scope')
      return result
    } })
  }
  queryContext(addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<MailoutContext>> {
    return this.readContext(addressID, key, 'query', signal)
  }
  refreshContext(addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<MailoutContext>> {
    return this.readContext(addressID, key, 'refresh', signal)
  }
  async queryUnknownSubmission(error: unknown, addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<MailoutSubmission> | undefined> {
    addressID = input(() => decodeIdentifier(addressID)); key = input(() => mailoutKey(key))
    return original(error, addressID, key) ? this.query(addressID, key, signal) : undefined
  }
  async queryUnknownContext(error: unknown, addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<MailoutContext> | undefined> {
    addressID = input(() => decodeIdentifier(addressID)); key = input(() => mailoutKey(key))
    return original(error, addressID, key) ? this.queryContext(addressID, key, signal) : undefined
  }
  private readContext(address: string, key: string, operation: 'query' | 'refresh', signal?: AbortSignal): Promise<ControlResult<MailoutContext>> {
    address = input(() => decodeIdentifier(address)); key = input(() => mailoutKey(key))
    return this.client.json(this.base(address) + '/compose-contexts/' + operation, { method: 'POST', body: { context_key: key }, signal, resource: { kind: 'address', id: address }, decodeResult: (value) => context(value, address, key) })
  }
  private base(address: string): string { return '/addresses/' + address }
}
