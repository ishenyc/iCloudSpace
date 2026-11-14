import { ControlClient, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { creationInteger, creationObject, decodeCreationAttempt, decodeCreationAttemptPage, decodeCreationPolicy } from './creation-contracts.ts'
import type { CreationAttempt, CreationAttemptPage, CreationAttemptsQuery, CreationPolicy, CreationRevision, CreationSettings } from './creation-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_creation_input', { outcome: 'not_sent' }) }
}
function policy(value: unknown, source: string): CreationPolicy {
  const decoded = decodeCreationPolicy(value)
  if (decoded.source_id !== source) throw new ContractError('creation_source')
  return decoded
}
function attempt(value: unknown, source: string, id: string): CreationAttempt {
  const decoded = decodeCreationAttempt(value)
  if (decoded.source_id !== source || decoded.id !== id) throw new ContractError('creation_attempt_scope')
  return decoded
}

/** Stateless, explicit protocol calls. CAS writes and resolution each make one
 * request; an unknown result requires a caller-directed metadata read. */
export class CreationModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  get(sourceID: string, signal?: AbortSignal): Promise<ControlResult<CreationPolicy>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    return this.client.json(this.base(sourceID), { signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => policy(value, sourceID) })
  }
  set(sourceID: string, value: CreationSettings, signal?: AbortSignal): Promise<ControlResult<CreationPolicy>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => {
      const data = creationObject(value)
      return { expected_revision: decodeIdentifier(data.expected_revision, 'expected_revision', true),
        maximum_addresses: creationInteger(data.maximum_addresses, 0, 2147483647), attempts_per_round: creationInteger(data.attempts_per_round, 1, 5) }
    })
    return this.client.json(this.base(sourceID), { method: 'PUT', body, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => policy(value, sourceID) })
  }
  enable(sourceID: string, value: CreationRevision, signal?: AbortSignal): Promise<ControlResult<CreationPolicy>> {
    return this.toggle(sourceID, value, 'enable', signal)
  }
  disable(sourceID: string, value: CreationRevision, signal?: AbortSignal): Promise<ControlResult<CreationPolicy>> {
    return this.toggle(sourceID, value, 'disable', signal)
  }
  attempts(sourceID: string, query: CreationAttemptsQuery = {}, signal?: AbortSignal): Promise<ControlResult<CreationAttemptPage>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const search = input(() => {
      const data = creationObject(query)
      return { after_id: data.after_id === undefined ? '0' : decodeIdentifier(data.after_id, 'after_id', true), limit: data.limit === undefined ? 50 : creationInteger(data.limit, 1, 100) }
    })
    return this.client.json(this.base(sourceID) + '/attempts', { search, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const decoded = decodeCreationAttemptPage(value)
      if (decoded.source_id !== sourceID || decoded.after_id !== search.after_id || decoded.limit !== search.limit) throw new ContractError('creation_page_scope')
      return decoded
    } })
  }
  attempt(sourceID: string, id: string, signal?: AbortSignal): Promise<ControlResult<CreationAttempt>> {
    sourceID = input(() => decodeIdentifier(sourceID)); id = input(() => decodeIdentifier(id))
    return this.client.json(this.base(sourceID) + '/attempts/' + id, { signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => attempt(value, sourceID, id) })
  }
  resolve(sourceID: string, id: string, signal?: AbortSignal): Promise<ControlResult<CreationAttempt>> {
    sourceID = input(() => decodeIdentifier(sourceID)); id = input(() => decodeIdentifier(id))
    return this.client.json(this.base(sourceID) + '/attempts/' + id + '/resolve', { method: 'POST', body: {}, signal,
      resource: { kind: 'account', id: sourceID }, decodeResult: (value) => attempt(value, sourceID, id) })
  }
  private toggle(sourceID: string, value: CreationRevision, action: 'enable' | 'disable', signal?: AbortSignal): Promise<ControlResult<CreationPolicy>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => ({ expected_revision: decodeIdentifier(creationObject(value).expected_revision, 'expected_revision', true) }))
    return this.client.json(this.base(sourceID) + '/' + action, { method: 'POST', body, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => policy(value, sourceID) })
  }
  private base(sourceID: string): string { return '/accounts/' + sourceID + '/creation-policy' }
}
