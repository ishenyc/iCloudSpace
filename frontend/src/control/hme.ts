import { ControlClient, ControlError, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { addressNullableID, addressProfile, addressText } from './address-contracts.ts'
import { decodeHMEOperationResult, decodeHMEReconciliation, hmeKey } from './hme-contracts.ts'
import type { HMECreate, HMEDelete, HMEOperationResult, HMEReconcile, HMEReconciliation } from './hme-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_hme_input', { outcome: 'not_sent' }) }
}
function matched(value: unknown, source: string, key: string, kind: 'create' | 'delete', address?: string): HMEOperationResult {
  const result = decodeHMEOperationResult(value), operation = result.operation
  if (operation.source_id !== source || operation.operation_key !== key || operation.kind !== kind || address !== undefined && operation.address_id !== address) throw new ContractError('hme_operation_scope')
  return result
}
function original(error: unknown, key: string, kind: 'account' | 'address', id: string): boolean {
  return error instanceof ControlError && error.outcome === 'unknown' && error.resource?.kind === kind && error.resource.id === id &&
    (error.requestKey === key || error.submissionKey === key) && (error.requestKey === undefined || error.requestKey === key) && (error.submissionKey === undefined || error.submissionKey === key)
}

/** Each method performs one explicit request. Accepted/unsettled operation
 * envelopes remain operations, never invented created/deleted address results. */
export class HMEModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  create(sourceID: string, value: HMECreate, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => ({ operation_key: hmeKey(value.operation_key, true), expected_revision: decodeIdentifier(value.expected_revision), label: addressText(value.label),
      group_id: addressNullableID(value.group_id), credential_profile: addressProfile(value.credential_profile) }))
    return this.client.json(this.base(sourceID) + '/creations', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => matched(value, sourceID, body.operation_key, 'create') })
  }
  queryCreate(sourceID: string, key: string, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult>> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => hmeKey(key))
    return this.client.json(this.base(sourceID) + '/creations/query', { method: 'POST', body: { operation_key: key }, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => matched(value, sourceID, key, 'create') })
  }
  reconcile(sourceID: string, value: HMEReconcile, signal?: AbortSignal): Promise<ControlResult<HMEReconciliation>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => ({ expected_revision: decodeIdentifier(value.expected_revision), credential_profile: addressProfile(value.credential_profile) }))
    return this.client.json(this.base(sourceID) + '/directory/reconcile', { method: 'POST', body, signal, resource: { kind: 'account', id: sourceID }, decodeResult: decodeHMEReconciliation })
  }
  delete(sourceID: string, addressID: string, value: HMEDelete, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult>> {
    sourceID = input(() => decodeIdentifier(sourceID)); addressID = input(() => decodeIdentifier(addressID))
    const body = input(() => ({ operation_key: hmeKey(value.operation_key, true), expected_revision: decodeIdentifier(value.expected_revision), confirm_address: addressText(value.confirm_address) }))
    return this.client.json(this.base(sourceID) + '/addresses/' + addressID + '/deletion', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'address', id: addressID }, decodeResult: (value) => matched(value, sourceID, body.operation_key, 'delete', addressID) })
  }
  queryDelete(sourceID: string, addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult>> {
    sourceID = input(() => decodeIdentifier(sourceID)); addressID = input(() => decodeIdentifier(addressID)); key = input(() => hmeKey(key))
    return this.client.json(this.base(sourceID) + '/addresses/' + addressID + '/deletion/query', { method: 'POST', body: { operation_key: key }, signal, resource: { kind: 'address', id: addressID }, decodeResult: (value) => matched(value, sourceID, key, 'delete', addressID) })
  }
  async queryUnknownCreate(error: unknown, sourceID: string, key: string, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult> | undefined> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => hmeKey(key))
    return original(error, key, 'account', sourceID) ? this.queryCreate(sourceID, key, signal) : undefined
  }
  async queryUnknownDelete(error: unknown, sourceID: string, addressID: string, key: string, signal?: AbortSignal): Promise<ControlResult<HMEOperationResult> | undefined> {
    sourceID = input(() => decodeIdentifier(sourceID)); addressID = input(() => decodeIdentifier(addressID)); key = input(() => hmeKey(key))
    return original(error, key, 'address', addressID) ? this.queryDelete(sourceID, addressID, key, signal) : undefined
  }
  private base(source: string): string { return '/accounts/' + source + '/hme' }
}
