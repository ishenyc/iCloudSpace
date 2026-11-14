import { ControlClient, ControlError, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { cleanupConfirmation, cleanupOperationKey, decodeCleanupRecovery, decodeLocalCleanupReceipt } from './local-cleanup-contracts.ts'
import type { LocalCleanupCommand, LocalCleanupReceipt, LocalCleanupRecovery } from './local-cleanup-contracts.ts'

function input<T>(read: () => T): T { try { return read() } catch { throw new RequestConfigurationError('invalid_local_cleanup_input', { outcome: 'not_sent' }) } }
function matching(value: unknown, recovery: LocalCleanupRecovery): LocalCleanupReceipt {
  const result = decodeLocalCleanupReceipt(value)
  if (result.operation_key !== recovery.operation_key || result.source_id !== recovery.source_id || result.kind !== recovery.kind || result.address_id !== recovery.address_id) throw new ContractError('local_cleanup_scope')
  return result
}
export class LocalCleanupModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }
  /** Caller chooses and persists the original operation key. A receipt states
   * retirement/cleanup progress; it never implies all historical facts vanished. */
  retireSource(sourceID: string, value: LocalCleanupCommand, signal?: AbortSignal): Promise<ControlResult<LocalCleanupReceipt>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => ({ operation_key: cleanupOperationKey(value.operation_key), expected_revision: decodeIdentifier(value.expected_revision), confirmation: cleanupConfirmation(value.confirmation) }))
    const recovery: LocalCleanupRecovery = { version: 1, kind: 'source_delete', source_id: sourceID, address_id: null, operation_key: body.operation_key }
    return this.client.json('/accounts/' + sourceID + '/retirements', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'account', id: sourceID }, decodeResult: value => matching(value, recovery) })
  }
  purgeAddress(sourceID: string, addressID: string, value: LocalCleanupCommand, signal?: AbortSignal): Promise<ControlResult<LocalCleanupReceipt>> {
    sourceID = input(() => decodeIdentifier(sourceID)); addressID = input(() => decodeIdentifier(addressID))
    const body = input(() => ({ source_id: sourceID, operation_key: cleanupOperationKey(value.operation_key), expected_revision: decodeIdentifier(value.expected_revision), confirmation: cleanupConfirmation(value.confirmation) }))
    const recovery: LocalCleanupRecovery = { version: 1, kind: 'address_purge', source_id: sourceID, address_id: addressID, operation_key: body.operation_key }
    return this.client.json('/addresses/' + addressID + '/local-purges', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'address', id: addressID }, decodeResult: value => matching(value, recovery) })
  }
  query(recovery: LocalCleanupRecovery, signal?: AbortSignal): Promise<ControlResult<LocalCleanupReceipt>> {
    recovery = input(() => decodeCleanupRecovery(recovery))
    const stable = recovery
    return this.client.json('/accounts/' + recovery.source_id + '/local-cleanups/query', { method: 'POST', body: { operation_key: recovery.operation_key }, signal, requestKey: recovery.operation_key, resource: { kind: 'account', id: recovery.source_id }, decodeResult: value => matching(value, stable) })
  }
  queryUnknown(error: unknown, recovery: LocalCleanupRecovery, signal?: AbortSignal): Promise<ControlResult<LocalCleanupReceipt>> | undefined {
    recovery = input(() => decodeCleanupRecovery(recovery))
    const target = recovery.address_id === null ? { kind: 'account', id: recovery.source_id } : { kind: 'address', id: recovery.address_id }
    if (!(error instanceof ControlError) || error.outcome !== 'unknown' || error.requestKey !== recovery.operation_key && error.submissionKey !== recovery.operation_key || error.resource && (error.resource.kind !== target.kind || error.resource.id !== target.id)) return undefined
    return this.query(recovery, signal)
  }
}
