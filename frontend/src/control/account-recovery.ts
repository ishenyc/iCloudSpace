import { decodeIdentifier } from './contracts.ts'
import { credentialKey } from './credential-contracts.ts'
import { hmeKey } from './hme-contracts.ts'
import { providerAction, providerRequestKey } from './provider-session-contracts.ts'
import type { ProviderAuthResult } from './provider-session-contracts.ts'
import type { ProviderAction } from './provider-session-contracts.ts'
import { ClientStateError, clientStateControlBase } from './client-state-handoff.ts'
import type { ClientStateStorage, PreservedClientState } from './client-state-handoff.ts'
import { handoffEntryReference, previousControlBase } from './entry-handoff.ts'

export type AccountRecoveryInput =
  | { readonly kind: 'hme'; readonly source_id: string; readonly operation_key: string }
  | { readonly kind: 'provider'; readonly source_id: string; readonly action: ProviderAction; readonly request_key: string }
  | { readonly kind: 'ack'; readonly source_id: string; readonly delivery_keys: readonly string[] }
  | { readonly kind: 'complete'; readonly source_id: string; readonly delivery_key: string; readonly generation: string }
export type AccountRecovery = AccountRecoveryInput & { readonly version: 1; readonly control_base: string; readonly operator_id: string }
export interface AccountRecoverySnapshot {
  readonly records: readonly AccountRecovery[]
  readonly blocked: boolean
  readonly error: ClientStateError | null
  readonly preserved: readonly PreservedClientState[]
}

const providerActions: readonly ProviderAction[] = ['login', 'load_challenge', 'send_device_code', 'verify_device_code', 'send_sms', 'verify_sms', 'verify_security_key', 'trust_browser', 'decline_trust', 'exchange_token', 'validate_session', 'restore_session', 'clear_authentication']
const slots = ['hme', 'ack', 'complete', ...providerActions.flatMap(action => ['provider:' + action + ':0', 'provider:' + action + ':1'])]
function recordSlots(value: AccountRecoveryInput): string[] { return value.kind === 'provider' ? ['provider:' + value.action + ':0', 'provider:' + value.action + ':1'] : [value.kind] }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ClientStateError('account_recovery_invalid')
  return value as Record<string, unknown>
}
function input(value: unknown): AccountRecoveryInput {
  const row = object(value), source_id = decodeIdentifier(row.source_id)
  if (row.kind === 'hme') return Object.freeze({ kind: 'hme', source_id, operation_key: hmeKey(row.operation_key) })
  if (row.kind === 'provider') return Object.freeze({ kind: 'provider', source_id, action: providerAction(row.action), request_key: providerRequestKey(row.request_key) })
  if (row.kind === 'complete') return Object.freeze({ kind: 'complete', source_id, delivery_key: credentialKey(row.delivery_key), generation: decodeIdentifier(row.generation) })
  if (row.kind === 'ack') {
    if (!Array.isArray(row.delivery_keys) || row.delivery_keys.length === 0 || row.delivery_keys.length > 1000) throw new ClientStateError('account_recovery_invalid')
    const delivery_keys = row.delivery_keys.map(credentialKey)
    if (new Set(delivery_keys).size !== delivery_keys.length) throw new ClientStateError('account_recovery_invalid')
    return Object.freeze({ kind: 'ack', source_id, delivery_keys: Object.freeze(delivery_keys) })
  }
  throw new ClientStateError('account_recovery_invalid')
}

/** Small explicit query-reference store. Each source/action owns one independent
 * slot. Provider actions have two fixed slots so a caller can first commit a
 * new explicit action, then forget its already-settled predecessor. This store
 * does not decide whether an earlier receipt permits that new action.
 * Passwords, codes, capsules, challenge tokens and follow-on intents are absent. */
export class AccountRecoveryStore {
  private readonly storage: ClientStateStorage
  readonly controlBase: string
  readonly operatorID: string
  private readonly prefix: string

  constructor(storage: ClientStateStorage, controlBase: string, operatorID: string) {
    this.storage = storage; this.controlBase = clientStateControlBase(controlBase); this.operatorID = decodeIdentifier(operatorID)
    this.prefix = 'icloudspace:account-recovery:v1:' + encodeURIComponent(this.controlBase) + ':' + this.operatorID + ':'
  }
  private key(sourceID: string, selected: string): string { return this.prefix + decodeIdentifier(sourceID) + ':' + selected }
  private record(value: AccountRecoveryInput): AccountRecovery {
    return Object.freeze({ version: 1, control_base: this.controlBase, operator_id: this.operatorID, ...input(value) })
  }
  private parse(raw: string, sourceID: string, selected: string): AccountRecovery {
    try {
      const row = object(JSON.parse(raw)), result = this.record(input(row))
      if (row.version !== 1 || row.control_base !== this.controlBase || row.operator_id !== this.operatorID || result.source_id !== sourceID || !recordSlots(result).includes(selected) || Object.keys(row).some(key => !Object.keys(result).includes(key))) throw new Error()
      return result
    } catch { throw new ClientStateError('account_recovery_invalid') }
  }
  /** Inspect keeps other readable references queryable if one action is corrupt.
   * It reads only known slots for this supplied source, never scans the origin. */
  inspect(sourceID: string): AccountRecoverySnapshot {
    sourceID = decodeIdentifier(sourceID)
    const records: AccountRecovery[] = [], preserved: PreservedClientState[] = []
    let error: ClientStateError | null = null
    const retain = (record: AccountRecovery) => { if (!records.some(prior => JSON.stringify(prior) === JSON.stringify(record))) records.push(record) }
    for (const selected of slots) {
      const key = this.key(sourceID, selected)
      const previous = previousControlBase(this.controlBase)
      if (previous) try {
          const old = 'icloudspace:account-recovery:v1:' + encodeURIComponent(previous) + ':' + this.operatorID + ':' + sourceID + ':' + selected
          const previousStore = new AccountRecoveryStore(this.storage, previous, this.operatorID)
          const raw = this.storage.getItem(old)
          if (raw !== null) { preserved.push(Object.freeze({ key: old, value: raw })); retain(this.record(previousStore.parse(raw,sourceID,selected))) }
          handoffEntryReference(this.storage, old, key, raw => {
            return JSON.stringify(this.record(previousStore.parse(raw,sourceID,selected)))
          })
      } catch(e) { error ??= e instanceof ClientStateError ? e : new ClientStateError('account_recovery_read_denied') }
      try {
        const raw = this.storage.getItem(key)
        if (raw !== null) { preserved.push(Object.freeze({ key, value: raw })); retain(this.parse(raw, sourceID, selected)) }
      } catch (e) { error ??= e instanceof ClientStateError ? e : new ClientStateError('account_recovery_read_denied') }
    }
    return Object.freeze({ records: Object.freeze(records), blocked: error !== null, error, preserved: Object.freeze(preserved) })
  }
  read(sourceID: string): readonly AccountRecovery[] {
    const result = this.inspect(sourceID)
    if (result.error) throw result.error
    return result.records
  }
  /** Must finish before the caller dispatches any network mutation. */
  remember(value: AccountRecoveryInput): AccountRecovery {
    const record = this.record(value), raw = JSON.stringify(record)
    const state = this.inspect(record.source_id)
    if (state.error) throw state.error
    try {
      let target: string | null = null
      for (const selected of recordSlots(record)) {
        const key = this.key(record.source_id, selected), existing = this.storage.getItem(key)
        if (existing === null) { target ??= selected; continue }
        const original = this.parse(existing, record.source_id, selected)
        if (JSON.stringify(original) === raw) return original
      }
      if (target === null) throw new ClientStateError('account_recovery_conflict')
      const key = this.key(record.source_id, target)
      this.storage.setItem(key, raw)
      const committed = this.storage.getItem(key)
      if (committed !== raw) throw new ClientStateError('account_recovery_write_unconfirmed')
      return this.parse(committed, record.source_id, target)
    } catch (e) { throw e instanceof ClientStateError ? e : new ClientStateError('account_recovery_write_denied') }
  }
  /** Remove only the exact original reference after its query proves settlement. */
  archiveExpiredProvider(value: AccountRecovery, result: ProviderAuthResult): void {
    if (value.kind !== 'provider' || value.operator_id !== this.operatorID || value.control_base !== this.controlBase ||
        result.state !== 'expired' || !result.durable || result.receipt?.request_key !== value.request_key ||
        result.receipt.action !== value.action || result.session?.source_id !== value.source_id) throw new ClientStateError('account_recovery_conflict')
    // Keep each receipt under its own key. Two tabs archiving distinct attempts
    // cannot overwrite one another. Never copy the provider challenge token.
    const key = this.key(value.source_id,'expired-provider:' + value.request_key)
    const saved = JSON.stringify({reference:this.record(value), receipt:result.receipt})
    this.storage.setItem(key,saved)
    if (this.storage.getItem(key) !== saved) throw new ClientStateError('account_recovery_conflict')
    this.forget(value)
  }
  forget(value: AccountRecovery): void {
    const supplied = object(value)
    if (supplied.version !== 1 || supplied.control_base !== this.controlBase || supplied.operator_id !== this.operatorID) throw new ClientStateError('account_recovery_scope')
    const record = this.record(value)
    try {
      for (const selected of recordSlots(record)) {
        const key = this.key(record.source_id, selected), raw = this.storage.getItem(key)
        if (raw === null || JSON.stringify(this.parse(raw, record.source_id, selected)) !== JSON.stringify(record)) continue
        if (this.storage.getItem(key) !== raw) throw new ClientStateError('account_recovery_conflict')
        this.storage.removeItem(key)
        if (this.storage.getItem(key) !== null) throw new ClientStateError('account_recovery_cleanup_unconfirmed')
      }
    } catch (e) { throw e instanceof ClientStateError ? e : new ClientStateError('account_recovery_cleanup_denied') }
  }
}
