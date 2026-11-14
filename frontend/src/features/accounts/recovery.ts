import { AccountRecoveryStore } from '../../control/account-recovery.ts'
import type { AccountRecovery, AccountRecoveryInput, AccountRecoverySnapshot } from '../../control/account-recovery.ts'
import type { ControlServices } from '../../control/runtime.ts'
import type { ProviderAuthResult } from '../../control/provider-session-contracts.ts'
import { readPendingBundle } from './model.ts'

export function sameAccountRecovery(left: AccountRecovery | null, right: AccountRecovery): boolean {
  return left !== null && JSON.stringify(left) === JSON.stringify(right)
}
export function retainReadableAccountRecoveries(previous: AccountRecoverySnapshot, next: AccountRecoverySnapshot): AccountRecoverySnapshot {
  if (!next.blocked) return next
  return { ...next, records: [...next.records, ...previous.records.filter(record => !next.records.some(current => sameAccountRecovery(record, current)))],
    preserved: [...next.preserved, ...previous.preserved.filter(row => !next.preserved.some(current => current.key === row.key && current.value === row.value))] }
}
export function accountRecoveryLabel(record: AccountRecovery): string {
  if (record.kind === 'provider') return `Apple ${record.action} · ${record.request_key}`
  if (record.kind === 'hme') return `创建邮箱 · ${record.operation_key}`
  if (record.kind === 'ack') return `确认凭据 · ${record.delivery_keys.join(', ')}`
  return `补全凭据 · ${record.delivery_key} · 代际 ${record.generation}`
}
export function accountRecoveryCopyValue(record: AccountRecovery): string {
  if (record.kind === 'provider') return record.request_key
  if (record.kind === 'hme') return record.operation_key
  if (record.kind === 'ack') return JSON.stringify({ source_id: record.source_id, delivery_keys: record.delivery_keys })
  return JSON.stringify({ source_id: record.source_id, delivery_key: record.delivery_key, generation: record.generation })
}
export function providerRecoveryDisposition(result: ProviderAuthResult): 'pending' | 'continue' | 'terminal' {
  if (!result.durable || !result.receipt || result.receipt.prepared || result.receipt.outcome === 'unknown') return 'pending'
  // A settled MFA step still owns a live flow. Keep its original query pointer
  // across reload, while allowing the next explicitly selected action.
  return result.state === 'mfa' ? 'continue' : 'terminal'
}

/** These are the exact command/query helpers used by AccountDetailPage. The
 * supplied view check includes the route epoch, so late A->B->A completions
 * cannot delete a current record or start a late secret read. */
export class AccountRecoveryActions {
  readonly store: AccountRecoveryStore
  readonly sourceID: string
  private readonly current: () => boolean
  constructor(store: AccountRecoveryStore, sourceID: string, current: () => boolean) {
    this.store = store; this.sourceID = sourceID; this.current = current
  }
  prepare(input: AccountRecoveryInput): AccountRecovery {
    if (!this.current() || input.source_id !== this.sourceID) throw new Error('原操作所属页面已变化，请返回原主号查询。')
    const record = this.store.remember(input)
    // A prior settled MFA pointer is retired by the UI only after the new
    // action returns a definite receipt. Pre-dispatch failures retain it.
    if (!this.current()) throw new Error('原操作所属页面已变化，请返回原主号查询。')
    return record
  }
  settle(record: AccountRecovery): boolean {
    if (!this.current() || record.source_id !== this.sourceID) return false
    this.store.forget(record)
    return true
  }
  async query(services: Pick<ControlServices, 'hme' | 'providerSessions' | 'credentials' | 'addresses'>, record: AccountRecovery, signal?: AbortSignal) {
    if (!this.current() || record.source_id !== this.sourceID || record.control_base !== this.store.controlBase || record.operator_id !== this.store.operatorID) throw new Error('原操作不属于当前页面。')
    const source = record.source_id
    if (record.kind === 'provider') return { kind: 'provider' as const, result: (await services.providerSessions.query(source, { action: record.action, request_key: record.request_key }, signal)).result }
    if (record.kind === 'hme') return { kind: 'hme' as const, result: (await services.hme.queryCreate(source, record.operation_key, signal)).result }
    if (record.kind === 'ack') {
      const facts = await Promise.all(record.delivery_keys.map(key => services.credentials.delivery(source, key, signal)))
      return { kind: 'ack' as const, acknowledged: facts.every(fact => fact.result.acknowledged_at !== null) }
    }
    const delivery = (await services.credentials.delivery(source, record.delivery_key, signal)).result
    if (!this.current() || signal?.aborted) throw new DOMException('Canceled', 'AbortError')
    if (delivery.generation !== record.generation) throw new Error('原待领取凭据代际已变化，保留原记录供核对，不会重新补全。')
    const item = { delivery }, bundle = await readPendingBundle(services, source, item, signal)
    return { kind: 'complete' as const, item: { delivery, bundle } }
  }
}
