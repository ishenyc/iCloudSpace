import { AccountRecoveryStore } from '../../control/account-recovery.ts'
import type { AccountRecovery, AccountRecoveryInput, AccountRecoverySnapshot } from '../../control/account-recovery.ts'
import type { ControlServices } from '../../control/runtime.ts'
import type { ProviderAction, ProviderAuthResult } from '../../control/provider-session-contracts.ts'
import { ReceiptError } from '../../lib/feedback.ts'
import { diagnosticMessage } from '../../lib/diagnostic-message.ts'
import { readPendingBundle } from './model.ts'

export function sameAccountRecovery(left: AccountRecovery | null, right: AccountRecovery): boolean {
  return left !== null && JSON.stringify(left) === JSON.stringify(right)
}
/** The durable record exists before dispatch. Only orphaned or unresolved records need a recovery prompt. */
export function recoveriesNeedingAttention(records: readonly AccountRecovery[], active: AccountRecovery | null, continuation: AccountRecovery | null) {
  return records.filter(record => !sameAccountRecovery(active, record) && !sameAccountRecovery(continuation, record))
}
export function retainReadableAccountRecoveries(previous: AccountRecoverySnapshot, next: AccountRecoverySnapshot): AccountRecoverySnapshot {
  if (!next.blocked) return next
  return { ...next, records: [...next.records, ...previous.records.filter(record => !next.records.some(current => sameAccountRecovery(record, current)))],
    preserved: [...next.preserved, ...previous.preserved.filter(row => !next.preserved.some(current => current.key === row.key && current.value === row.value))] }
}
export const providerLabels: Record<ProviderAction, string> = {
  login: '登录 Apple', load_challenge: '读取验证方式', send_device_code: '发送设备验证码', verify_device_code: '验证设备验证码',
  send_sms: '发送短信验证码', verify_sms: '验证短信验证码', verify_security_key: '验证安全密钥', trust_browser: '信任此登录环境', decline_trust: '仅本次登录',
  exchange_token: '完成登录', validate_session: '验证会话', clear_authentication: '退出 Apple', restore_session: '恢复 Apple 会话',
}
export function accountRecoveryLabel(record: AccountRecovery): string {
  if (record.kind === 'provider') return `${providerLabels[record.action]} · ${record.request_key}`
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
  return result.state === 'mfa' || result.state === 'password' && Boolean(result.next_action) ? 'continue' : 'terminal'
}

export function appleVerificationAction(result: ProviderAuthResult | null, factor: 'device' | 'sms'): ProviderAction | '' {
  if (!result || providerRecoveryDisposition(result) !== 'continue') return ''
  const next = result.next_action
  if (!next && result.receipt?.action && !['load_challenge','send_device_code','send_sms','verify_device_code','verify_sms'].includes(result.receipt.action)) return ''
  if (next && next !== 'verify_device_code' && next !== 'verify_sms') return next
  const options = result.options
  if (options?.sms && options.phones.length && (factor === 'sms' || !options.trusted_device)) return 'verify_sms'
  if (options?.trusted_device) return 'verify_device_code'
  if (options?.security_keys.length) return 'verify_security_key'
  return 'load_challenge'
}

/** Only a response to the user's current submit can advance the flow. A lookup
 * or remount never sends another code or repeats a trust/token exchange. */
export function nextAppleLoginAction(result: ProviderAuthResult): 'load_challenge' | 'send_device_code' | null {
  const receipt = result.receipt
  if (!result.durable || !receipt || receipt.prepared || receipt.outcome !== 'accepted' || (result.state !== 'mfa' && result.state !== 'password')) return null
  if (receipt.action === 'login' && result.next_action === 'load_challenge') return 'load_challenge'
  if ((receipt.action === 'login' || receipt.action === 'load_challenge') && result.next_action === 'verify_device_code' && result.options?.trusted_device) return 'send_device_code'
  return null
}

export function deviceDispatchAccepted(result: ProviderAuthResult | null): boolean {
  const r = result?.receipt
  if (!result?.durable || !r || r.prepared || r.action !== 'send_device_code') return false
  return r.outcome === 'accepted' || r.outcome === 'rejected' && r.error_code === 'apple_rejected' && r.http_status === 202
}

export function appleReceiptMessage(result: ProviderAuthResult, label: string): string {
  const r = result.receipt
  if (!r) return '当前步骤没有可核对的回执，请查询原请求。'
  if (!result.durable || r.prepared || r.outcome === 'unknown') return label + '的结果待确认，当前登录尚未完成。请查询原请求。'
  if (r.outcome === 'accepted' || deviceDispatchAccepted(result)) {
    if (result.state === 'expired') return '本次验证已过期，请重新登录。'
    if (result.state === 'failed') return 'Apple 登录未完成，请核对主号状态。'
    return ''
  }
  if (r.outcome === 'not_sent') return label + '请求尚未发出，请核对当前步骤。'
  if (r.provider_code === 'PRINCIPAL_MISMATCH') return '会话交换返回的账户身份与当前主号不匹配，登录未完成。请核对 Apple 登录账户。'
  if (r.error_code === 'rate_limited' || r.http_status === 429) return 'Apple 暂时限制了请求次数，请稍后再试。'
  if (r.action === 'send_device_code') return '这次发码请求没有成功。设备上如已收到验证码，可以直接填写。'
  if (r.action === 'decline_trust') return 'Apple 未接受本次登录方式选择。请查看当前步骤，或关闭后稍后继续。'
  if (r.action === 'verify_device_code' || r.action === 'verify_sms') return 'Apple 未接受本次验证。请核对最新的六位验证码和所选验证方式。'
  if (r.action === 'login') return 'Apple 未接受这次登录，请核对账户、密码和服务区域。'
  if (r.action === 'trust_browser') return 'Apple 尚未确认信任此浏览器，登录未完成。请查看当前验证步骤。'
  if (r.action === 'exchange_token') return 'Apple 未能建立登录会话，请核对当前主号的登录状态。'
  return diagnosticMessage(r.error_code || '', label + '未完成，请核对 Apple 账户状态。')
}
export function appleReceiptError(result: ProviderAuthResult, label: string) {
  const message = appleReceiptMessage(result, label), r = result.receipt
  return message ? new ReceiptError(message, { code: r?.error_code, providerCode: r?.provider_code, httpStatus: r?.http_status, requestId: result.request_key || r?.request_key }) : null
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
