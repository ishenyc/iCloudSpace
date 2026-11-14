import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'

export type ProviderAction = 'login' | 'load_challenge' | 'send_device_code' | 'verify_device_code' | 'send_sms' | 'verify_sms' | 'verify_security_key' | 'trust_browser' | 'exchange_token' | 'validate_session' | 'restore_session' | 'clear_authentication'
export type ProviderChallengeAction = Exclude<ProviderAction, 'login' | 'restore_session' | 'clear_authentication'>
export interface ProviderSessionStatus {
  source_id: string; principal_revision: string; revision: string | null; authenticated: boolean
  saved_at: string | null; last_validated_at: string | null; expires_at: string | null
}
export interface ProviderReceipt {
  request_key: string; action: ProviderAction; outcome: 'accepted' | 'rejected' | 'unknown' | 'not_sent'
  error_code: string; prepared: boolean; started_at: string; finished_at: string | null
}
export interface ProviderAuthOptions {
  auth_type: string; trusted_device: boolean; sms: boolean
  phones: { id: string; numeric: boolean; display: string; mode: 'sms' | 'voice' }[]
  security_keys: { id: string; kind: 'fsa1' | 'fsa2'; challenge: string; rp_id: 'apple.com' | 'idmsa.apple.com'; request_id: string; key_handles: string[] }[]
}
export interface ProviderAuthResult {
  request_key: string; challenge_token: string; challenge_revision: string | null
  state: 'password' | 'mfa' | 'complete' | 'failed' | 'expired'
  session: ProviderSessionStatus | null; receipt: ProviderReceipt | null; options: ProviderAuthOptions | null
  next_action: ProviderAction | ''; durable: boolean
}
export interface ProviderRequest { request_key: string }
export interface ProviderLogin extends ProviderRequest { password: string }
export interface ProviderQuery extends ProviderRequest { action: ProviderAction; challenge_token?: string }
export interface ProviderSecurityKeyAssertion {
  challenge_id: string; credential_id: string; client_data_json: string; authenticator_data: string; signature: string; user_handle?: string
}
export type ProviderActionInput = ProviderRequest & { challenge_token: string } & (
  { action: 'load_challenge' | 'send_device_code' | 'trust_browser' | 'exchange_token' | 'validate_session' } |
  { action: 'verify_device_code'; code: string } |
  { action: 'send_sms'; phone_id: string; mode: 'sms' | 'voice' } |
  { action: 'verify_sms'; phone_id: string; mode: 'sms' | 'voice'; code: string } |
  { action: 'verify_security_key'; assertion: ProviderSecurityKeyAssertion }
)
// An imported canonical capsule is an opaque provider document. The server
// validates its full schema/binding; the model never keeps it in session state.
export interface ProviderRestore extends ProviderRequest { document: string | Readonly<Record<string, unknown>> }

const actions = ['login', 'load_challenge', 'send_device_code', 'verify_device_code', 'send_sms', 'verify_sms', 'verify_security_key', 'trust_browser', 'exchange_token', 'validate_session', 'restore_session', 'clear_authentication'] as const
export function providerObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('provider_object')
  return value as Record<string, unknown>
}
export function providerText(value: unknown, maximum = 4096, required = false): string {
  if (typeof value !== 'string' || required && value.length === 0 || new TextEncoder().encode(value).byteLength > maximum) throw new ContractError('provider_text')
  return value
}
export function providerBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('provider_boolean')
  return value
}
export function providerChoice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) throw new ContractError('provider_choice')
  return value as T
}
export function providerAction(value: unknown): ProviderAction { return providerChoice(value, actions) }
export function providerRequestKey(value: unknown, mutation = false): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:-]{8,128}$/.test(value) || mutation && !/^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/.test(value)) throw new ContractError('provider_request_key')
  return value
}
export function providerChallengeToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new ContractError('provider_challenge')
  return value
}
function nullableInstant(value: unknown): string | null { return value === null ? null : decodeInstant(value) }
function list(value: unknown, maximum: number): unknown[] {
  if (value === null) return [] // Go's empty metadata slices may encode as null.
  if (!Array.isArray(value) || value.length > maximum) throw new ContractError('provider_options')
  return value
}
export function decodeProviderSessionStatus(value: unknown): ProviderSessionStatus {
  const data = providerObject(value)
  const revision = data.revision === null ? null : decodeIdentifier(data.revision)
  const saved_at = nullableInstant(data.saved_at), authenticated = providerBoolean(data.authenticated)
  if ((revision === null) !== (saved_at === null) || authenticated && revision === null) throw new ContractError('provider_session')
  return { source_id: decodeIdentifier(data.source_id), principal_revision: decodeIdentifier(data.principal_revision), revision, authenticated,
    saved_at, last_validated_at: nullableInstant(data.last_validated_at), expires_at: nullableInstant(data.expires_at) }
}
export function decodeProviderReceipt(value: unknown): ProviderReceipt {
  const data = providerObject(value), outcome = providerChoice(data.outcome, ['accepted', 'rejected', 'unknown', 'not_sent'] as const)
  const prepared = providerBoolean(data.prepared)
  if (prepared && outcome !== 'unknown') throw new ContractError('provider_receipt')
  return { request_key: providerRequestKey(data.request_key), action: providerAction(data.action), outcome,
    error_code: providerText(data.error_code, 80), prepared, started_at: decodeInstant(data.started_at), finished_at: nullableInstant(data.finished_at) }
}
export function decodeProviderAuthOptions(value: unknown): ProviderAuthOptions {
  const data = providerObject(value)
  const phones = list(data.phones, 20).map((value) => {
    const phone = providerObject(value), id = providerText(phone.id, 64, true), numeric = phone.numeric === undefined ? false : providerBoolean(phone.numeric)
    if (numeric && !/^\d+$/.test(id)) throw new ContractError('provider_phone')
    return { id, numeric, display: providerText(phone.display, 128), mode: providerChoice(phone.mode, ['sms', 'voice'] as const) }
  })
  const security_keys = list(data.security_keys, 4).map((value) => {
    const key = providerObject(value)
    return { id: providerText(key.id, 64, true), kind: providerChoice(key.kind, ['fsa1', 'fsa2'] as const), challenge: providerText(key.challenge, 2048, true),
      rp_id: providerChoice(key.rp_id, ['apple.com', 'idmsa.apple.com'] as const), request_id: key.request_id === undefined ? '' : providerText(key.request_id, 512),
      key_handles: key.key_handles === undefined ? [] : list(key.key_handles, 20).map((value) => providerText(value, 2048, true)) }
  })
  if (new Set(phones.map((phone) => phone.id)).size !== phones.length || new Set(security_keys.map((key) => key.id)).size !== security_keys.length) throw new ContractError('provider_options')
  return { auth_type: providerText(data.auth_type, 32), trusted_device: providerBoolean(data.trusted_device), sms: providerBoolean(data.sms), phones, security_keys }
}
export function decodeProviderAuthResult(value: unknown): ProviderAuthResult {
  const data = providerObject(value), request_key = providerRequestKey(data.request_key)
  const receipt = data.receipt === null ? null : decodeProviderReceipt(data.receipt)
  if (receipt !== null && receipt.request_key !== request_key) throw new ContractError('provider_receipt_scope')
  return { request_key, challenge_token: providerChallengeToken(data.challenge_token), challenge_revision: data.challenge_revision === null ? null : decodeIdentifier(data.challenge_revision),
    state: providerChoice(data.state, ['password', 'mfa', 'complete', 'failed', 'expired'] as const), session: data.session === null ? null : decodeProviderSessionStatus(data.session),
    receipt, options: data.options === null ? null : decodeProviderAuthOptions(data.options), next_action: data.next_action === '' ? '' : providerAction(data.next_action), durable: providerBoolean(data.durable) }
}
