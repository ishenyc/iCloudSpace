import { ContractError, decodeIdentifier } from './contracts.ts'
import { addressNullableID, addressObject, addressText, decodeAddressOperation } from './address-contracts.ts'
import type { AddressOperation } from './address-contracts.ts'

export type HMEOperationState = 'reserved' | 'candidate_unknown' | 'candidate_known' | 'confirming' | 'deactivate_unknown' | 'deactivated' | 'delete_unknown' | 'confirmed' | 'failed'
export type HMEOperation = Omit<AddressOperation, 'kind' | 'state' | 'query_only'> & { kind: 'create' | 'delete'; state: HMEOperationState; query_only: true }
export interface HMEWarning { kind: 'provider'; code: 'HME_OPERATION_UNSETTLED' | 'HME_OPERATION_REJECTED' | 'HME_CREATION_NOT_STARTED' | 'HME_FORWARDING_INITIALIZED' | 'HME_LOGIN_REQUIRED' | 'INSTALLATION_READ_ONLY'; message: string; outcome: 'unknown' | 'rejected' | 'not_sent'; submission_key: string; resource?: { kind: 'address'; id: string } }
export interface HMEProviderFailure { kind: string; code: string; http_status: number; unknown: boolean; retry_after_seconds: number }
export interface HMEOperationResult { operation: HMEOperation; candidate_address: string | null; warning: HMEWarning | null; provider_failure: HMEProviderFailure | null }
export interface HMECreate { operation_key: string; expected_revision: string; label: string; group_id: string | null; credential_profile: 'api_key_only' | 'mailbox' }
export interface HMEDelete { operation_key: string; expected_revision: string; confirm_address: string }
export interface HMEReconcile { expected_revision: string; credential_profile: 'api_key_only' | 'mailbox' }
export interface HMEReconciliation { imported: number; existing: number; archived: number; rediscovered: number; active: number; inactive: number; skipped_forward: number; conflicts: number; pending: number }

export function hmeKey(value: unknown, mutation = false): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value) || mutation && !/^[A-Za-z0-9]/.test(value)) throw new ContractError('hme_operation_key')
  return value
}
export function decodeHMEOperationResult(value: unknown): HMEOperationResult {
  const data = addressObject(value), operation = decodeAddressOperation(data.operation)
  const states = operation.kind === 'create' ? ['reserved', 'candidate_unknown', 'candidate_known', 'confirming', 'confirmed', 'failed'] : ['reserved', 'deactivate_unknown', 'deactivated', 'delete_unknown', 'confirmed', 'failed']
  if (operation.kind !== 'create' && operation.kind !== 'delete' || !states.includes(operation.state) || operation.query_only !== true) throw new ContractError('hme_operation')
  hmeKey(operation.operation_key)
  if ((operation.kind === 'delete' || operation.state === 'confirmed') && operation.address_id === null) throw new ContractError('hme_address')
  const candidate_address = data.candidate_address === null ? null : addressText(data.candidate_address)
  if (candidate_address !== null && candidate_address.length === 0) throw new ContractError('hme_candidate')
  let warning: HMEWarning | null = null
  if (data.warning !== null) {
    const item = addressObject(data.warning)
    const rejected = item.code === 'HME_OPERATION_REJECTED' && item.outcome === 'rejected' && operation.state === 'failed'
    const unsettled = item.code === 'HME_OPERATION_UNSETTLED' && item.outcome === 'unknown'
    const notStarted = ['HME_CREATION_NOT_STARTED', 'HME_FORWARDING_INITIALIZED', 'HME_LOGIN_REQUIRED', 'INSTALLATION_READ_ONLY'].includes(item.code as string) && item.outcome === 'not_sent' && operation.state === 'failed' && operation.kind === 'create' &&
      ['forwarding_target_unverified', 'forwarding_preflight_failed', 'source_changed', 'forwarding_initialized_retry_explicit'].includes(operation.error_code)
    if (item.kind !== 'provider' || !rejected && !unsettled && !notStarted || item.submission_key !== operation.operation_key) throw new ContractError('hme_warning')
    warning = { kind: 'provider', code: item.code as HMEWarning['code'], message: addressText(item.message), outcome: item.outcome as HMEWarning['outcome'], submission_key: hmeKey(item.submission_key) }
    if (item.resource !== undefined) {
      const resource = addressObject(item.resource), id = addressNullableID(resource.id)
      if (resource.kind !== 'address' || id === null || id !== operation.address_id) throw new ContractError('hme_warning_scope')
      warning.resource = { kind: 'address', id }
    }
  }
  let provider_failure: HMEProviderFailure | null = null
  if (data.provider_failure !== null) {
    const item = addressObject(data.provider_failure)
    const kinds = ['invalid', 'canceled', 'dns', 'connect', 'tls', 'timeout', 'transport', 'redirect', 'response_budget', 'malformed_response', 'authentication_required', 'rate_limited', 'apple_rejected', 'second_factor_required']
    if (!warning || typeof item.kind !== 'string' || !kinds.includes(item.kind) || typeof item.code !== 'string' || !/^[A-Za-z0-9_-]{0,64}$/.test(item.code) ||
      !Number.isSafeInteger(item.http_status) || item.http_status !== 0 && ((item.http_status as number) < 100 || (item.http_status as number) > 599) ||
      typeof item.unknown !== 'boolean' || warning.outcome === 'rejected' && item.unknown || !Number.isSafeInteger(item.retry_after_seconds) || (item.retry_after_seconds as number) < 0) throw new ContractError('hme_provider_failure')
    provider_failure = { kind: item.kind, code: item.code, http_status: item.http_status as number, unknown: item.unknown, retry_after_seconds: item.retry_after_seconds as number }
  }
  return { operation: operation as HMEOperation, candidate_address, warning, provider_failure }
}
export function decodeHMEReconciliation(value: unknown): HMEReconciliation {
  const data = addressObject(value), result = {} as HMEReconciliation
  for (const field of ['imported', 'existing', 'archived', 'rediscovered', 'active', 'inactive', 'skipped_forward', 'conflicts', 'pending'] as const) {
    if (!Number.isSafeInteger(data[field]) || (data[field] as number) < 0) throw new ContractError('hme_reconciliation')
    result[field] = data[field] as number
  }
  return result
}
