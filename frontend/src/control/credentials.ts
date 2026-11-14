import { ControlClient, ControlError, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier, decodeNull } from './contracts.ts'
import { FULL_ROTATION_CONFIRMATION, credentialDigest, credentialKey, decodeCredentialBundleReveal, decodeCredentialDelivery,
  decodeCredentialDeliveryPage, decodeCredentialRotation, decodeCredentialScope, decodePendingCredentialReveal, decodePendingCredentialBundleReveal } from './credential-contracts.ts'
import type { CredentialBundleReveal, CredentialDelivery, CredentialDeliveryPage, CredentialRotation, CredentialRotationKind,
  CredentialScope, PendingCredentialReveal, PendingCredentialBundleReveal, PendingDeliveryQuery, RotateAPIKey, RotateAllCredentials, RotateCredentialBundle } from './credential-contracts.ts'

export interface CredentialsModelOptions {
  // Root owns SessionModel/UI invalidation. No cookie, token or password is
  // stored here. Historical read-only receipt queries do not revoke a new login.
  onSessionRevoked?: (revision?: number) => void
  sessionRevision?: () => number
}
export interface APIKeyReveal {
  address_id: string
  api: { key: string; purposes: ('latest_read' | 'mail_read' | 'mail_consume' | 'raw_read')[] }
}
function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_credential_input', { outcome: 'not_sent' }) }
}
function deliveryMatches(value: unknown, source: string, key: string): CredentialDelivery {
  const result = decodeCredentialDelivery(value)
  if (result.source_id !== source || result.delivery_key !== key) throw new ContractError('credential_delivery_scope')
  return result
}
function rotationMatches(value: unknown, key: string, kind?: CredentialRotationKind, addressID?: string, digest?: string, expectedGeneration?: string, requireCommitted = false): CredentialRotation {
  const result = decodeCredentialRotation(value)
  if (result.operation_key !== key || kind !== undefined && result.kind !== kind || digest !== undefined && result.scope_digest !== digest ||
    addressID !== undefined && result.state === 'committed' && (result.items.length !== 1 || result.items[0].address_id !== addressID) ||
    expectedGeneration !== undefined && result.state === 'committed' && result.items.some((item) => item.previous_generation !== expectedGeneration) || requireCommitted && result.state !== 'committed') throw new ContractError('credential_rotation_scope')
  return result
}
function apiKeyReveal(value: unknown, address: string): APIKeyReveal {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('credential_api_reveal')
  const data = value as Record<string, unknown>, address_id = decodeIdentifier(data.address_id)
  if (address_id !== address || data.api === null || typeof data.api !== 'object' || Array.isArray(data.api)) throw new ContractError('credential_address_scope')
  const api = data.api as Record<string, unknown>, key = api.key
  if (typeof key !== 'string' || key.length === 0 || key.length > 4096 || /[\x00\r\n]/.test(key)) throw new ContractError('credential_secret')
  for (let index = 0; index < key.length; index++) {
    const unit = key.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = key.charCodeAt(++index)
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ContractError('credential_secret')
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new ContractError('credential_secret')
  }
  if (new TextEncoder().encode(key).byteLength > 4096) throw new ContractError('credential_secret')
  const purposes = api.purposes, known = ['latest_read', 'mail_read', 'mail_consume', 'raw_read'] as const
  if (!Array.isArray(purposes) || purposes.length === 0 || purposes.some((purpose) => typeof purpose !== 'string' || !known.includes(purpose as typeof known[number])) || new Set(purposes).size !== purposes.length) throw new ContractError('credential_api_purposes')
  return { address_id, api: { key, purposes: [...purposes] as APIKeyReveal['api']['purposes'] } }
}

export class CredentialsModel {
  private readonly client: ControlClient
  private readonly onSessionRevoked?: (revision?: number) => void
  private readonly sessionRevision?: () => number
  constructor(client: ControlClient, options: CredentialsModelOptions = {}) { this.client = client; this.onSessionRevoked = options.onSessionRevoked; this.sessionRevision = options.sessionRevision }

  scope(signal?: AbortSignal): Promise<ControlResult<CredentialScope>> {
    return this.client.json('/credential-rotation-scope', { signal, decodeResult: decodeCredentialScope })
  }
  addressScope(addressID: string, signal?: AbortSignal): Promise<ControlResult<CredentialScope>> {
    addressID = input(() => decodeIdentifier(addressID))
    return this.client.json('/addresses/' + addressID + '/credential-scope', { signal, decodeResult: (value) => {
      const result = decodeCredentialScope(value)
      if (result.address_count !== '1') throw new ContractError('credential_address_scope')
      return result
    } })
  }
  revealAPIKey(addressID: string, signal?: AbortSignal): Promise<ControlResult<APIKeyReveal>> {
    addressID = input(() => decodeIdentifier(addressID))
    return this.client.json('/addresses/' + addressID + '/api-key/reveal', { method: 'POST', body: {}, signal, resource: { kind: 'address', id: addressID }, decodeResult: (value) => apiKeyReveal(value, addressID) })
  }
  revealBundle(addressID: string, signal?: AbortSignal): Promise<ControlResult<CredentialBundleReveal>> {
    addressID = input(() => decodeIdentifier(addressID))
    return this.client.json('/addresses/' + addressID + '/credential-bundle/reveal', { method: 'POST', body: {}, signal, resource: { kind: 'address', id: addressID }, decodeResult: (value) => {
      const result = decodeCredentialBundleReveal(value)
      if (result.address_id !== addressID) throw new ContractError('credential_address_scope')
      return result
    } })
  }
  pending(sourceID: string, query: PendingDeliveryQuery = {}, signal?: AbortSignal): Promise<ControlResult<CredentialDeliveryPage>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const search = input(() => {
      const values: Record<string, string | number> = {}
      if (query.after_id !== undefined) values.after_id = decodeIdentifier(query.after_id)
      if (query.limit !== undefined) { if (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 1000) throw new ContractError('credential_limit'); values.limit = query.limit }
      return values
    })
    const limit = typeof search.limit === 'number' ? search.limit : 20
    const after = typeof search.after_id === 'string' ? search.after_id : undefined
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries', { search, signal, decodeResult: (value) => {
      const result = decodeCredentialDeliveryPage(value)
      if (result.items.length > limit || result.items.some((item) => item.source_id !== sourceID || after !== undefined && BigInt(item.id) <= BigInt(after))) throw new ContractError('credential_delivery_scope')
      return result
    } })
  }
  delivery(sourceID: string, key: string, signal?: AbortSignal): Promise<ControlResult<CredentialDelivery>> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => credentialKey(key))
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries/' + key, { signal, decodeResult: (value) => deliveryMatches(value, sourceID, key) })
  }
  revealPending(sourceID: string, key: string, signal?: AbortSignal): Promise<ControlResult<PendingCredentialReveal>> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => credentialKey(key))
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries/' + key + '/reveal', { method: 'POST', body: {}, signal, decodeResult: (value) => {
      const result = decodePendingCredentialReveal(value)
      if (result.delivery.source_id !== sourceID || result.delivery.delivery_key !== key) throw new ContractError('credential_delivery_scope')
      return result
    } })
  }
  completePending(sourceID: string, key: string, expectedGeneration: string, signal?: AbortSignal): Promise<ControlResult<CredentialDelivery>> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => credentialKey(key)); expectedGeneration = input(() => decodeIdentifier(expectedGeneration))
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries/' + key + '/complete-mailbox', { method: 'POST', body: { expected_generation: expectedGeneration }, signal, decodeResult: (value) => {
      const result = deliveryMatches(value, sourceID, key)
      if (result.generation !== expectedGeneration) throw new ContractError('credential_generation')
      return result
    } })
  }
  revealPendingBundle(sourceID: string, key: string, expectedGeneration: string, signal?: AbortSignal): Promise<ControlResult<PendingCredentialBundleReveal>> {
    sourceID = input(() => decodeIdentifier(sourceID)); key = input(() => credentialKey(key)); expectedGeneration = input(() => decodeIdentifier(expectedGeneration))
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries/' + key + '/reveal-bundle', { method: 'POST', body: {}, signal, decodeResult: value => {
      const result = decodePendingCredentialBundleReveal(value)
      if (result.delivery.source_id !== sourceID || result.delivery.delivery_key !== key || result.delivery.generation !== expectedGeneration) throw new ContractError('credential_delivery_scope')
      return result
    } })
  }
  acknowledge(sourceID: string, keys: string[], signal?: AbortSignal): Promise<ControlResult<null>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => {
      if (!Array.isArray(keys) || keys.length < 1 || keys.length > 1000) throw new ContractError('credential_selection')
      const delivery_keys = keys.map(credentialKey)
      if (new Set(delivery_keys).size !== delivery_keys.length) throw new ContractError('credential_selection')
      return { delivery_keys }
    })
    return this.client.json('/accounts/' + sourceID + '/credential-deliveries', { method: 'DELETE', body, signal, decodeResult: decodeNull })
  }
  rotateKey(addressID: string, value: RotateAPIKey, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    return this.rotateOne(addressID, 'api_key', value, signal)
  }
  rotateBundle(addressID: string, value: RotateCredentialBundle, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    return this.rotateOne(addressID, 'bundle', value, signal)
  }
  private rotateOne(addressID: string, kind: 'api_key' | 'bundle', value: RotateCredentialBundle, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    addressID = input(() => decodeIdentifier(addressID))
    const body = input(() => {
      const request = { kind, operation_key: credentialKey(value.operation_key), expected_generation: decodeIdentifier(value.expected_generation), expected_scope_digest: value.expected_scope_digest === undefined ? undefined : credentialDigest(value.expected_scope_digest) }
      if (kind === 'api_key' && request.expected_scope_digest === undefined) throw new ContractError('credential_digest')
      return request
    })
    return this.client.json('/addresses/' + addressID + '/credential-rotations', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'address', id: addressID }, decodeResult: (value) => rotationMatches(value, body.operation_key, kind, addressID, body.expected_scope_digest, body.expected_generation, true) })
  }
  async rotateAll(value: RotateAllCredentials, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    const revision = this.sessionRevision?.()
    const body = input(() => {
      if (value.confirmation !== FULL_ROTATION_CONFIRMATION || typeof value.current_password !== 'string' || value.current_password.length === 0 || new TextEncoder().encode(value.current_password).byteLength > 1024) throw new ContractError('credential_confirmation')
      return { operation_key: credentialKey(value.operation_key), expected_scope_digest: credentialDigest(value.expected_scope_digest), confirmation: FULL_ROTATION_CONFIRMATION, current_password: value.current_password }
    })
    try {
      const response = await this.client.json('/credential-rotations', { method: 'POST', body, signal, requestKey: body.operation_key, decodeResult: (result) => rotationMatches(result, body.operation_key, 'all', undefined, body.expected_scope_digest, undefined, true) })
      this.sessionRevoked(revision)
      return response
    } catch (error) {
      if (error instanceof ControlError && error.outcome === 'unknown') this.sessionRevoked(revision)
      throw error
    } finally { body.current_password = '' }
  }
  queryRotation(key: string, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    key = input(() => credentialKey(key))
    return this.client.json('/credential-rotations/' + key, { signal, decodeResult: (value) => rotationMatches(value, key) })
  }
  cancelRotation(key: string, signal?: AbortSignal): Promise<ControlResult<CredentialRotation>> {
    key = input(() => credentialKey(key))
    return this.client.json('/credential-rotations/' + key + '/cancel', { method: 'POST', body: {}, requestKey: key, signal, decodeResult: (value) => {
      const result = rotationMatches(value, key)
      if (result.state === 'prepared') throw new ContractError('credential_cancellation')
      return result
    } })
  }
  async queryUnknownRotation(error: unknown, key: string, signal?: AbortSignal): Promise<ControlResult<CredentialRotation> | undefined> {
    key = input(() => credentialKey(key))
    if (!(error instanceof ControlError) || error.outcome !== 'unknown' || error.requestKey !== key && error.submissionKey !== key ||
      error.requestKey !== undefined && error.requestKey !== key || error.submissionKey !== undefined && error.submissionKey !== key) return undefined
    return this.queryRotation(key, signal)
  }
  private sessionRevoked(revision?: number): void { try { this.onSessionRevoked?.(revision) } catch { /* Caller UI errors cannot replace a durable protocol result. */ } }
}
