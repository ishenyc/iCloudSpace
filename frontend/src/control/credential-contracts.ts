import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'
import { credentialCopyURL } from './credential-copy.ts'
import type { CredentialCopyLinks } from './credential-copy.ts'

export const FULL_ROTATION_CONFIRMATION = 'rotate-all-address-credentials' as const
export interface CredentialBundle {
  version: 1
  api: { key: string }
  imap: { password: string }
  oauth: { client_id: string; refresh_token: string }
}
export interface CredentialBundleReveal { address_id: string; bundle: CredentialBundle }
export interface CredentialScope { digest: string; address_count: string; eligible_count: string }
export interface CredentialDelivery {
  id: string; source_id: string; address_id: string; generation: string; delivery_key: string
  created_at: string; acknowledged_at: string | null
  address: string; label: string; source_label: string; lifecycle: 'pending' | 'confirmed' | 'deletion_pending' | 'archived'
  deleted: boolean; enabled: boolean; current: boolean; bundle_available: boolean
}
export interface CredentialDeliveryPage { items: CredentialDelivery[]; next_after_id: string | null }
export interface PendingCredentialReveal {
  delivery: CredentialDelivery
  revoked: boolean
  secret: { version: 1; api_key: string }
  links: CredentialCopyLinks | null
}
export interface PendingCredentialBundleReveal { delivery: CredentialDelivery; bundle: CredentialBundle; links: CredentialCopyLinks | null }
export type CredentialRotationKind = 'api_key' | 'bundle' | 'all'
export type CredentialRotationState = 'prepared' | 'committed' | 'cancelled'
export interface CredentialRotationItem {
  source_id: string; address_id: string; previous_generation: string; generation: string; delivery_key: string
  previous_uid_validity: string; uid_validity: string; upgraded: boolean
}
export interface CredentialRotation {
  operation_key: string; kind: CredentialRotationKind; state: CredentialRotationState
  scope_digest: string; items: CredentialRotationItem[]
}
export interface PendingDeliveryQuery { after_id?: string; limit?: number }
export interface RotateAPIKey { operation_key: string; expected_generation: string; expected_scope_digest: string }
export interface RotateCredentialBundle { operation_key: string; expected_generation: string; expected_scope_digest?: string }
export interface RotateAllCredentials {
  operation_key: string; expected_scope_digest: string
  confirmation: typeof FULL_ROTATION_CONFIRMATION
  current_password: string
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('credential_object')
  return value as Record<string, unknown>
}
function choice<T extends string>(value: unknown, choices: readonly T[]): T {
  if (typeof value !== 'string' || !choices.includes(value as T)) throw new ContractError('credential_choice')
  return value as T
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('credential_boolean')
  return value
}
export function credentialKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._~-]{0,255}$/.test(value)) throw new ContractError('credential_key')
  return value
}
export function credentialDigest(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new ContractError('credential_digest')
  return value
}
function secret(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || /[\x00\r\n]/.test(value)) throw new ContractError('credential_secret')
  // Reject unpaired UTF-16 rather than letting JSON/UTF-8 silently substitute
  // a different imported secret. Whitespace and exact case remain untouched.
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i)
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ContractError('credential_secret')
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new ContractError('credential_secret')
  }
  if (new TextEncoder().encode(value).byteLength > 4096) throw new ContractError('credential_secret')
  return value
}
function uidValidity(value: unknown): string {
  const id = decodeIdentifier(value)
  if (BigInt(id) > 4294967295n) throw new ContractError('credential_uid')
  return id
}

export function decodeCredentialBundle(value: unknown): CredentialBundle {
  const data = object(value), api = object(data.api), imap = object(data.imap), oauth = object(data.oauth)
  if (data.version !== 1) throw new ContractError('credential_version')
  return { version: 1, api: { key: secret(api.key) }, imap: { password: secret(imap.password) },
    oauth: { client_id: secret(oauth.client_id), refresh_token: secret(oauth.refresh_token) } }
}
export function decodeCredentialBundleReveal(value: unknown): CredentialBundleReveal {
  const data = object(value)
  return { address_id: decodeIdentifier(data.address_id), bundle: decodeCredentialBundle(data.bundle) }
}
export function decodeCredentialScope(value: unknown): CredentialScope {
  const data = object(value)
  const address_count = decodeIdentifier(data.address_count, 'credential_count', true)
  const eligible_count = decodeIdentifier(data.eligible_count, 'credential_count', true)
  if (BigInt(eligible_count) > BigInt(address_count)) throw new ContractError('credential_count')
  return { digest: credentialDigest(data.digest), address_count, eligible_count }
}
export function decodeCredentialDelivery(value: unknown): CredentialDelivery {
  const data = object(value)
  const text = (value: unknown) => { if (typeof value !== 'string' || !value || /[\x00\r\n]/.test(value)) throw new ContractError('credential_label'); return value }
  if (typeof data.label !== 'string') throw new ContractError('credential_label')
  return { id: decodeIdentifier(data.id), source_id: decodeIdentifier(data.source_id), address_id: decodeIdentifier(data.address_id),
    generation: decodeIdentifier(data.generation), delivery_key: credentialKey(data.delivery_key), created_at: decodeInstant(data.created_at),
    acknowledged_at: data.acknowledged_at === null ? null : decodeInstant(data.acknowledged_at),
    address: text(data.address), label: data.label, source_label: text(data.source_label), lifecycle: choice(data.lifecycle, ['pending','confirmed','deletion_pending','archived'] as const),
    deleted: boolean(data.deleted), enabled: boolean(data.enabled), current: boolean(data.current), bundle_available: boolean(data.bundle_available) }
}
export function decodeCredentialDeliveryPage(value: unknown): CredentialDeliveryPage {
  const data = object(value)
  if (!Array.isArray(data.items) || data.items.length > 1000) throw new ContractError('credential_deliveries')
  const items = data.items.map(decodeCredentialDelivery)
  const next_after_id = data.next_after_id === null ? null : decodeIdentifier(data.next_after_id)
  let previous = 0n
  const keys = new Set<string>()
  for (const item of items) {
    if (BigInt(item.id) <= previous || keys.has(item.delivery_key) || item.acknowledged_at !== null) throw new ContractError('credential_deliveries')
    previous = BigInt(item.id); keys.add(item.delivery_key)
  }
  if (next_after_id !== null && (items.length === 0 || next_after_id !== items.at(-1)!.id)) throw new ContractError('credential_cursor')
  return { items, next_after_id }
}
export function decodePendingCredentialReveal(value: unknown): PendingCredentialReveal {
  const data = object(value), pending = object(data.secret)
  if (pending.version !== 1) throw new ContractError('credential_version')
  return { delivery: decodeCredentialDelivery(data.delivery), revoked: boolean(data.revoked), secret: { version: 1, api_key: secret(pending.api_key) }, links: decodeCopyLinks(data.links) }
}
function decodeCopyLinks(value: unknown): CredentialCopyLinks | null {
  if (value === null) return null
  const data = object(value)
  const path = (value: unknown) => {
    if (typeof value !== 'string') throw new ContractError('credential_copy_link')
    try { credentialCopyURL(value, 'https://credential-copy.invalid'); return value } catch { throw new ContractError('credential_copy_link') }
  }
  return { otp: path(data.otp), recent: path(data.recent), raw: path(data.raw) }
}
export function decodePendingCredentialBundleReveal(value: unknown): PendingCredentialBundleReveal {
  const data = object(value), delivery = decodeCredentialDelivery(data.delivery)
  if (!delivery.current || delivery.deleted || !delivery.bundle_available) throw new ContractError('credential_delivery_bundle')
  return { delivery, bundle: decodeCredentialBundle(data.bundle), links: decodeCopyLinks(data.links) }
}
export function decodeCredentialRotation(value: unknown): CredentialRotation {
  const data = object(value)
  const operation_key = credentialKey(data.operation_key)
  const kind = choice(data.kind, ['api_key', 'bundle', 'all'] as const)
  const state = choice(data.state, ['prepared', 'committed', 'cancelled'] as const)
  if (!Array.isArray(data.items) || state !== 'committed' && data.items.length !== 0 || state === 'committed' && kind !== 'all' && data.items.length !== 1) throw new ContractError('credential_rotation')
  const seen = new Set<string>()
  const items = data.items.map((value): CredentialRotationItem => {
    const item = object(value)
    const address_id = decodeIdentifier(item.address_id), previous_generation = decodeIdentifier(item.previous_generation), generation = decodeIdentifier(item.generation)
    const previous_uid_validity = uidValidity(item.previous_uid_validity), uid_validity = uidValidity(item.uid_validity), upgraded = boolean(item.upgraded)
    if (seen.has(address_id) || (kind === 'api_key' ? generation !== previous_generation : BigInt(generation) !== BigInt(previous_generation) + 1n) ||
      upgraded && kind !== 'all' || (upgraded ? uid_validity === previous_uid_validity : uid_validity !== previous_uid_validity)) throw new ContractError('credential_rotation')
    seen.add(address_id)
    return { source_id: decodeIdentifier(item.source_id), address_id, previous_generation, generation, delivery_key: credentialKey(item.delivery_key), previous_uid_validity, uid_validity, upgraded }
  })
  return { operation_key, kind, state, scope_digest: credentialDigest(data.scope_digest), items }
}
