import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'

export interface AddressMetadata {
  id: string
  source_id: string
  source_label: string
  source_kind?: 'apple_direct' | 'apple_forwarded' | 'custom'
  address: string
  kind: 'apple' | 'manual' | 'random'
  label: string
  group_id: string | null
  lifecycle: 'pending' | 'confirmed' | 'deletion_pending' | 'archived'
  enabled: boolean
  credential_profile: 'mailbox' | 'api_key_only' | 'legacy_latest' | 'unavailable'
  registration_banned: boolean
  registration_banned_at: string | null
  latest_received_at: string | null
  revision: string
  auth_generation: string
  uid_validity: string
  uid_next: string
  has_mail: boolean
  capabilities: string[]
  archive_notice: { reason: 'remote_missing' | 'historical'; archived_at: string } | null
  last_sync_state: string
  last_sync_error: string
  last_synced_at: string | null
  last_accessed_at: string | null
  created_at: string
  updated_at: string
}

export interface AddressFilter {
  source_id?: string
  group_id?: string
  ungrouped?: boolean
  query?: string
  enabled?: boolean
  has_mail?: boolean
  archive?: 'all' | 'archived' | 'unarchived'
}
export interface AddressListQuery extends AddressFilter { page?: number; page_size?: number }
export interface AddressPage { items: AddressMetadata[]; total: number; page: number; page_size: number }
export interface HistoricalRemoval { id: string; source_id: string; source_label: string; address: string; kind: 'manual' | 'random'; revision: string; deleted_at: string }
export interface HistoricalRemovalPage { items: HistoricalRemoval[]; total: number; page: number; page_size: number }
export interface AddressGroup { id: string; name: string; revision: string; address_count: string }
export interface AddressCreate {
  source_id: string
  address: string
  label: string
  group_id: string | null
  enabled: boolean
  credential_profile: 'api_key_only' | 'mailbox'
}
export interface AddressRandomCreate {
  source_id: string
  count: number
  label: string
  group_id: string | null
  credential_profile: 'api_key_only' | 'mailbox'
}
export interface AddressPatch {
  expected_revision: string
  label?: string
  enabled?: boolean
  group_id?: string | null
}
export interface AddressDelete { expected_revision: string; confirm_address: string }
export interface AddressSelection { id: string; expected_revision: string }
export interface AddressOperation {
  operation_key: string
  source_id: string
  address_id: string | null
  kind: 'create' | 'delete' | 'purge'
  state: string
  error_code: string
  query_only: boolean
  created_at: string
  updated_at: string
}
export interface AddressPurge extends AddressDelete { operation_key: string }

export function addressObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('address')
  return value as Record<string, unknown>
}
export function addressText(value: unknown): string {
  if (typeof value !== 'string') throw new ContractError('address_text')
  return value
}
export function addressBoolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('address_boolean')
  return value
}
export function addressNullableID(value: unknown): string | null {
  return value === null ? null : decodeIdentifier(value)
}
function nullableInstant(value: unknown): string | null { return value === null ? null : decodeInstant(value) }
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ContractError('address_choice')
  return value as T
}
function positiveCount(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) throw new ContractError('address_count')
  return value as number
}
function countString(value: unknown): string {
  if (value === '0') return value
  return decodeIdentifier(value)
}

export function decodeAddress(value: unknown): AddressMetadata {
  const data = addressObject(value)
  const lifecycle = choice(data.lifecycle, ['pending', 'confirmed', 'deletion_pending', 'archived'] as const)
  const enabled = addressBoolean(data.enabled)
  const credential_profile = choice(data.credential_profile, ['mailbox', 'api_key_only', 'legacy_latest', 'unavailable'] as const)
  const registration_banned = addressBoolean(data.registration_banned), registration_banned_at = nullableInstant(data.registration_banned_at)
  if (registration_banned !== (registration_banned_at !== null)) throw new ContractError('address_registration_ban')
  if (enabled && lifecycle !== 'confirmed') throw new ContractError('address_eligibility')
  const capabilities = data.capabilities
  const purposes = ['latest_read', 'mail_read', 'mail_consume', 'raw_read', 'imap_login', 'oauth_client', 'oauth_refresh']
  if (!Array.isArray(capabilities) || capabilities.some((v) => typeof v !== 'string' || !purposes.includes(v)) || new Set(capabilities).size !== capabilities.length) throw new ContractError('address_capabilities')
  if (!enabled && capabilities.length !== 0) throw new ContractError('address_capabilities')
  let archive_notice: AddressMetadata['archive_notice'] = null
  if (data.archive_notice !== null) {
    const notice = addressObject(data.archive_notice)
    archive_notice = { reason: choice(notice.reason, ['remote_missing', 'historical'] as const), archived_at: decodeInstant(notice.archived_at) }
  }
  if ((lifecycle === 'archived') !== (archive_notice !== null)) throw new ContractError('address_archive')
  const uid_validity = decodeIdentifier(data.uid_validity)
  const uid_next = decodeIdentifier(data.uid_next)
  if (BigInt(uid_validity) > 4294967295n || BigInt(uid_next) > 4294967296n) throw new ContractError('address_uid')
  return {
    id: decodeIdentifier(data.id), source_id: decodeIdentifier(data.source_id),
    source_label: data.source_label === undefined ? '' : addressText(data.source_label),
    source_kind: data.source_kind === undefined ? undefined : choice(data.source_kind, ['apple_direct','apple_forwarded','custom'] as const),
    address: addressText(data.address), kind: choice(data.kind, ['apple', 'manual', 'random'] as const),
    label: addressText(data.label), group_id: addressNullableID(data.group_id), lifecycle, enabled, credential_profile,
    registration_banned, registration_banned_at, latest_received_at: nullableInstant(data.latest_received_at),
    revision: decodeIdentifier(data.revision), auth_generation: decodeIdentifier(data.auth_generation), uid_validity, uid_next,
    has_mail: addressBoolean(data.has_mail), capabilities: [...capabilities], archive_notice,
    last_sync_state: addressText(data.last_sync_state), last_sync_error: addressText(data.last_sync_error),
    last_synced_at: nullableInstant(data.last_synced_at), last_accessed_at: nullableInstant(data.last_accessed_at),
    created_at: decodeInstant(data.created_at), updated_at: decodeInstant(data.updated_at),
  }
}

export function decodeAddressPage(value: unknown): AddressPage {
  const data = addressObject(value)
  if (!Array.isArray(data.items) || !Number.isSafeInteger(data.total) || (data.total as number) < 0) throw new ContractError('address_page')
  const page = positiveCount(data.page, 2147483647)
  const page_size = positiveCount(data.page_size, 1000)
  if (data.items.length > page_size || data.items.length > (data.total as number)) throw new ContractError('address_page')
  const items = data.items.map(decodeAddress)
  if (new Set(items.map((item) => item.id)).size !== items.length) throw new ContractError('address_page')
  return { items, total: data.total as number, page, page_size }
}

export function decodeHistoricalRemovalPage(value: unknown): HistoricalRemovalPage {
  const data = addressObject(value)
  const page = positiveCount(data.page, 2147483647), page_size = positiveCount(data.page_size, 1000)
  if (!Number.isSafeInteger(data.total) || (data.total as number) < 0 || !Array.isArray(data.items) || data.items.length > page_size) throw new ContractError('historical_removals')
  const ids = new Set<string>()
  const items = data.items.map((value): HistoricalRemoval => {
    const item = addressObject(value), id = decodeIdentifier(item.id)
    if (ids.has(id)) throw new ContractError('historical_removals'); ids.add(id)
    return { id, source_id: decodeIdentifier(item.source_id), source_label: addressText(item.source_label), address: addressText(item.address), kind: choice(item.kind,['manual','random'] as const), revision: decodeIdentifier(item.revision), deleted_at: decodeInstant(item.deleted_at) }
  })
  return { items, total: data.total as number, page, page_size }
}

export function decodeAddressGroup(value: unknown): AddressGroup {
  const data = addressObject(value)
  return { id: decodeIdentifier(data.id), name: addressText(data.name), revision: decodeIdentifier(data.revision), address_count: countString(data.address_count) }
}
export function decodeAddressOperation(value: unknown): AddressOperation {
  const data = addressObject(value)
  return {
    operation_key: addressText(data.operation_key), source_id: decodeIdentifier(data.source_id), address_id: addressNullableID(data.address_id),
    kind: choice(data.kind, ['create', 'delete', 'purge'] as const), state: addressText(data.state), error_code: addressText(data.error_code),
    query_only: addressBoolean(data.query_only), created_at: decodeInstant(data.created_at), updated_at: decodeInstant(data.updated_at),
  }
}

export function addressFilter(value: AddressFilter): Record<string, string | number | boolean> {
  const data = addressObject(value)
  const filter: Record<string, string | number | boolean> = {}
  if (data.source_id !== undefined) filter.source_id = decodeIdentifier(data.source_id)
  if (data.group_id !== undefined) filter.group_id = decodeIdentifier(data.group_id)
  if (data.ungrouped !== undefined) filter.ungrouped = addressBoolean(data.ungrouped)
  if (filter.group_id && filter.ungrouped) throw new ContractError('address_group_filter')
  if (data.query !== undefined) filter.query = addressText(data.query)
  if (data.enabled !== undefined) filter.enabled = addressBoolean(data.enabled)
  if (data.has_mail !== undefined) filter.has_mail = addressBoolean(data.has_mail)
  if (data.archive !== undefined) filter.archive = choice(data.archive, ['all', 'archived', 'unarchived'] as const)
  return filter
}
export function addressProfile(value: unknown): AddressCreate['credential_profile'] { return choice(value, ['api_key_only', 'mailbox'] as const) }
export function addressPageQuery(query: AddressListQuery): Record<string, string | number | boolean> {
  const filter = addressFilter(query)
  if (query.page !== undefined) filter.page = positiveCount(query.page, 2147483647)
  if (query.page_size !== undefined) filter.page_size = positiveCount(query.page_size, 1000)
  return filter
}
