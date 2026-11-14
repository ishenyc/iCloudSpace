/** Wire identifiers and instants stay strings; no nanosecond or int64 round trip through Number. */
export type DecimalIdentifier = string
export type Instant = string
export type AccountKind = 'custom' | 'apple_direct' | 'apple_forwarded'

export interface Operator {
  id: DecimalIdentifier
  username: string
}

export type Session = { authenticated: false } | {
  authenticated: true
  operator: Operator
  csrf_token: string
  expires_at: Instant
}

export interface PasswordChange {
  current_password: string
  new_password: string
  confirmation: string
}

export interface AccountEndpoint {
  host: string
  port: number
  username: string
}

export interface AppleIdentityInput {
  apple_id: string
  region: string
}

export interface AppleIdentity extends AppleIdentityInput {
  dsid?: string
  revision: DecimalIdentifier
}

export interface Account {
  id: DecimalIdentifier
  kind: AccountKind
  display_name: string
  address_namespace: string
  endpoint: AccountEndpoint
  address_suffix: string
  enabled: boolean
  address_count: DecimalIdentifier
  revision: DecimalIdentifier
  source_generation: DecimalIdentifier
  credential_generation: DecimalIdentifier
  automatic_sync_after?: Instant
  last_terminal_sync_at?: Instant
  last_sync_state: string
  last_sync_error: string
  last_synced_at: Instant | null
  created_at: Instant
  updated_at: Instant
  apple?: AppleIdentity
}

export interface AccountFilter {
  query?: string
  kind?: AccountKind
  enabled?: boolean
}

export interface AccountListQuery extends AccountFilter {
  page?: number
  page_size?: number
}

export interface AccountPage {
  items: Account[]
  total: number
  page: number
  page_size: number
}

export interface AccountCredentials {
  version: 1
  imap_password: string
}

export interface AccountCreate {
  kind: AccountKind
  display_name: string
  address_namespace: string
  endpoint: AccountEndpoint
  address_suffix: string
  enabled: boolean
  credentials: AccountCredentials
  apple?: AppleIdentityInput
}

export interface AccountPatch {
  expected_revision: DecimalIdentifier
  require_source_change?: boolean
  kind?: AccountKind
  display_name?: string
  address_namespace?: string
  endpoint?: AccountEndpoint
  address_suffix?: string
  enabled?: boolean
  credentials?: AccountCredentials
  apple?: AppleIdentityInput
}

export interface AccountChange {
  source: Account
  source_changed: boolean
  credentials_changed: boolean
  previous_source_generation: DecimalIdentifier
}

export interface AccountReveal {
  source: Account
  credentials: AccountCredentials
}

export interface AccountDelete {
  expected_revision: DecimalIdentifier
  operation_key: string
}

export interface AccountDeleted {
  operation_key: string
  source_id: DecimalIdentifier
  deleted: boolean
}

export interface AccountExport {
  format: 'csv' | 'jsonl'
  filter: AccountFilter
}

/** A decoder failure records a constant field label, never any supplied field value. */
export class ContractError extends Error {
  readonly field: string
  constructor(field: string) {
    super('The response does not match the management contract.')
    this.name = 'ContractError'
    this.field = field
  }
}

export function decodeIdentifier(value: unknown, field = 'id', allowZero = false): DecimalIdentifier {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value) ||
    (!allowZero && value === '0') || (value.length === 19 && value > '9223372036854775807')) throw new ContractError(field)
  return value
}

export function decodeInstant(value: unknown, field = 'instant'): Instant {
  if (typeof value !== 'string') throw new ContractError(field)
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!match) throw new ContractError(field)
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number)
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59 ||
    (match[8] !== 'Z' && (Number(match[8].slice(1, 3)) > 23 || Number(match[8].slice(4, 6)) > 59))) throw new ContractError(field)
  return value
}

export function decodeSession(value: unknown): Session {
  const session = object(value, 'session')
  if (session.authenticated === false) {
    if (session.operator !== undefined || session.csrf_token !== undefined || session.expires_at !== undefined) throw new ContractError('session')
    return { authenticated: false }
  }
  if (session.authenticated !== true) throw new ContractError('authenticated')
  const operator = object(session.operator, 'operator')
  const token = text(session.csrf_token, 'csrf_token')
  if (!token || token.length > 4096 || /[\u0000-\u0020\u007f]/.test(token)) throw new ContractError('csrf_token')
  return {
    authenticated: true,
    operator: { id: decodeIdentifier(operator.id, 'operator.id'), username: text(operator.username, 'operator.username') },
    csrf_token: token,
    expires_at: decodeInstant(session.expires_at, 'expires_at'),
  }
}

export function decodeAuthenticatedSession(value: unknown): Extract<Session, { authenticated: true }> {
  const session = decodeSession(value)
  if (!session.authenticated) throw new ContractError('authenticated')
  return session
}

export function decodeAccount(value: unknown): Account {
  const account = object(value, 'account')
  // A metadata result must not silently become a sensitive-read result.
  if (account.credentials !== undefined || account.imap_password !== undefined) throw new ContractError('account')
  const result: Account = {
    id: decodeIdentifier(account.id), kind: decodeAccountKind(account.kind),
    display_name: text(account.display_name, 'display_name'), address_namespace: text(account.address_namespace, 'address_namespace'),
    endpoint: decodeEndpoint(account.endpoint), address_suffix: text(account.address_suffix, 'address_suffix'),
    enabled: boolean(account.enabled, 'enabled'), revision: decodeIdentifier(account.revision, 'revision'),
    address_count: decodeIdentifier(account.address_count, 'address_count', true),
    source_generation: decodeIdentifier(account.source_generation, 'source_generation'),
    credential_generation: decodeIdentifier(account.credential_generation, 'credential_generation'),
    last_sync_state: accountSyncState(account.last_sync_state), last_sync_error: accountSyncError(account.last_sync_error),
    last_synced_at: account.last_synced_at === null ? null : decodeInstant(account.last_synced_at,'last_synced_at'),
    created_at: decodeInstant(account.created_at, 'created_at'), updated_at: decodeInstant(account.updated_at, 'updated_at'),
  }
  if (account.automatic_sync_after !== undefined) result.automatic_sync_after = decodeInstant(account.automatic_sync_after, 'automatic_sync_after')
  if (account.last_terminal_sync_at !== undefined) result.last_terminal_sync_at = decodeInstant(account.last_terminal_sync_at, 'last_terminal_sync_at')
  if (account.apple !== undefined) {
    const apple = object(account.apple, 'apple')
    result.apple = { apple_id: text(apple.apple_id, 'apple.apple_id'), region: text(apple.region, 'apple.region'), revision: decodeIdentifier(apple.revision, 'apple.revision') }
    if (apple.dsid !== undefined) result.apple.dsid = text(apple.dsid, 'apple.dsid')
  }
  if ((result.kind === 'custom') === (result.apple !== undefined)) throw new ContractError('apple')
  return result
}

const accountSyncStates=new Set(['','ok','error','succeeded','degraded','failed','cancelled','superseded','unknown','mail_succeeded','mail_degraded','mail_failed','mail_cancelled','mail_superseded','mail_unknown'])
const accountSyncExactCodes=new Set(['','historical_sync_failure','login_required','session_binding','read_only','source_changed','invalid_step','invalid_admission','directory_not_applicable','directory_checkpoint_failed','mail_snapshot_changed','mail_frontier_changed','mail_frontier_unknown','backfill_changed','invalid_backfill_continuation','intake_recovery_required','backfill_prepare_unknown','invalid_counters','invalid_frontier','step_failed','step_timeout','executor_panic','round_budget_exhausted','terminal_persistence_unknown','terminal_clock_not_advanced','terminal_timestamp_range','source_gate_failed','slot_wait_timeout'])
const accountSyncPhases=['directory','source_metadata','source_credentials','intake_receipt','intake_snapshot','mail','mail_frontier','backfill_prepare','backfill_catalog','backfill_snapshot','imap']
const accountSyncKinds=new Set(['invalid','canceled','cancelled','dns','connect','tls','timeout','transport','redirect','response_budget','malformed_response','authentication_required','auth_required','rate_limited','apple_rejected','second_factor_required','auth','command','protocol','timestamp_range','uid_exhausted','source_bytes_changed','session_unknown','unavailable','failed'])
function accountSyncState(value:unknown):string {
  if(typeof value!=='string'||!accountSyncStates.has(value))throw new ContractError('last_sync_state')
  return value
}
function accountSyncError(value:unknown):string {
  if(typeof value!=='string'||!accountSyncExactCodes.has(value)&&!accountSyncPhases.some(phase=>value.startsWith(phase+'_')&&accountSyncKinds.has(value.slice(phase.length+1))))throw new ContractError('last_sync_error')
  return value
}

export function decodeAccountPage(value: unknown): AccountPage {
  const page = object(value, 'page')
  if (!Array.isArray(page.items)) throw new ContractError('items')
  const result = {
    items: page.items.map(decodeAccount), total: integer(page.total, 0, Number.MAX_SAFE_INTEGER, 'total'),
    page: integer(page.page, 1, Number.MAX_SAFE_INTEGER, 'page'), page_size: integer(page.page_size, 1, 1000, 'page_size'),
  }
  if (result.items.length > result.page_size || result.items.length > result.total) throw new ContractError('items')
  return result
}

export function decodeAccountChange(value: unknown): AccountChange {
  const change = object(value, 'change')
  return {
    source: decodeAccount(change.source), source_changed: boolean(change.source_changed, 'source_changed'),
    credentials_changed: boolean(change.credentials_changed, 'credentials_changed'),
    previous_source_generation: decodeIdentifier(change.previous_source_generation, 'previous_source_generation', true),
  }
}

export function decodeAccountReveal(value: unknown): AccountReveal {
  const reveal = object(value, 'reveal')
  return { source: decodeAccount(reveal.source), credentials: decodeCredentials(reveal.credentials) }
}

export function decodeAccountDeleted(value: unknown): AccountDeleted {
  const deleted = object(value, 'deletion')
  const key = text(deleted.operation_key, 'operation_key')
  if (!/^[A-Za-z0-9][A-Za-z0-9._~-]{0,511}$/.test(key)) throw new ContractError('operation_key')
  return { operation_key: key, source_id: decodeIdentifier(deleted.source_id, 'source_id'), deleted: boolean(deleted.deleted, 'deleted') }
}

export function decodeNull(value: unknown): null {
  if (value !== null) throw new ContractError('result')
  return null
}

export function decodeAccountKind(value: unknown): AccountKind {
  if (value !== 'custom' && value !== 'apple_direct' && value !== 'apple_forwarded') throw new ContractError('kind')
  return value
}

export function decodeEndpoint(value: unknown): AccountEndpoint {
  const endpoint = object(value, 'endpoint')
  return { host: text(endpoint.host, 'endpoint.host'), port: integer(endpoint.port, 1, 65535, 'endpoint.port'), username: text(endpoint.username, 'endpoint.username') }
}

export function decodeCredentials(value: unknown): AccountCredentials {
  const credentials = object(value, 'credentials')
  const password = text(credentials.imap_password, 'credentials.imap_password')
  if (credentials.version !== 1 || !password) throw new ContractError('credentials')
  return { version: 1, imap_password: password }
}

function object(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ContractError(field)
  return value as Record<string, unknown>
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new ContractError(field)
  return value
}

function boolean(value: unknown, field: string): boolean {
  if (typeof value !== 'boolean') throw new ContractError(field)
  return value
}

function integer(value: unknown, min: number, max: number, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) throw new ContractError(field)
  return value
}
