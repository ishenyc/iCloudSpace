import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'

export type RuntimeStream = 'live' | 'history'
export type EventLevel = 'debug' | 'info' | 'warn' | 'error'
export type AuditOutcome = 'success' | 'rejected' | 'unknown' | 'failure'
export interface RuntimeEvent {
  id: string
  occurred_at: string
  level: EventLevel
  source_id: string | null
  round_key: string
  attempt: number
  phase: string
  outcome: string
  error_code: string
  message: string
  fields: Record<string, string>
}
export interface RuntimeEventsQuery {
  stream?: RuntimeStream
  before_id?: string
  after_id?: string
  limit?: number
  level?: EventLevel
  query?: string
  source_id?: string
  round_key?: string
}
export interface RuntimeEventsPage {
  stream: RuntimeStream
  generation: string | null
  items: RuntimeEvent[]
  limit: number
  before_id: string | null
  after_id: string | null
  next_before_id: string | null
  earliest_id: string | null
  latest_id: string | null
  evicted: boolean
  total: number
}
export interface AuditRecord {
  id: string
  occurred_at: string
  actor_kind: 'operator' | 'address' | 'system' | 'historical'
  actor_ref: string
  actor_display: string
  action: string
  resource_kind: string
  resource_ref: string
  outcome: AuditOutcome
  source_id: string | null
  correlation_key: string
  origin: string
  detail: string
  fields: Record<string, string>
}
export interface AuditRecordsQuery {
  page?: number
  page_size?: number
  query?: string
  source_id?: string
  action?: string
  outcome?: AuditOutcome
}
export interface AuditRecordsPage { items: AuditRecord[]; total: number; page: number; page_size: number }
export type RuntimeEventsSearch = RuntimeEventsQuery & { stream: RuntimeStream; limit: number }
export type AuditRecordsSearch = AuditRecordsQuery & { page: number; page_size: number }

export function eventObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('event_object')
  return value as Record<string, unknown>
}
export function eventText(value: unknown, maximum?: number): string {
  if (typeof value !== 'string' || maximum !== undefined && new TextEncoder().encode(value).byteLength > maximum) throw new ContractError('event_text')
  return value
}
export function eventInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new ContractError('event_integer')
  return value as number
}
export function eventChoice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ContractError('event_choice')
  return value as T
}
function metadata(value: unknown, maximum: number): string {
  const decoded = eventText(value, maximum)
  if (!/^[A-Za-z0-9_.:-]+$/.test(decoded)) throw new ContractError('event_metadata')
  const lower = decoded.toLowerCase()
  if (['password', 'secret', 'authorization', 'bearer', 'cookie', 'csrf', 'access_token', 'refresh_token', 'session_token', 'private_key'].some((word) => lower.includes(word))) throw new ContractError('event_metadata')
  return decoded
}
function nullableID(value: unknown): string | null { return value === null ? null : decodeIdentifier(value) }
function fields(value: unknown): Record<string, string> {
  const entries = Object.entries(eventObject(value))
  if (entries.length > 16) throw new ContractError('event_fields')
  return Object.fromEntries(entries.map(([key, value]) => [eventText(key, 64), eventText(value, 256)]))
}
function descending(items: { id: string }[]): void {
  for (let index = 1; index < items.length; index++) if (BigInt(items[index - 1].id) <= BigInt(items[index].id)) throw new ContractError('event_order')
}
export function runtimeEventsSearch(value: unknown): RuntimeEventsSearch {
  const data = eventObject(value)
  const search: RuntimeEventsSearch = {
    stream: data.stream === undefined ? 'live' : eventChoice(data.stream, ['live', 'history'] as const),
    limit: data.limit === undefined ? 100 : eventInteger(data.limit, 1, 200),
  }
  if (data.before_id !== undefined) search.before_id = decodeIdentifier(data.before_id)
  if (data.after_id !== undefined) search.after_id = decodeIdentifier(data.after_id)
  if (search.before_id !== undefined && search.after_id !== undefined) throw new ContractError('event_cursor')
  if (data.level !== undefined) search.level = eventChoice(data.level, ['debug', 'info', 'warn', 'error'] as const)
  if (data.query !== undefined) search.query = eventText(data.query, 200)
  if (data.source_id !== undefined) search.source_id = decodeIdentifier(data.source_id)
  if (data.round_key !== undefined) search.round_key = metadata(data.round_key, 128)
  return search
}
export function auditRecordsSearch(value: unknown): AuditRecordsSearch {
  const data = eventObject(value)
  const search: AuditRecordsSearch = {
    page: data.page === undefined ? 1 : eventInteger(data.page, 1), page_size: data.page_size === undefined ? 50 : eventInteger(data.page_size, 1, 100),
  }
  if (data.query !== undefined) search.query = eventText(data.query, 200)
  if (data.source_id !== undefined) search.source_id = decodeIdentifier(data.source_id)
  if (data.action !== undefined) search.action = metadata(data.action, 80)
  if (data.outcome !== undefined) search.outcome = eventChoice(data.outcome, ['success', 'rejected', 'unknown', 'failure'] as const)
  return search
}
export function decodeRuntimeEvent(value: unknown): RuntimeEvent {
  const data = eventObject(value)
  return {
    id: decodeIdentifier(data.id), occurred_at: decodeInstant(data.occurred_at), level: eventChoice(data.level, ['debug', 'info', 'warn', 'error'] as const),
    source_id: nullableID(data.source_id), round_key: eventText(data.round_key), attempt: eventInteger(data.attempt, 0),
    phase: eventText(data.phase), outcome: eventText(data.outcome), error_code: eventText(data.error_code), message: eventText(data.message), fields: fields(data.fields),
  }
}
export function decodeRuntimeEventsPage(value: unknown): RuntimeEventsPage {
  const data = eventObject(value), stream = eventChoice(data.stream, ['live', 'history'] as const)
  const generation = data.generation === null ? null : eventText(data.generation)
  if (stream === 'live' ? generation === null || !/^[0-9a-f]{32}$/.test(generation) : generation !== null) throw new ContractError('event_generation')
  const limit = eventInteger(data.limit, 1, 200), total = eventInteger(data.total, 0)
  const before_id = nullableID(data.before_id), after_id = nullableID(data.after_id), next_before_id = nullableID(data.next_before_id)
  const earliest_id = nullableID(data.earliest_id), latest_id = nullableID(data.latest_id)
  if (before_id !== null && after_id !== null || (earliest_id === null) !== (latest_id === null) ||
    earliest_id !== null && latest_id !== null && BigInt(earliest_id) > BigInt(latest_id) ||
    !Array.isArray(data.items) || data.items.length > limit || data.items.length > total || typeof data.evicted !== 'boolean') throw new ContractError('event_page')
  const items = data.items.map(decodeRuntimeEvent)
  descending(items)
  if (items.some((item) => before_id !== null && BigInt(item.id) >= BigInt(before_id) || after_id !== null && BigInt(item.id) <= BigInt(after_id) ||
    earliest_id === null || latest_id === null || BigInt(item.id) < BigInt(earliest_id) || BigInt(item.id) > BigInt(latest_id)) ||
    next_before_id !== null && (items.length === 0 || next_before_id !== items[items.length - 1].id)) throw new ContractError('event_cursor')
  return { stream, generation, items, limit, before_id, after_id, next_before_id, earliest_id, latest_id, evicted: data.evicted, total }
}
export function decodeAuditRecord(value: unknown): AuditRecord {
  const data = eventObject(value)
  return {
    id: decodeIdentifier(data.id), occurred_at: decodeInstant(data.occurred_at), actor_kind: eventChoice(data.actor_kind, ['operator', 'address', 'system', 'historical'] as const),
    actor_ref: eventText(data.actor_ref), actor_display: eventText(data.actor_display), action: eventText(data.action), resource_kind: eventText(data.resource_kind), resource_ref: eventText(data.resource_ref),
    outcome: eventChoice(data.outcome, ['success', 'rejected', 'unknown', 'failure'] as const), source_id: nullableID(data.source_id), correlation_key: eventText(data.correlation_key),
    origin: eventText(data.origin), detail: eventText(data.detail), fields: fields(data.fields),
  }
}
export function decodeAuditRecordsPage(value: unknown): AuditRecordsPage {
  const data = eventObject(value), total = eventInteger(data.total, 0), page = eventInteger(data.page, 1), page_size = eventInteger(data.page_size, 1, 100)
  if (!Array.isArray(data.items) || data.items.length > page_size || data.items.length > total) throw new ContractError('audit_page')
  const offset = (BigInt(page) - 1n) * BigInt(page_size)
  if (data.items.length > 0 && offset + BigInt(data.items.length) > BigInt(total)) throw new ContractError('audit_page')
  const items = data.items.map(decodeAuditRecord)
  descending(items)
  return { items, total, page, page_size }
}
