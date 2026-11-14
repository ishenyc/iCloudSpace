import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'

export type CreationSlotState = 'scheduled' | 'claimed' | 'finished' | 'cancelled' | 'unknown'
export type CreationAttemptState = 'scheduled' | 'claimed' | 'confirmed' | 'not_created' | 'unknown' | 'cancelled'
export type CreationOperationState = 'reserved' | 'candidate_unknown' | 'candidate_known' | 'confirming' | 'confirmed' | 'failed'
export interface CreationSlot {
  source_id: string
  policy_revision: string
  scheduled_for: string
  state: CreationSlotState
}
export interface CreationAttempt {
  id: string
  source_id: string
  policy_revision: string
  scheduled_for: string
  ordinal: number
  state: CreationAttemptState
  operation_key: string | null
  claimed_at: string | null
  finished_at: string | null
  error_code: string
  created_at: string
  operation_state: CreationOperationState | null
  address_id: string | null
  query_only: true
}
export interface CreationPolicy {
  source_id: string
  revision: string
  enabled: boolean
  schedule_kind: 'scheduled' | 'interval'
  interval_milliseconds: string | null
  maximum_addresses: number
  attempts_per_round: number
  cooldown_until: string | null
  last_attempted_at: string | null
  last_confirmed_at: string | null
  paused_reason: string
  last_address: string
  last_error_detail: string
  created_at: string
  updated_at: string
  slots: CreationSlot[]
  pending_attempt: CreationAttempt | null
}
export interface CreationRevision { expected_revision: string }
export interface CreationSettings extends CreationRevision { maximum_addresses: number; attempts_per_round: number }
export interface CreationAttemptsQuery { after_id?: string; limit?: number }
export interface CreationAttemptPage {
  source_id: string
  after_id: string
  limit: number
  next_after_id: string | null
  items: CreationAttempt[]
}

export function creationObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('creation_object')
  return value as Record<string, unknown>
}
function text(value: unknown): string {
  if (typeof value !== 'string') throw new ContractError('creation_text')
  return value
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('creation_boolean')
  return value
}
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ContractError('creation_choice')
  return value as T
}
export function creationInteger(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new ContractError('creation_integer')
  return value as number
}
function nullableInstant(value: unknown): string | null { return value === null ? null : decodeInstant(value) }
function nullableID(value: unknown): string | null { return value === null ? null : decodeIdentifier(value) }

export function decodeCreationSlot(value: unknown): CreationSlot {
  const data = creationObject(value)
  return { source_id: decodeIdentifier(data.source_id), policy_revision: decodeIdentifier(data.policy_revision),
    scheduled_for: decodeInstant(data.scheduled_for), state: choice(data.state, ['scheduled', 'claimed', 'finished', 'cancelled', 'unknown'] as const) }
}
export function decodeCreationAttempt(value: unknown): CreationAttempt {
  const data = creationObject(value)
  const operation_key = data.operation_key === null ? null : text(data.operation_key)
  if (data.query_only !== true || operation_key === '') throw new ContractError('creation_attempt')
  return {
    id: decodeIdentifier(data.id), source_id: decodeIdentifier(data.source_id), policy_revision: decodeIdentifier(data.policy_revision),
    scheduled_for: decodeInstant(data.scheduled_for), ordinal: creationInteger(data.ordinal, 0),
    state: choice(data.state, ['scheduled', 'claimed', 'confirmed', 'not_created', 'unknown', 'cancelled'] as const), operation_key,
    claimed_at: nullableInstant(data.claimed_at), finished_at: nullableInstant(data.finished_at), error_code: text(data.error_code), created_at: decodeInstant(data.created_at),
    operation_state: data.operation_state === null ? null : choice(data.operation_state, ['reserved', 'candidate_unknown', 'candidate_known', 'confirming', 'confirmed', 'failed'] as const),
    address_id: nullableID(data.address_id), query_only: true,
  }
}
export function decodeCreationPolicy(value: unknown): CreationPolicy {
  const data = creationObject(value), source_id = decodeIdentifier(data.source_id)
  const schedule_kind = choice(data.schedule_kind, ['scheduled', 'interval'] as const), interval_milliseconds = nullableID(data.interval_milliseconds)
  if ((schedule_kind === 'interval') !== (interval_milliseconds !== null) || !Array.isArray(data.slots)) throw new ContractError('creation_schedule')
  const slots = data.slots.map(decodeCreationSlot), pending_attempt = data.pending_attempt === null ? null : decodeCreationAttempt(data.pending_attempt)
  if (slots.some((slot) => slot.source_id !== source_id) || pending_attempt !== null && pending_attempt.source_id !== source_id ||
    new Set(slots.map((slot) => slot.policy_revision + '\x00' + slot.scheduled_for)).size !== slots.length) throw new ContractError('creation_source')
  return {
    source_id, revision: decodeIdentifier(data.revision), enabled: boolean(data.enabled), schedule_kind, interval_milliseconds,
    maximum_addresses: creationInteger(data.maximum_addresses, 0, 2147483647), attempts_per_round: creationInteger(data.attempts_per_round, 1),
    cooldown_until: nullableInstant(data.cooldown_until), last_attempted_at: nullableInstant(data.last_attempted_at), last_confirmed_at: nullableInstant(data.last_confirmed_at),
    paused_reason: text(data.paused_reason), last_address: text(data.last_address), last_error_detail: text(data.last_error_detail),
    created_at: decodeInstant(data.created_at), updated_at: decodeInstant(data.updated_at), slots, pending_attempt,
  }
}
export function decodeCreationAttemptPage(value: unknown): CreationAttemptPage {
  const data = creationObject(value), source_id = decodeIdentifier(data.source_id), after_id = decodeIdentifier(data.after_id, 'after_id', true)
  const limit = creationInteger(data.limit, 1, 100), next_after_id = nullableID(data.next_after_id)
  if (!Array.isArray(data.items) || data.items.length > limit) throw new ContractError('creation_page')
  const items = data.items.map(decodeCreationAttempt)
  let previous = BigInt(after_id)
  for (const item of items) {
    const current = BigInt(item.id)
    if (item.source_id !== source_id || current <= previous) throw new ContractError('creation_page_scope')
    previous = current
  }
  if (next_after_id !== null && (items.length === 0 || next_after_id !== items[items.length - 1].id)) throw new ContractError('creation_cursor')
  return { source_id, after_id, limit, next_after_id, items }
}
