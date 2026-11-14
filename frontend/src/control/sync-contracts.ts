import { ContractError, decodeIdentifier, decodeInstant } from './contracts.ts'

export type SyncTrigger = 'automatic' | 'manual' | 'public'
export type SyncPhase = 'directory' | 'mail' | 'finalize' | 'resolve'
export type SyncState = 'queued' | 'running' | 'waiting' | 'finished'
export type SyncOutcome = 'succeeded' | 'degraded' | 'failed' | 'cancelled' | 'superseded' | 'unknown'
export interface SyncScope {
  source_id: string; revision: string; generation: string; credential_generation: string; configuration_revision: string
}
export interface SyncBackfill {
  address_id: string; scan_epoch: string; uid_validity: string; captured_upper: string; committed: string
}
export interface SyncFrontier {
  uid_validity: string; captured_upper: string; committed: string; backfill: SyncBackfill | null
}
export interface SyncCounters { discovered: string; archived: string; links: string; bytes: string }
export interface SyncProgress {
  source: SyncScope; round_id: string; trigger: SyncTrigger; phase: SyncPhase; state: SyncState; outcome: SyncOutcome | null
  queued_at: string; started_at: string | null; finished_at: string | null; ready_at: string | null
  attempts: string; failed_attempts: string; segments: string; retries: string; admission_waits: string; admission_errors: string
  active_nanoseconds: string; recovered: boolean; error_code: string; directory_error_code: string
  frontier: SyncFrontier | null; counters: SyncCounters; waiting_manual: boolean
}
export interface Synchronization {
  source_id: string; automatic_after: string | null; last_terminal_at: string | null; progress: SyncProgress | null
}
export interface SyncWake { source_id: string; disposition: 'queued' | 'coalesced'; round_id: string | null; follow_up: boolean }
export interface SyncStatistics {
  sources: string; ready: string; in_flight: string; slots: string; closing: boolean
  catalog_errors: string; catalog_reloads: string; catalog_error_code: string
}
export interface SyncEvent {
  sequence: string; at: string; level: 'info' | 'warn' | 'error'; scope: 'round' | 'attempt' | 'phase' | 'admission' | 'schedule'
  name: string; outcome: SyncOutcome | null; progress: SyncProgress
}
export interface SyncEvents {
  source_id: string; round_id: string | null; after_sequence: string; last_sequence: string; lost: string; items: SyncEvent[]
}
export interface SyncEventsQuery { after_sequence?: string; round_id?: string }
export interface SyncBatch { items: { source_id: string; progress: SyncProgress | null }[]; statistics: SyncStatistics }

export function syncObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('sync_object')
  return value as Record<string, unknown>
}
function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new ContractError('sync_boolean')
  return value
}
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) throw new ContractError('sync_choice')
  return value as T
}
export function syncRoundID(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/.test(value)) throw new ContractError('sync_round')
  return value
}
function code(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{0,96}$/.test(value)) throw new ContractError('sync_code')
  return value
}
export function syncSequence(value: unknown): string {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 18446744073709551615n) throw new ContractError('sync_sequence')
  return value
}
function count(value: unknown): string { return decodeIdentifier(value, 'sync_count', true) }
function uid(value: unknown, zero = false): string {
  const decoded = decodeIdentifier(value, 'sync_uid', zero)
  if (BigInt(decoded) > 4294967295n) throw new ContractError('sync_uid')
  return decoded
}
function nullableInstant(value: unknown): string | null { return value === null ? null : decodeInstant(value) }
const outcomes = ['succeeded', 'degraded', 'failed', 'cancelled', 'superseded', 'unknown'] as const
function outcome(value: unknown): SyncOutcome | null { return value === null ? null : choice(value, outcomes) }

export function decodeSyncProgress(value: unknown): SyncProgress {
  const p = syncObject(value), s = syncObject(p.source), c = syncObject(p.counters)
  const source: SyncScope = { source_id: decodeIdentifier(s.source_id), revision: decodeIdentifier(s.revision), generation: decodeIdentifier(s.generation),
    credential_generation: decodeIdentifier(s.credential_generation), configuration_revision: decodeIdentifier(s.configuration_revision) }
  let frontier: SyncFrontier | null = null
  if (p.frontier !== null) {
    const f = syncObject(p.frontier)
    frontier = { uid_validity: uid(f.uid_validity), captured_upper: uid(f.captured_upper, true), committed: uid(f.committed, true), backfill: null }
    if (BigInt(frontier.committed) > BigInt(frontier.captured_upper)) throw new ContractError('sync_frontier')
    if (f.backfill !== null) {
      const b = syncObject(f.backfill)
      frontier.backfill = { address_id: decodeIdentifier(b.address_id), scan_epoch: decodeIdentifier(b.scan_epoch),
        uid_validity: uid(b.uid_validity), captured_upper: uid(b.captured_upper, true), committed: uid(b.committed, true) }
      if (frontier.committed !== frontier.captured_upper || frontier.backfill.uid_validity !== frontier.uid_validity ||
        BigInt(frontier.backfill.captured_upper) > BigInt(frontier.captured_upper) || BigInt(frontier.backfill.committed) > BigInt(frontier.backfill.captured_upper)) throw new ContractError('sync_backfill')
    }
  }
  const result: SyncProgress = {
    source, round_id: syncRoundID(p.round_id), trigger: choice(p.trigger, ['automatic', 'manual', 'public'] as const),
    phase: choice(p.phase, ['directory', 'mail', 'finalize', 'resolve'] as const), state: choice(p.state, ['queued', 'running', 'waiting', 'finished'] as const), outcome: outcome(p.outcome),
    queued_at: decodeInstant(p.queued_at), started_at: nullableInstant(p.started_at), finished_at: nullableInstant(p.finished_at), ready_at: nullableInstant(p.ready_at),
    attempts: count(p.attempts), failed_attempts: count(p.failed_attempts), segments: count(p.segments), retries: count(p.retries),
    admission_waits: count(p.admission_waits), admission_errors: count(p.admission_errors), active_nanoseconds: count(p.active_nanoseconds),
    recovered: boolean(p.recovered), error_code: code(p.error_code), directory_error_code: code(p.directory_error_code),
    frontier, counters: { discovered: count(c.discovered), archived: count(c.archived), links: count(c.links), bytes: count(c.bytes) }, waiting_manual: boolean(p.waiting_manual),
  }
  if ((result.state === 'finished') !== (result.outcome !== null && result.finished_at !== null) ||
    (result.state !== 'finished' && (result.finished_at !== null || result.outcome !== null && result.outcome !== 'unknown')) ||
    BigInt(result.failed_attempts) > BigInt(result.attempts) || BigInt(result.retries) > BigInt(result.failed_attempts) ||
    (result.trigger === 'public' && result.phase === 'directory')) throw new ContractError('sync_progress_state')
  return result
}
export function decodeSynchronization(value: unknown): Synchronization {
  const data = syncObject(value), source_id = decodeIdentifier(data.source_id)
  const progress = data.progress === null ? null : decodeSyncProgress(data.progress)
  if (progress !== null && progress.source.source_id !== source_id) throw new ContractError('sync_source')
  return { source_id, automatic_after: nullableInstant(data.automatic_after), last_terminal_at: nullableInstant(data.last_terminal_at), progress }
}
export function decodeSyncWake(value: unknown): SyncWake {
  const data = syncObject(value)
  const result = { source_id: decodeIdentifier(data.source_id), disposition: choice(data.disposition, ['queued', 'coalesced'] as const),
    round_id: data.round_id === null ? null : syncRoundID(data.round_id), follow_up: boolean(data.follow_up) }
  if (result.follow_up !== (result.round_id === null)) throw new ContractError('sync_wake')
  return result
}
export function decodeSyncStatistics(value: unknown): SyncStatistics {
  const data = syncObject(value)
  const result = { sources: count(data.sources), ready: count(data.ready), in_flight: count(data.in_flight), slots: count(data.slots), closing: boolean(data.closing),
    catalog_errors: syncSequence(data.catalog_errors), catalog_reloads: syncSequence(data.catalog_reloads), catalog_error_code: code(data.catalog_error_code) }
  if (BigInt(result.ready) > BigInt(result.sources) || BigInt(result.in_flight) > BigInt(result.sources)) throw new ContractError('sync_statistics')
  return result
}
export function decodeSyncEvents(value: unknown): SyncEvents {
  const data = syncObject(value), source_id = decodeIdentifier(data.source_id), round_id = data.round_id === null ? null : syncRoundID(data.round_id)
  const after_sequence = syncSequence(data.after_sequence), last_sequence = syncSequence(data.last_sequence), lost = syncSequence(data.lost)
  if (!Array.isArray(data.items)) throw new ContractError('sync_events')
  let previous = BigInt(after_sequence)
  const items: SyncEvent[] = data.items.map((value) => {
    const event = syncObject(value), sequence = syncSequence(event.sequence), progress = decodeSyncProgress(event.progress)
    if (BigInt(sequence) <= previous || BigInt(sequence) > BigInt(last_sequence) || progress.source.source_id !== source_id ||
      (round_id !== null && progress.round_id !== round_id)) throw new ContractError('sync_event_scope')
    previous = BigInt(sequence)
    return { sequence, at: decodeInstant(event.at), level: choice(event.level, ['info', 'warn', 'error'] as const),
      scope: choice(event.scope, ['round', 'attempt', 'phase', 'admission', 'schedule'] as const), name: code(event.name), outcome: outcome(event.outcome), progress }
  })
  return { source_id, round_id, after_sequence, last_sequence, lost, items }
}
export function decodeSyncBatch(value: unknown): SyncBatch {
  const data=syncObject(value)
  if(!Array.isArray(data.items)||data.items.length<1||data.items.length>1000)throw new ContractError('sync_batch')
  const seen=new Set<string>()
  const items=data.items.map(value=>{
    const item=syncObject(value),source_id=decodeIdentifier(item.source_id),progress=item.progress===null?null:decodeSyncProgress(item.progress)
    if(seen.has(source_id)||progress!==null&&progress.source.source_id!==source_id)throw new ContractError('sync_batch_scope')
    seen.add(source_id);return {source_id,progress}
  })
  return {items,statistics:decodeSyncStatistics(data.statistics)}
}
