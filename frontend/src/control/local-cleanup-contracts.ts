import { ContractError, decodeIdentifier } from './contracts.ts'

export type LocalCleanupKind = 'source_delete' | 'address_purge'
export type LocalCleanupState = 'retired' | 'cleaning' | 'blocked' | 'complete'
export interface LocalCleanupCommand { operation_key: string; expected_revision: string; confirmation: string }
export interface LocalCleanupRecovery { version: 1; kind: LocalCleanupKind; source_id: string; address_id: string | null; operation_key: string }
export interface LocalCleanupReceipt {
  operation_key: string
  kind: LocalCleanupKind
  source_id: string
  address_id: string | null
  state: LocalCleanupState
  query_only: true
  payload_scrubbed: boolean
  inventory_complete: boolean
  last_error_code: string
  counts: { objects: string; pending: string; collected: string; absent: string; shared: string; protected: string; needs_review: string; unacknowledged: string; unresolved_operations: string }
}
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('local_cleanup')
  return value as Record<string, unknown>
}
function bool(value: unknown): boolean { if (typeof value !== 'boolean') throw new ContractError('local_cleanup_boolean'); return value }
function kind(value: unknown): LocalCleanupKind { if (value !== 'source_delete' && value !== 'address_purge') throw new ContractError('local_cleanup_kind'); return value }
function count(value: unknown): string { return value === '0' ? value : decodeIdentifier(value) }
export function cleanupOperationKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(value)) throw new ContractError('local_cleanup_key')
  return value
}
export function cleanupConfirmation(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || /[\x00\r\n]/.test(value) || new TextEncoder().encode(value).byteLength > 1024) throw new ContractError('local_cleanup_confirmation')
  for (let index = 0; index < value.length; index++) {
    const c = value.charCodeAt(index)
    if (c >= 0xd800 && c <= 0xdbff) { const next = value.charCodeAt(++index); if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ContractError('local_cleanup_confirmation') }
    else if (c >= 0xdc00 && c <= 0xdfff) throw new ContractError('local_cleanup_confirmation')
  }
  return value // Exact confirmation is never trimmed or reconstructed.
}
export function decodeCleanupRecovery(value: unknown): LocalCleanupRecovery {
  const row = object(value), selected = kind(row.kind), address = row.address_id === null ? null : decodeIdentifier(row.address_id)
  if (row.version !== 1 || (selected === 'source_delete') !== (address === null)) throw new ContractError('local_cleanup_recovery')
  return { version: 1, kind: selected, source_id: decodeIdentifier(row.source_id), address_id: address, operation_key: cleanupOperationKey(row.operation_key) }
}
/** Persist this metadata before sending a caller-chosen key. Neither input
 * confirmation nor credential/session material belongs in recovery storage. */
export function serializeCleanupRecovery(value: LocalCleanupRecovery): string { return JSON.stringify(decodeCleanupRecovery(value)) }
export function parseCleanupRecovery(raw: string): LocalCleanupRecovery {
  if (typeof raw !== 'string' || raw.length > 2048) throw new ContractError('local_cleanup_recovery')
  try { return decodeCleanupRecovery(JSON.parse(raw)) } catch { throw new ContractError('local_cleanup_recovery') }
}
export function decodeLocalCleanupReceipt(value: unknown): LocalCleanupReceipt {
  const row = object(value), counts = object(row.counts), selected = kind(row.kind), address = row.address_id === null ? null : decodeIdentifier(row.address_id)
  if ((selected === 'source_delete') !== (address === null) || row.query_only !== true || !['retired', 'cleaning', 'blocked', 'complete'].includes(row.state as string)) throw new ContractError('local_cleanup_state')
  const result: LocalCleanupReceipt = {
    operation_key: cleanupOperationKey(row.operation_key), kind: selected, source_id: decodeIdentifier(row.source_id), address_id: address,
    state: row.state as LocalCleanupState, query_only: true, payload_scrubbed: bool(row.payload_scrubbed), inventory_complete: bool(row.inventory_complete),
    last_error_code: typeof row.last_error_code === 'string' && (row.last_error_code === '' || /^[a-z][a-z0-9_]{0,127}$/.test(row.last_error_code)) ? row.last_error_code : (() => { throw new ContractError('local_cleanup_error') })(),
    counts: { objects: count(counts.objects), pending: count(counts.pending), collected: count(counts.collected), absent: count(counts.absent), shared: count(counts.shared), protected: count(counts.protected), needs_review: count(counts.needs_review), unacknowledged: count(counts.unacknowledged), unresolved_operations: count(counts.unresolved_operations) },
  }
  const c = result.counts
  if (BigInt(c.pending) + BigInt(c.collected) + BigInt(c.absent) + BigInt(c.shared) + BigInt(c.protected) + BigInt(c.needs_review) !== BigInt(c.objects)) throw new ContractError('local_cleanup_counts')
  if (result.state === 'complete' && (!result.payload_scrubbed || !result.inventory_complete || c.pending !== '0' || c.protected !== '0' || c.needs_review !== '0')) throw new ContractError('local_cleanup_complete')
  return result
}
