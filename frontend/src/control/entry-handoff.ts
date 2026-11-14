import { ClientStateError, clientStateControlBase } from './client-state-handoff.ts'
import type { ClientStateStorage } from './client-state-handoff.ts'

let configured: { previous: string; current: string } | undefined
export function configureEntryHandoff(current: string, previous?: string): void {
  configured = previous ? { current: clientStateControlBase(current), previous: clientStateControlBase(previous) } : undefined
  if (configured?.current === configured?.previous) configured = undefined
}
export function previousControlBase(current: string): string | undefined { return configured?.current === current ? configured.previous : undefined }

/** Only a caller-supplied key in the explicitly configured old scope is read.
 * Destination must be verified before removing an unchanged original. No
 * cookies, secrets, network requests or mutations are restored here. */
export function handoffEntryReference(storage: ClientStateStorage, source: string, target: string, transform = (raw: string) => raw, merge?: (left: string, right: string) => string): void {
  const original = storage.getItem(source)
  if (original === null) return
  const incoming = transform(original), existing = storage.getItem(target)
  const value = existing === null || existing === incoming ? incoming : merge ? merge(existing, incoming) : null
  if (value === null) throw new ClientStateError('entry_handoff_conflict')
  if (existing !== value) storage.setItem(target, value)
  if (storage.getItem(target) !== value || storage.getItem(source) !== original) throw new ClientStateError('entry_handoff_unconfirmed')
  storage.removeItem(source)
  if (storage.getItem(source) !== null) throw new ClientStateError('entry_handoff_cleanup_unconfirmed')
}

export function mergeReferenceLists(left: string, right: string, field?: string): string {
  const first = JSON.parse(left), second = JSON.parse(right)
  const a = field ? first[field] : first, b = field ? second[field] : second
  if (!Array.isArray(a) || !Array.isArray(b) || field && (first.version !== 1 || second.version !== 1)) throw new ClientStateError('entry_handoff_invalid')
  const rows = [...a]
  for (const row of b) {
    const key = row.operation_key ?? row.key
    const prior = rows.find(value => (value.operation_key ?? value.key) === key)
    if (prior && JSON.stringify(prior) !== JSON.stringify(row)) throw new ClientStateError('entry_handoff_conflict')
    if (!prior) rows.push(row)
  }
  return JSON.stringify(field ? { ...first, [field]: rows } : rows)
}
