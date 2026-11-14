import { credentialKey, decodeCredentialScope } from './credential-contracts.ts'
import type { CredentialScope } from './credential-contracts.ts'
import { handoffEntryReference } from './entry-handoff.ts'
import type { ClientStateStorage } from './client-state-handoff.ts'

export type PendingRotation = { version: 1; operation_key: string; scope: CredentialScope; storage_key?: string }
export type RotationRecovery = { prefix: string; pending: PendingRotation[]; error: Error | null }
type RotationStorage = ClientStateStorage & Pick<Storage, 'length' | 'key'>

export function parsePendingRotation(raw: string): PendingRotation {
  const value: unknown = JSON.parse(raw)
  if (value === null || typeof value !== 'object' || Array.isArray(value) || !('version' in value) || value.version !== 1 || !('operation_key' in value) || !('scope' in value)) throw new Error('invalid_rotation_reference')
  return { version: 1, operation_key: credentialKey(value.operation_key), scope: decodeCredentialScope(value.scope) }
}

/** A failed handoff blocks commands while each independently readable exact
 * reference remains available for an explicit query. No network is issued. */
export function inspectPendingRotations(storage: RotationStorage, prefix: string, previousPrefix?: string): RotationRecovery {
  const keys: string[] = [], pending = new Map<string, PendingRotation>()
  let error: Error | null = null
  const failed = () => { error ??= new Error('无法读取或校验已保存的原操作引用。请先核对本入口的操作记录，本页不会发起新的全量轮换。') }
  try {
    for (let index = 0; index < storage.length; index++) {
      const key = storage.key(index)
      if (key?.startsWith(prefix) || previousPrefix && key?.startsWith(previousPrefix)) keys.push(key!)
    }
  } catch { failed() }
  const read = (key: string, selectedPrefix: string) => {
    try {
      const raw = storage.getItem(key)
      if (raw === null) return
      const item = parsePendingRotation(raw)
      if (key !== selectedPrefix + item.operation_key) throw new Error('invalid_rotation_reference')
      pending.set(key, { ...item, storage_key: key })
    } catch { failed() }
  }
  for (const key of keys.sort()) read(key, previousPrefix && key.startsWith(previousPrefix) ? previousPrefix : prefix)
  for (const key of keys) {
    if (!previousPrefix || !key.startsWith(previousPrefix) || !pending.has(key)) continue
    const target = prefix + key.slice(previousPrefix.length)
    try {
      handoffEntryReference(storage, key, target, raw => { const item = parsePendingRotation(raw); if (key !== previousPrefix + item.operation_key) throw new Error(); return raw })
      pending.delete(key)
    } catch { failed() }
    read(target, prefix)
  }
  return { prefix, pending: [...pending.values()], error }
}

export function persistPendingRotation(storage: ClientStateStorage, prefix: string, item: PendingRotation): void {
  const value: PendingRotation = { version: 1, operation_key: credentialKey(item.operation_key), scope: decodeCredentialScope(item.scope) }
  const key = prefix + value.operation_key, raw = JSON.stringify(value), existing = storage.getItem(key)
  if (existing !== null && existing !== raw) throw new Error('rotation_reference_conflict')
  storage.setItem(key, raw)
  if (storage.getItem(key) !== raw) throw new Error('rotation_reference_unconfirmed')
}

export function forgetPendingRotation(storage: ClientStateStorage, prefix: string, item: PendingRotation): void {
  const key = item.storage_key || prefix + item.operation_key, raw = storage.getItem(key)
  if (raw === null) return
  const expected = { version: 1, operation_key: item.operation_key, scope: item.scope }
  if (JSON.stringify(parsePendingRotation(raw)) !== JSON.stringify(expected)) throw new Error('rotation_reference_changed')
  storage.removeItem(key)
  if (storage.getItem(key) !== null) throw new Error('rotation_reference_cleanup_unconfirmed')
}
