import { decodeIdentifier } from './contracts.ts'
import { mailoutKey } from './mailout-contracts.ts'
import { handoffEntryReference, previousControlBase } from './entry-handoff.ts'

export type ClientStateStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
export interface PreservedClientState { readonly key: string; readonly value: string }
export interface CompositionRecord { readonly version: 1; readonly address_id: string; readonly context_key?: string; readonly submission_key?: string }
export interface CompositionRecovery {
  readonly record: CompositionRecord | null
  readonly queryKeys: readonly string[]
  readonly contextKeys: readonly string[]
  readonly blocked: boolean
  readonly error: ClientStateError | null
  readonly preserved: readonly PreservedClientState[]
}

export class ClientStateError extends Error {
  readonly code: string
  constructor(code: string) {
    super('Browser storage could not safely preserve the original operation. Keep its original reference and query it.')
    this.name = 'ClientStateError'; this.code = code
  }
}

/** Acquisition is deliberately inside the caller-supplied function: even the
 * browser's localStorage property getter may throw before getItem is reached. */
export function safeBrowserStorage(acquire: () => ClientStateStorage): ClientStateStorage {
  let storage: ClientStateStorage | undefined
  try { storage = acquire() } catch { /* Render recovery UI without browser storage. */ }
  return {
    getItem(key) { if (!storage) throw new ClientStateError('storage_unavailable'); return storage.getItem(key) },
    setItem(key, value) { if (!storage) throw new ClientStateError('storage_unavailable'); storage.setItem(key, value) },
    removeItem(key) { if (!storage) throw new ClientStateError('storage_unavailable'); storage.removeItem(key) },
  }
}

export function clientStateControlBase(value: string): string {
  if (typeof value !== 'string' || !value.startsWith('/') || !value.endsWith('/api/control/v1') || /[?#%{}\\\s\p{Cc}]/u.test(value) || value.includes('//') || value.split('/').some(part => part === '.' || part === '..')) throw new ClientStateError('storage_scope_invalid')
  return value
}

export function compositionStorageKey(controlBase: string, addressID: string): string {
  return 'iCloudSpace:composition:1:' + encodeURIComponent(clientStateControlBase(controlBase)) + ':' + decodeIdentifier(addressID)
}
export function legacyCompositionStorageKey(addressID: string): string { return 'icloudspace-mail-send:' + decodeIdentifier(addressID) }

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ClientStateError('composition_record_invalid')
  return value as Record<string, unknown>
}
export function decodeCompositionRecord(value: unknown, addressID: string): CompositionRecord {
  const row = object(value)
  if (row.version !== 1 || row.address_id !== decodeIdentifier(addressID) || Object.keys(row).some(key => !['version', 'address_id', 'context_key', 'submission_key'].includes(key))) throw new ClientStateError('composition_record_invalid')
  try {
    return Object.freeze({ version: 1, address_id: addressID, ...(row.context_key === undefined ? {} : { context_key: mailoutKey(row.context_key) }), ...(row.submission_key === undefined ? {} : { submission_key: mailoutKey(row.submission_key) }) })
  } catch { throw new ClientStateError('composition_record_invalid') }
}
function parse(raw: string, addressID: string): CompositionRecord {
  try { return decodeCompositionRecord(JSON.parse(raw), addressID) } catch { throw new ClientStateError('composition_record_invalid') }
}
const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i

/** One confirmed old UUID pointer and one current v1 record, for one supplied
 * installation/address only. There is no namespace discovery or network I/O. */
export class CompositionHandoff {
  readonly key: string
  readonly legacyKey: string
  private readonly storage: ClientStateStorage
  private readonly addressID: string
  private expected: string | null | undefined
  private blocked = false
  private readonly previousKey?: string

  constructor(storage: ClientStateStorage, controlBase: string, addressID: string) {
    this.storage = storage; this.addressID = decodeIdentifier(addressID)
    this.key = compositionStorageKey(controlBase, addressID); this.legacyKey = legacyCompositionStorageKey(addressID)
    const previous = previousControlBase(controlBase)
    this.previousKey = previous ? compositionStorageKey(previous, addressID) : undefined
  }

  recover(readable?: (state: CompositionRecovery) => void): CompositionRecovery {
    const preserved: PreservedClientState[] = [], errors: ClientStateError[] = []
    let old: string | null | undefined, current: string | null | undefined, record: CompositionRecord | null = null
    let previousRecord: CompositionRecord | null = null
    if (this.previousKey) try {
      const raw = this.storage.getItem(this.previousKey)
      if (raw !== null) { preserved.push({ key: this.previousKey, value: raw }); previousRecord = parse(raw, this.addressID) }
      handoffEntryReference(this.storage, this.previousKey, this.key)
    } catch (error) { errors.push(error instanceof ClientStateError ? error : new ClientStateError('entry_handoff_storage_failed')) }
    // Read independently: a broken target must not hide a readable original UUID.
    try { old = this.storage.getItem(this.legacyKey); if (old !== null) preserved.push({ key: this.legacyKey, value: old }) } catch { errors.push(new ClientStateError('legacy_storage_read_denied')) }
    try { current = this.storage.getItem(this.key); if (current !== null) preserved.push({ key: this.key, value: current }) } catch { errors.push(new ClientStateError('composition_storage_read_denied')) }
    const original = typeof old === 'string' && uuid.test(old) ? old : null
    if (typeof old === 'string' && !original) errors.push(new ClientStateError('legacy_pointer_invalid'))
    if (typeof current === 'string') try { record = parse(current, this.addressID) } catch { errors.push(new ClientStateError('composition_record_invalid')) }
    this.expected = current
    const queryKeys = [...new Set([...(original ? [original] : []), ...(previousRecord?.submission_key ? [previousRecord.submission_key] : []), ...(record?.submission_key ? [record.submission_key] : [])])]
    const contextKeys = [...new Set([...(previousRecord?.context_key ? [previousRecord.context_key] : []), ...(record?.context_key ? [record.context_key] : [])])]
    if (!record && previousRecord) record = previousRecord
    if (original && record && record.submission_key !== original) errors.push(new ClientStateError('composition_handoff_conflict'))
    if (!record && original) record = Object.freeze({ version: 1, address_id: this.addressID, submission_key: original })
    // Let the actual model expose the readable original before a destination
    // write or source cleanup can fail. New mutations stay locked during this.
    readable?.(Object.freeze({ record, queryKeys: Object.freeze(queryKeys),contextKeys:Object.freeze(contextKeys), blocked: true, error: errors[0] ?? null, preserved: Object.freeze(preserved) }))
    if (original && !errors.length) {
      try {
        if (current === null) {
          record = Object.freeze({ version: 1, address_id: this.addressID, submission_key: original })
          this.blocked = false
          this.commit(record)
        }
        // Confirm the committed target again before touching the original.
        if (this.storage.getItem(this.key) !== this.expected) throw new ClientStateError('composition_commit_changed')
        if (this.storage.getItem(this.legacyKey) !== old) throw new ClientStateError('legacy_pointer_changed')
        this.storage.removeItem(this.legacyKey)
        if (this.storage.getItem(this.legacyKey) !== null) throw new ClientStateError('legacy_cleanup_unconfirmed')
      } catch (error) { errors.push(error instanceof ClientStateError ? error : new ClientStateError('composition_handoff_storage_failed')) }
    }
    // A readable old key remains queryable even if the destination cannot commit.
    this.blocked = errors.length > 0
    return Object.freeze({ record, queryKeys: Object.freeze(queryKeys),contextKeys:Object.freeze(contextKeys), blocked: this.blocked, error: errors[0] ?? null, preserved: Object.freeze(preserved.map(row => Object.freeze(row))) })
  }

  commit(value: CompositionRecord): void {
    if (this.blocked) throw new ClientStateError('composition_recovery_blocked')
    const record = decodeCompositionRecord(value, this.addressID), raw = JSON.stringify(record)
    try {
      if (this.expected === undefined || this.storage.getItem(this.key) !== this.expected) throw new ClientStateError('composition_commit_changed')
      this.storage.setItem(this.key, raw)
      const committed = this.storage.getItem(this.key)
      if (committed !== raw) throw new ClientStateError('composition_commit_unconfirmed')
      parse(committed, this.addressID)
      this.expected = raw
    } catch (error) {
      this.blocked = true
      throw error instanceof ClientStateError ? error : new ClientStateError('composition_storage_write_denied')
    }
  }
}
