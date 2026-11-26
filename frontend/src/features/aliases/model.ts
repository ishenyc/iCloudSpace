import { ControlError, InvalidResponseError, RequestConfigurationError } from '../../transport/index.ts'
import { decodeIdentifier } from '../../control/contracts.ts'
import type { AddressFilter, AddressMetadata } from '../../control/address-contracts.ts'
import type { ControlServices } from '../../control/runtime.ts'
import type { CredentialExportDownload, CredentialExportKind, CredentialExportFormat } from '../../control/credential-exports.ts'
import { aliasAccess, archiveQuery } from '../alias-archive.ts'
import type { ArchiveFilter } from '../alias-archive.ts'
import { handoffEntryReference, mergeReferenceLists, previousControlBase } from '../../control/entry-handoff.ts'
import type { ClientStateStorage } from '../../control/client-state-handoff.ts'

export type AliasRows = { items: AddressMetadata[]; total: number }
export interface AliasFilters { source: string; group: string; query: string; withoutMail: boolean; archive: ArchiveFilter }
export function aliasFilter(value: AliasFilters): AddressFilter {
  return { ...(value.source ? { source_id: decodeIdentifier(value.source) } : {}), ...(value.group === 'none' ? { ungrouped: true } : value.group ? { group_id: decodeIdentifier(value.group) } : {}),
    ...(value.query.trim() ? { query: value.query.trim() } : {}), ...(value.withoutMail ? { has_mail: false } : {}), archive: archiveQuery(value.archive) }
}
export async function loadAliasRows(addresses: ControlServices['addresses'], filter: AddressFilter, page: number, size: number, signal: AbortSignal): Promise<AliasRows> {
  signal.throwIfAborted()
  if (size !== 0) { const result = (await addresses.list({ ...filter, page, page_size: size }, signal)).result; signal.throwIfAborted(); return result }
  const items: AddressMetadata[] = [], seen = new Set<string>()
  let total: number | undefined
  for (let current = 1; ; current++) {
    const result = (await addresses.list({ ...filter, page: current, page_size: 1000 }, signal)).result
    signal.throwIfAborted()
    if (total !== undefined && total !== result.total) throw new InvalidResponseError('address_collection_changed')
    total = result.total
    for (const row of result.items) { if (seen.has(row.id)) throw new InvalidResponseError('address_collection_changed'); seen.add(row.id); items.push(row) }
    if (items.length === total) return { items, total }
    if (items.length > total || result.items.length === 0) throw new InvalidResponseError('address_collection_changed')
  }
}
export function formatAliasTime(value: string | null | undefined, seconds = false): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isFinite(date.valueOf()) ? new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}), hour12: false }).format(date) : '—'
}
export function credentialLabel(row: AddressMetadata) { return ({ mailbox: 'IMAP/OAuth', api_key_only: 'API 凭证', legacy_latest: '最新快照 API', unavailable: '凭证不可用' } as const)[row.credential_profile] }

export type AliasRotationKind = 'key' | 'bundle'
export type PendingAliasAction = Readonly<{ kind: AliasRotationKind | 'remote_delete' | 'local_delete' | 'purge'; key: string; sourceID: string; addressID: string }>
type Ports = Pick<ControlServices, 'addresses' | 'credentials' | 'credentialExports' | 'hme'>
type PendingStore = { storage: Pick<Storage, 'getItem' | 'setItem'>; key: string }

/** Original uncertain identities survive page/filter changes and optional tab
 * restoration. This feature stores no password, key, bearer or draft body. */
export class AliasActions {
  private readonly services: Ports
  private readonly unresolved = new Map<string, PendingAliasAction>()
  private readonly store?: PendingStore
  private readonly active = new Set<string>()
  private restorationFailed = false
  private referenceID(operation:PendingAliasAction) {return [operation.kind,operation.sourceID,operation.addressID,operation.key].join(':')}
  private restore(raw:string) {
    const value=JSON.parse(raw)
    if(!value || value.version!==1 || !Array.isArray(value.operations) || value.operations.length>1000)throw new Error()
    const seen=new Set<string>()
    for(const row of value.operations) {
      if(!row || !['key','bundle','remote_delete','local_delete','purge'].includes(row.kind) || typeof row.key!=='string' || !/^[A-Za-z0-9._~-]{1,256}$/.test(row.key))throw new Error()
      const operation=Object.freeze({kind:row.kind,key:row.key,sourceID:decodeIdentifier(row.sourceID),addressID:decodeIdentifier(row.addressID)})
      if(seen.has(operation.key))throw new Error()
      seen.add(operation.key)
      const reference=this.referenceID(operation)
      if([...this.unresolved.values()].some(prior=>prior.key===operation.key && this.referenceID(prior)!==reference))this.restorationFailed=true
      if(!this.unresolved.has(reference))this.unresolved.set(reference,operation)
    }
  }
  constructor(services: Ports, store?: PendingStore) {
    this.services = services; this.store = store
    if (store) {
      const current = store.key.split(':')[1] || '', previous = previousControlBase(current)
      if(previous)try {
        const old=store.key.replace(current,previous),raw=store.storage.getItem(old)
        if(raw!==null)this.restore(raw)
        handoffEntryReference(store.storage as ClientStateStorage,old,store.key,raw=>{this.restore(raw);return raw},(left,right)=>mergeReferenceLists(left,right,'operations'))
      }catch{this.restorationFailed=true}
      try {const raw=store.storage.getItem(store.key);if(raw!==null)this.restore(raw)}catch{this.restorationFailed=true}
    }
  }
  get recoveryRequired() { return this.restorationFailed }
  get awaitingQuery(): readonly PendingAliasAction[] { return this.pending.filter(record => !this.active.has(record.addressID)) }
  get pending(): readonly PendingAliasAction[] { return [...this.unresolved.values()] }
  private persist() { if (this.store && !this.restorationFailed) try { const raw=JSON.stringify({version:1,operations:this.pending});this.store.storage.setItem(this.store.key,raw);if(this.store.storage.getItem(this.store.key)!==raw)throw new Error() } catch { this.restorationFailed = true } }
  private remember(operation: PendingAliasAction) { this.unresolved.set(this.referenceID(operation), operation); this.persist() }
  private settled(operation: PendingAliasAction) { this.unresolved.delete(this.referenceID(operation)); this.persist() }
  private identity(row: AddressMetadata, kind: PendingAliasAction['kind']): PendingAliasAction { return Object.freeze({ kind, key: kind === 'local_delete' ? 'local-' + row.id : crypto.randomUUID(), sourceID: row.source_id, addressID: row.id }) }
  private available(addressID: string) {
    if (this.restorationFailed || this.active.has(addressID) || [...this.unresolved.values()].some(item => item.addressID === addressID)) throw new RequestConfigurationError('address_operation_unresolved', { outcome: 'not_sent' })
  }
  private async perform<T>(operation: PendingAliasAction, invoke: () => Promise<T>, unsettled?: (result: T) => boolean): Promise<T> {
    this.available(operation.addressID)
    this.remember(operation) // persist the original ID before entering network I/O
    if (this.restorationFailed) throw new RequestConfigurationError('address_recovery_storage_unavailable', { outcome: 'not_sent' })
    this.active.add(operation.addressID)
    try { const result = await invoke(); if (!unsettled?.(result)) this.settled(operation); return result } catch (error) {
      const rejectedCodes = ['CREDENTIAL_SCOPE_CHANGED', 'CREDENTIAL_INPUT_INVALID', 'ADDRESS_INPUT_INVALID', 'ADDRESS_REVISION_CONFLICT', 'ADDRESS_INELIGIBLE', 'CSRF_INVALID', 'SESSION_REQUIRED', 'CREDENTIALS_INVALID']
      if (error instanceof ControlError && (error.category === 'request' || error.outcome === 'not_sent' || error.outcome === 'rejected' || error.category === 'http' && rejectedCodes.includes(error.code))) this.settled(operation)
      throw error
    } finally { this.active.delete(operation.addressID) }
  }
  async rotate(row: AddressMetadata, kind: AliasRotationKind = row.credential_profile === 'mailbox' ? 'bundle' : 'key') {
    if (!aliasAccess(row).canRotate || kind === 'bundle' && row.credential_profile !== 'mailbox') throw new RequestConfigurationError('address_ineligible', { outcome: 'not_sent' })
    this.available(row.id)
    const operation = this.identity(row, kind)
    const scope = kind === 'key' ? (await this.services.credentials.addressScope(row.id)).result : undefined
    return this.perform(operation, async () => {
      if (kind === 'bundle') return (await this.services.credentials.rotateBundle(row.id, { operation_key: operation.key, expected_generation: row.auth_generation })).result
      return (await this.services.credentials.rotateKey(row.id, { operation_key: operation.key, expected_generation: row.auth_generation, expected_scope_digest: scope!.digest })).result
    }, result => result.state !== 'committed' && result.state !== 'cancelled')
  }
  async remove(row: AddressMetadata, confirmation: string) {
    if (!aliasAccess(row).canDelete || confirmation.trim() !== row.address) throw new RequestConfigurationError('address_ineligible', { outcome: 'not_sent' })
    if (row.lifecycle === 'archived') {
      const operation = this.identity(row, 'purge')
      return this.perform(operation, async () => (await this.services.addresses.purge(row.id, { expected_revision: row.revision, confirm_address: confirmation, operation_key: operation.key })).result,
        result => result.state !== 'confirmed' && result.state !== 'failed')
    }
    if (row.kind !== 'apple') {
      const operation = this.identity(row, 'local_delete')
      return this.perform(operation, async () => (await this.services.addresses.delete(row.id, { expected_revision: row.revision, confirm_address: confirmation })).result)
    }
    const operation = this.identity(row, 'remote_delete')
    return this.perform(operation, async () => (await this.services.hme.delete(row.source_id, row.id, { expected_revision: row.revision, confirm_address: confirmation, operation_key: operation.key })).result,
      result => result.operation.state !== 'confirmed' && result.operation.state !== 'failed')
  }
  async query(operation: PendingAliasAction) {
    if (this.unresolved.get(this.referenceID(operation)) !== operation) throw new RequestConfigurationError('unknown_address_operation', { outcome: 'not_sent' })
    if (operation.kind === 'key' || operation.kind === 'bundle') {
      const result = (await this.services.credentials.queryRotation(operation.key)).result
      if (result.kind !== (operation.kind === 'key' ? 'api_key' : 'bundle') || result.state === 'committed' && (result.items.length !== 1 || result.items[0].address_id !== operation.addressID || result.items[0].source_id !== operation.sourceID)) throw new InvalidResponseError('rotation_scope')
      if (result.state === 'committed' || result.state === 'cancelled') this.settled(operation)
      return result.state
    }
    if (operation.kind === 'remote_delete') {
      const result = (await this.services.hme.queryDelete(operation.sourceID, operation.addressID, operation.key)).result
      if (result.operation.state === 'confirmed' || result.operation.state === 'failed') this.settled(operation)
      return result.operation.state
    }
    if (operation.kind === 'purge') {
      const result = (await this.services.addresses.queryPurge(operation.addressID, operation.key)).result
      if (result.source_id !== operation.sourceID) throw new InvalidResponseError('address_operation_scope')
      if (result.state === 'confirmed' || result.state === 'failed') this.settled(operation)
      return result.state
    }
    try { const row = (await this.services.addresses.get(operation.addressID)).result; if (row.source_id !== operation.sourceID) throw new InvalidResponseError('address_operation_scope'); if(row.lifecycle==='archived'){this.settled(operation);return 'confirmed'}; return 'present' } catch (error) {
      if (error instanceof ControlError && error.code === 'ADDRESS_NOT_FOUND') { this.settled(operation); return 'confirmed' }
      throw error
    }
  }
  async export(kind: CredentialExportKind, format: CredentialExportFormat, filter: AddressFilter, selected?: readonly string[], signal?: AbortSignal): Promise<CredentialExportDownload> {
    return this.services.credentialExports.download(selected ? { kind, format, selected_ids: [...selected] } : { kind, format, filter }, signal)
  }
}
export function saveAliasDownload(download: CredentialExportDownload) {
  const url = URL.createObjectURL(download.blob), anchor = document.createElement('a')
  try { anchor.href = url; anchor.download = download.filename; document.body.append(anchor); anchor.click() } finally { anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000) }
}
