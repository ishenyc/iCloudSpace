import { ControlClient, ControlError, RequestConfigurationError, RequestSequence } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import {
  addressBoolean, addressFilter, addressNullableID, addressObject, addressPageQuery, addressProfile, addressText,
  decodeAddress, decodeAddressGroup, decodeAddressOperation, decodeAddressPage, decodeHistoricalRemovalPage,
} from './address-contracts.ts'
import type {
  AddressCreate, AddressDelete, AddressFilter, AddressGroup, AddressListQuery, AddressMetadata, AddressOperation,
  AddressPage, AddressPatch, AddressPurge, AddressRandomCreate, AddressSelection, HistoricalRemovalPage,
} from './address-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_address_input', { outcome: 'not_sent' }) }
}
function array<T>(value: unknown, decode: (value: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new ContractError('address_array')
  return value.map(decode)
}
function matches(value: unknown, id: string): AddressMetadata {
  const item = decodeAddress(value)
  if (item.id !== id) throw new ContractError('address_id')
  return item
}
function archived(value: unknown, id: string): { id: string; archived: true } {
  const item = addressObject(value)
  if (decodeIdentifier(item.id) !== id || item.archived !== true) throw new ContractError('address_archival')
  return { id, archived: true }
}
function deleted(value: unknown, id: string): { id: string; deleted: true } {
  const item = addressObject(value)
  if (decodeIdentifier(item.id) !== id || item.deleted !== true) throw new ContractError('address_deletion')
  return { id, deleted: true }
}
function operationKey(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/.test(value)) throw new ContractError('operation_key')
  return value
}

export class AddressesModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  list(query: AddressListQuery = {}, signal?: AbortSignal): Promise<ControlResult<AddressPage>> {
    return this.client.json('/addresses', { search: input(() => addressPageQuery(query)), signal, decodeResult: decodeAddressPage })
  }
  historicalRemovals(query: Pick<AddressListQuery,'source_id'|'query'|'page'|'page_size'> = {}, signal?: AbortSignal): Promise<ControlResult<HistoricalRemovalPage>> {
    return this.client.json('/addresses/historical-removals', { search: input(() => addressPageQuery(query)), signal, decodeResult: value => {
      const result = decodeHistoricalRemovalPage(value)
      if (query.source_id && result.items.some(item => item.source_id !== query.source_id)) throw new ContractError('historical_source')
      return result
    } })
  }
  get(id: string, signal?: AbortSignal): Promise<ControlResult<AddressMetadata>> {
    id = input(() => decodeIdentifier(id))
    return this.client.json('/addresses/' + id, { signal, decodeResult: (value) => matches(value, id) })
  }
  create(value: AddressCreate, signal?: AbortSignal): Promise<ControlResult<AddressMetadata>> {
    const body = input(() => ({
      source_id: decodeIdentifier(value.source_id), address: addressText(value.address), label: addressText(value.label),
      group_id: addressNullableID(value.group_id), enabled: addressBoolean(value.enabled), credential_profile: addressProfile(value.credential_profile),
    }))
    return this.client.json('/addresses', { method: 'POST', body, signal, decodeResult: decodeAddress })
  }
  random(value: AddressRandomCreate, signal?: AbortSignal): Promise<ControlResult<AddressMetadata[]>> {
    const body = input(() => {
      if (!Number.isInteger(value.count) || value.count < 1 || value.count > 1000) throw new ContractError('address_count')
      return { source_id: decodeIdentifier(value.source_id), count: value.count, label: addressText(value.label),
        group_id: addressNullableID(value.group_id), credential_profile: addressProfile(value.credential_profile) }
    })
    return this.client.json('/addresses/random', { method: 'POST', body, signal, decodeResult: (value) => array(value, decodeAddress) })
  }
  patch(id: string, value: AddressPatch, signal?: AbortSignal): Promise<ControlResult<AddressMetadata>> {
    id = input(() => decodeIdentifier(id))
    const body = input(() => {
      const data = addressObject(value)
      const result: AddressPatch = { expected_revision: decodeIdentifier(data.expected_revision) }
      if (data.label !== undefined) result.label = addressText(data.label)
      if (data.enabled !== undefined) result.enabled = addressBoolean(data.enabled)
      if (Object.hasOwn(data, 'group_id')) result.group_id = addressNullableID(data.group_id)
      return result
    })
    return this.client.json('/addresses/' + id, { method: 'PATCH', body, signal, resource: { kind: 'address', id }, decodeResult: (value) => matches(value, id) })
  }
  delete(id: string, value: AddressDelete, signal?: AbortSignal): Promise<ControlResult<{ id: string; archived: true }>> {
    id = input(() => decodeIdentifier(id))
    const body = input(() => ({ expected_revision: decodeIdentifier(value.expected_revision), confirm_address: addressText(value.confirm_address) }))
    return this.client.json('/addresses/' + id, { method: 'DELETE', body, signal, resource: { kind: 'address', id }, decodeResult: (value) => archived(value, id) })
  }
  export(format: 'csv' | 'jsonl', filter: AddressFilter = {}, signal?: AbortSignal): Promise<ReadableStream<Uint8Array>> {
    const body = input(() => {
      if (format !== 'csv' && format !== 'jsonl') throw new ContractError('format')
      return { format, filter: addressFilter(filter) }
    })
    return this.client.stream('/addresses/export', { method: 'POST', body, signal })
  }
  groups(signal?: AbortSignal): Promise<ControlResult<AddressGroup[]>> {
    return this.client.json('/address-groups', { signal, decodeResult: (value) => array(value, decodeAddressGroup) })
  }
  createGroup(name: string, signal?: AbortSignal): Promise<ControlResult<AddressGroup>> {
    return this.client.json('/address-groups', { method: 'POST', body: input(() => ({ name: addressText(name) })), signal, decodeResult: decodeAddressGroup })
  }
  renameGroup(id: string, expectedRevision: string, name: string, signal?: AbortSignal): Promise<ControlResult<AddressGroup>> {
    id = input(() => decodeIdentifier(id))
    const body = input(() => ({ expected_revision: decodeIdentifier(expectedRevision), name: addressText(name) }))
    return this.client.json('/address-groups/' + id, { method: 'PATCH', body, signal, resource: { kind: 'address_group', id }, decodeResult: (value) => {
      const result = decodeAddressGroup(value)
      if (result.id !== id) throw new ContractError('group_id')
      return result
    } })
  }
  deleteGroup(id: string, expectedRevision: string, signal?: AbortSignal): Promise<ControlResult<{ id: string; deleted: true }>> {
    id = input(() => decodeIdentifier(id))
    const body = input(() => ({ expected_revision: decodeIdentifier(expectedRevision) }))
    return this.client.json('/address-groups/' + id, { method: 'DELETE', body, signal, resource: { kind: 'address_group', id }, decodeResult: (value) => deleted(value, id) })
  }
  move(selection: AddressSelection[], groupID: string | null, signal?: AbortSignal): Promise<ControlResult<AddressMetadata[]>> {
    const body = input(() => {
      if (!Array.isArray(selection) || selection.length < 1 || selection.length > 1000) throw new ContractError('selection')
      const items = selection.map((item) => ({ id: decodeIdentifier(item.id), expected_revision: decodeIdentifier(item.expected_revision) }))
      if (new Set(items.map((item) => item.id)).size !== items.length) throw new ContractError('selection')
      return { selection: items, group_id: addressNullableID(groupID) }
    })
    return this.client.json('/addresses/move', { method: 'POST', body, signal, decodeResult: (value) => {
      const items = array(value, decodeAddress)
      const expected = new Set(body.selection.map((item) => item.id))
      if (items.length !== expected.size || items.some((item) => !expected.delete(item.id))) throw new ContractError('selection')
      return items
    } })
  }
  purge(id: string, value: AddressPurge, signal?: AbortSignal): Promise<ControlResult<AddressOperation>> {
    id = input(() => decodeIdentifier(id))
    const body = input(() => ({ expected_revision: decodeIdentifier(value.expected_revision), confirm_address: addressText(value.confirm_address), operation_key: operationKey(value.operation_key) }))
    return this.client.json('/addresses/' + id + '/purge', { method: 'POST', body, signal, requestKey: body.operation_key, resource: { kind: 'address', id }, decodeResult: (value) => this.purgeResult(value, id, body.operation_key) })
  }
  queryPurge(id: string, key: string, signal?: AbortSignal): Promise<ControlResult<AddressOperation>> {
    id = input(() => decodeIdentifier(id)); key = input(() => operationKey(key))
    return this.client.json('/addresses/' + id + '/purges/' + key, { signal, decodeResult: (value) => this.purgeResult(value, id, key) })
  }
  async queryUnknownResource(error: unknown, signal?: AbortSignal): Promise<ControlResult<AddressMetadata> | undefined> {
    if (!(error instanceof ControlError) || error.outcome !== 'unknown' || error.resource?.kind !== 'address') return undefined
    return this.get(error.resource.id, signal)
  }
  private purgeResult(value: unknown, id: string, key: string): AddressOperation {
    const result = decodeAddressOperation(value)
    if (result.address_id !== id || result.operation_key !== key || result.kind !== 'purge') throw new ContractError('purge_identity')
    return result
  }
}

export interface AddressListSnapshot {
  readonly phase: 'idle' | 'loading' | 'ready' | 'error'
  readonly page?: AddressPage
  readonly error?: ControlError
}
export class AddressListModel {
  private readonly reads = new RequestSequence()
  private state: AddressListSnapshot = Object.freeze({ phase: 'idle' })
  private readonly addresses: AddressesModel
  private readonly onChange?: (value: AddressListSnapshot) => void
  constructor(addresses: AddressesModel, onChange?: (value: AddressListSnapshot) => void) { this.addresses = addresses; this.onChange = onChange }
  get snapshot(): AddressListSnapshot { return this.state }
  async load(query: AddressListQuery = {}, signal?: AbortSignal): Promise<{ applied: false } | { applied: true; response: ControlResult<AddressPage> }> {
    const ticket = this.reads.start()
    const requestSignal = signal ? AbortSignal.any([ticket.signal, signal]) : ticket.signal
    const previous: AddressListSnapshot = this.state.phase === 'loading'
      ? this.state.page ? { phase: 'ready', page: this.state.page } : { phase: 'idle' }
      : this.state
    this.publish({ phase: 'loading', page: previous.page })
    try {
      const response = await this.addresses.list(query, requestSignal)
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) { this.publish(previous); return { applied: false } }
      this.publish({ phase: 'ready', page: response.result })
      return { applied: true, response }
    } catch (error) {
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) { this.publish(previous); return { applied: false } }
      this.publish({ phase: 'error', page: previous.page, error: error instanceof ControlError ? error : new ControlError('invalid_response', 'invalid_addresses', 'The address list could not be verified.') })
      throw error
    } finally { ticket.finish() }
  }
  cancel(): void {
    this.reads.cancel()
    if (this.state.phase === 'loading') this.publish(this.state.page ? { phase: 'ready', page: this.state.page } : { phase: 'idle' })
  }
  private publish(value: AddressListSnapshot): void { this.state = Object.freeze(value); this.onChange?.(this.state) }
}
