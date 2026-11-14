import { ControlClient, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { decodeSynchronization, decodeSyncEvents, decodeSyncStatistics, decodeSyncWake, decodeSyncBatch, syncObject, syncRoundID, syncSequence } from './sync-contracts.ts'
import type { Synchronization, SyncEvents, SyncEventsQuery, SyncStatistics, SyncWake, SyncBatch } from './sync-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_synchronization_input', { outcome: 'not_sent' }) }
}

/** Reads never wake work. An explicit manual wake sends one command and returns
 * admission metadata; transport uncertainty requires a caller-directed read. */
export class SynchronizationModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }
  get(sourceID: string, signal?: AbortSignal): Promise<ControlResult<Synchronization>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    return this.client.json(this.base(sourceID), { signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const decoded = decodeSynchronization(value)
      if (decoded.source_id !== sourceID) throw new ContractError('sync_source')
      return decoded
    } })
  }
  wake(sourceID: string, signal?: AbortSignal): Promise<ControlResult<SyncWake>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    return this.client.json(this.base(sourceID), { method: 'POST', body: {}, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const decoded = decodeSyncWake(value)
      if (decoded.source_id !== sourceID) throw new ContractError('sync_source')
      return decoded
    } })
  }
  statistics(signal?: AbortSignal): Promise<ControlResult<SyncStatistics>> {
    return this.client.json('/synchronization-statistics', { signal, decodeResult: decodeSyncStatistics })
  }
  progress(sourceIDs: readonly string[], signal?: AbortSignal): Promise<ControlResult<SyncBatch>> {
    const ids=input(()=>{
      if(!Array.isArray(sourceIDs)||sourceIDs.length<1||sourceIDs.length>1000)throw new ContractError('sync_batch')
      const ids=sourceIDs.map(value=>decodeIdentifier(value))
      if(new Set(ids).size!==ids.length)throw new ContractError('sync_batch')
      return ids
    })
    const search=new URLSearchParams();for(const id of ids)search.append('source_id',id)
    return this.client.json('/synchronization/progress',{search,signal,decodeResult:value=>{
      const decoded=decodeSyncBatch(value)
      if(decoded.items.length!==ids.length||decoded.items.some((item,index)=>item.source_id!==ids[index]))throw new ContractError('sync_batch_scope')
      return decoded
    }})
  }
  events(sourceID: string, query: SyncEventsQuery = {}, signal?: AbortSignal): Promise<ControlResult<SyncEvents>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const search = input(() => {
      const data = syncObject(query)
      return { after_sequence: data.after_sequence === undefined ? '0' : syncSequence(data.after_sequence),
        ...(data.round_id === undefined ? {} : { round_id: syncRoundID(data.round_id) }) }
    })
    return this.client.json(this.base(sourceID) + '/events', { search, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const decoded = decodeSyncEvents(value)
      if (decoded.source_id !== sourceID || decoded.after_sequence !== search.after_sequence || decoded.round_id !== (search.round_id ?? null)) throw new ContractError('sync_event_scope')
      return decoded
    } })
  }
  private base(sourceID: string): string { return '/accounts/' + sourceID + '/synchronization' }
}
