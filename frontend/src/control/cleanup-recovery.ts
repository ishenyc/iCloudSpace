import { parseCleanupRecovery, serializeCleanupRecovery } from './local-cleanup-contracts.ts'
import type { LocalCleanupRecovery } from './local-cleanup-contracts.ts'
import { handoffEntryReference, mergeReferenceLists, previousControlBase } from './entry-handoff.ts'
import type { ClientStateStorage } from './client-state-handoff.ts'

export interface CleanupStorage { getItem(key: string): string | null; setItem(key: string, value: string): void }
export interface CleanupRecoverySnapshot { records: LocalCleanupRecovery[]; error: Error | null }

/** Only original request identifiers are durable. Saving must succeed before
 * sending: a lost response must remain queryable after navigation or reload. */
export class CleanupRecoveryLedger {
  private readonly key: string
  private readonly storage: CleanupStorage
  private readonly basePath: string
  constructor(storage: CleanupStorage, basePath: string) {
    this.storage = storage
    this.basePath = basePath
    this.key = 'icloudspace:local-cleanup:v1:' + basePath
  }
  read(): LocalCleanupRecovery[] {
    const state=this.inspect()
    if(state.error)throw state.error
    return state.records
  }
  inspect(): CleanupRecoverySnapshot {
    const records:LocalCleanupRecovery[]=[],raws=new Map<string,string>()
    let error:Error|null=null
    const retain=(raw:string)=>{
      const rows:unknown=JSON.parse(raw)
      if(!Array.isArray(rows))throw new Error('本地清理恢复记录格式错误；请保留记录并检查存储。')
      const seen=new Set<string>()
      for(const row of rows){
        const value=parseCleanupRecovery(JSON.stringify(row)),exact=serializeCleanupRecovery(value)
        if(seen.has(value.operation_key))throw new Error('本地清理恢复记录存在重复标识。')
        seen.add(value.operation_key)
        if(!records.some(prior=>serializeCleanupRecovery(prior)===exact))records.push(value)
      }
    }
    const previous = previousControlBase(this.basePath)
    const old=previous?'icloudspace:local-cleanup:v1:'+previous:undefined
    for(const key of [this.key,...(old?[old]:[])])try{const raw=this.storage.getItem(key);if(raw!==null){raws.set(key,raw);retain(raw)}}catch(e){error??=e instanceof Error?e:new Error('无法读取本地清理原引用。')}
    if(old && raws.has(old) && !error)try{handoffEntryReference(this.storage as ClientStateStorage,old,this.key,raw=>{retain(raw);return raw},mergeReferenceLists)}catch(e){error??=e instanceof Error?e:new Error('无法交接本地清理原引用。')}
    return {records,error}
  }
  remember(recovery: LocalCleanupRecovery): void {
    recovery = parseCleanupRecovery(serializeCleanupRecovery(recovery))
    const rows = this.read(), old = rows.find(row => row.operation_key === recovery.operation_key)
    if (old) {
      if (serializeCleanupRecovery(old) !== serializeCleanupRecovery(recovery)) throw new Error('本地清理请求标识冲突。')
      return
    }
    const raw=JSON.stringify([...rows,recovery])
    this.storage.setItem(this.key,raw)
    if(this.storage.getItem(this.key)!==raw)throw new Error('无法确认本地清理原引用已保存，尚未提交删除。')
  }
  forget(recovery: LocalCleanupRecovery): void {
    const exact = serializeCleanupRecovery(recovery)
    this.storage.setItem(this.key, JSON.stringify(this.read().filter(row => serializeCleanupRecovery(row) !== exact)))
  }
}
