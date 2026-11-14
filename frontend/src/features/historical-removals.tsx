import { useState } from 'react'
import { useControl } from '../lib/control'
import { useResource } from '../lib/hooks'
import type { HistoricalRemoval } from '../control/address-contracts'
import { Alert, Button, Empty, Input, Loading } from '../components/ui'
import { RefreshButton } from '../components/refresh-button'
import { LocalCleanupDialog } from './local-cleanup'
import { formatAliasTime } from './aliases/model'

export function HistoricalRemovals({ sourceID }: { sourceID: string }) {
  const [open,setOpen]=useState(false)
  return <details className="detail-section" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary>历史已移除邮箱的本地清理</summary>
    {open&&<HistoricalRemovalList sourceID={sourceID}/>}
  </details>
}

function HistoricalRemovalList({ sourceID }: { sourceID:string }) {
  const control=useControl(),[query,setQuery]=useState(''),[page,setPage]=useState(1)
  const [selected,setSelected]=useState<HistoricalRemoval|null>(null)
  const rows=useResource(signal=>control.addresses.historicalRemovals({...sourceID?{source_id:sourceID}:{},query,page,page_size:20},signal).then(value=>value.result),[sourceID,query,page],{poll:false,keepPreviousData:true})
  return <div className="stack mt-4">
    <p className="text-muted">以下邮箱已从列表移除，但尚未申请本地内容清理。它们保持已删除状态；查看此列表不会恢复邮箱或开始清理。</p>
    <div className="toolbar"><Input aria-label="搜索历史已移除邮箱" placeholder="搜索邮箱地址或备注" value={query} onChange={event=>{setQuery(event.target.value);setPage(1)}}/><RefreshButton variant="secondary" pending={rows.refreshing} onRefresh={rows.refresh}>刷新</RefreshButton></div>
    {rows.error&&<Alert error={rows.error}/>}
    {!rows.data&&rows.loading?<Loading label="正在读取历史已移除邮箱"/>:rows.data?.items.length?<>
      <ul className="stack">{rows.data.items.map(item=><li key={item.id} className="detail-section">
        <div className="detail-section-heading"><strong className="break-all">{item.address}</strong><Button variant="destructive" size="sm" disabled={rows.stale} onClick={()=>setSelected(item)}>清理本地数据</Button></div>
        <p className="text-muted">{item.source_label} · 原移除时间：{formatAliasTime(item.deleted_at,true)}</p>
      </li>)}</ul>
      <div className="pagination"><span>共 {rows.data.total} 条历史记录</span><div className="row-actions"><Button variant="secondary" size="sm" disabled={rows.stale||page===1} onClick={()=>setPage(page-1)}>上一页</Button><Button variant="secondary" size="sm" disabled={rows.stale||page*20>=rows.data.total} onClick={()=>setPage(page+1)}>下一页</Button></div></div>
    </>:!rows.error&&<Empty compact title="没有待清理的历史已移除邮箱" description="已经申请清理的对象继续通过原清理进度查询。"/>}
    {selected&&<LocalCleanupDialog sourceID={selected.source_id} addressID={selected.id} revision={selected.revision} confirmation={selected.address} historical onClose={()=>setSelected(null)} onAccepted={()=>{void rows.refresh()}}/>}
  </div>
}
