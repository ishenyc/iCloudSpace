import { useEffect, useRef, useState } from 'react'
import { useControl } from '../lib/control'
import { CleanupRecoveryLedger } from '../control/cleanup-recovery'
import { decodeLocalCleanupReceipt } from '../control/local-cleanup-contracts'
import type { LocalCleanupReceipt, LocalCleanupRecovery } from '../control/local-cleanup-contracts'
import { ControlError } from '../transport'
import { Alert, Button, Field, Input, Modal } from '../components/ui'

const updated = 'icloudspace:local-cleanup-updated'
function notify(receipt?: LocalCleanupReceipt) { window.dispatchEvent(new CustomEvent(updated, { detail: receipt })) }
function ledger(basePath: string) { return new CleanupRecoveryLedger(window.localStorage, basePath) }
const cleanupReferenceKey=(value:Pick<LocalCleanupRecovery,'kind'|'source_id'|'address_id'|'operation_key'>)=>[value.kind,value.source_id,value.address_id||'',value.operation_key].join(':')
function cleanupDetails(receipt: LocalCleanupReceipt): string {
  const counts = receipt.counts
  return `正文总计 ${counts.objects}，待处理 ${counts.pending}，已回收 ${counts.collected}，原已不存在 ${counts.absent}，仍被其他邮箱引用 ${counts.shared}，受保护 ${counts.protected}，待核对 ${counts.needs_review}。未领取凭据 ${counts.unacknowledged}，未决操作 ${counts.unresolved_operations}。`
}
function description(receipt: LocalCleanupReceipt): string {
  const state = { retired: '已停止访问，正在准备本地清理。', cleaning: '正在清理已确认的本地正文。', blocked: '仍有待确认或无法验证的内容，清理尚未完成。', complete: '本地清理已完成。' }[receipt.state]
  return state
}

/** Stays above route changes so a retired source's original request can still
 * be queried even after it disappears from ordinary source/address lists. */
export function LocalCleanupStatus() {
  const control = useControl()
  const [tasks, setTasks] = useState<LocalCleanupRecovery[]>([])
  const [receipts, setReceipts] = useState<Record<string, LocalCleanupReceipt>>({})
  const [error, setError] = useState<unknown>(null), [busy, setBusy] = useState('')
  useEffect(() => {
    const refresh = (event?: Event) => {
      try {
        const state=ledger(control.basePath).inspect();setTasks(state.records); setError(state.error)
        const value = (event as CustomEvent<unknown> | undefined)?.detail
        if (value) { const receipt = decodeLocalCleanupReceipt(value); setReceipts(old => ({ ...old, [cleanupReferenceKey(receipt)]: receipt })) }
      } catch (e) { setError(e) }
    }
    refresh(); window.addEventListener(updated, refresh); window.addEventListener('storage', refresh)
    return () => { window.removeEventListener(updated, refresh); window.removeEventListener('storage', refresh) }
  }, [control.basePath])
  async function query(task: LocalCleanupRecovery) {
    if (busy) return
    setBusy(task.operation_key); setError(null)
    try { const receipt = (await control.localCleanup.query(task)).result; setReceipts(old => ({ ...old, [cleanupReferenceKey(task)]: receipt })) }
    catch (e) { setError(e) } finally { setBusy('') }
  }
  if (!tasks.length && !error) return null
  return <div className="stack mb-5" aria-label="本地清理进度">
    {!!error && <Alert error={error} />}
    {tasks.map(task => {
      const receipt = receipts[cleanupReferenceKey(task)]
      return <Alert key={cleanupReferenceKey(task)} tone={receipt?.state === 'complete' ? 'info' : 'warning'}><div className="stack" style={{ gap: 8 }}><strong>{task.kind === 'source_delete' ? '主号已申请本地删除' : '邮箱已申请本地清理'}</strong><span>{receipt ? description(receipt) : '原请求尚未核对。仅查询该请求，不会再次提交删除。'}</span><details className="operation-details"><summary>清理详情与原请求编号</summary>{receipt && <p>{cleanupDetails(receipt)}</p>}<code>{task.operation_key}</code></details><div className="row-actions"><Button size="sm" variant="outline" disabled={!!busy} loading={busy === task.operation_key} loadingLabel="正在核对…" onClick={() => void query(task)}>查询原请求</Button>{receipt?.state === 'complete' && <Button size="sm" variant="ghost" onClick={() => { try { ledger(control.basePath).forget(task); notify() } catch (e) { setError(e) } }}>关闭提示</Button>}</div></div></Alert>
    })}
  </div>
}

export function LocalCleanupDialog({ sourceID, addressID = null, revision, confirmation, historical = false, onClose, onAccepted }: {
  sourceID: string; addressID?: string | null; revision: string; confirmation: string; historical?: boolean; onClose: () => void; onAccepted: (receipt: LocalCleanupReceipt) => void
}) {
  const control = useControl(), lock = useRef(false)
  const [text, setText] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(null)
  const [recovery, setRecovery] = useState<LocalCleanupRecovery | null>(null)
  const [receipt, setReceipt] = useState<LocalCleanupReceipt | null>(null)
  const mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  function accepted(value: LocalCleanupReceipt) { notify(value); if (mounted.current) { setReceipt(value); onAccepted(value) } }
  async function submit() {
    if (lock.current || recovery || text !== confirmation) return
    lock.current = true; setBusy(true); setError(null)
    const original: LocalCleanupRecovery = { version: 1, kind: addressID === null ? 'source_delete' : 'address_purge', source_id: sourceID, address_id: addressID, operation_key: crypto.randomUUID() }
    let saved = false
    try {
      ledger(control.basePath).remember(original); saved = true; setRecovery(original); notify()
      const command = { operation_key: original.operation_key, expected_revision: revision, confirmation: text }
      const result = addressID === null ? await control.localCleanup.retireSource(sourceID, command) : await control.localCleanup.purgeAddress(sourceID, addressID, command)
      accepted(result.result)
    } catch (e) {
      if (saved && e instanceof ControlError && e.outcome === 'not_sent') {
        try { ledger(control.basePath).forget(original); notify(); if (mounted.current) setRecovery(null) } catch { /* Keep the original query identity when storage cannot be updated. */ }
      }
      if (mounted.current) setError(e)
    } finally { lock.current = false; if (mounted.current) setBusy(false) }
  }
  async function query() {
    if (lock.current || !recovery) return
    lock.current = true; setBusy(true); setError(null)
    try { accepted((await control.localCleanup.query(recovery)).result) } catch (e) { if (mounted.current) setError(e) }
    finally { lock.current = false; if (mounted.current) setBusy(false) }
  }
  return <Modal open onOpenChange={open => { if (!open && !busy) onClose() }} title={addressID === null ? '删除主号及本地数据' : historical ? '清理历史已移除邮箱' : '清理本地归档邮箱'} description={confirmation} footer={<><Button variant="outline" disabled={busy} onClick={onClose}>关闭</Button>{recovery ? <Button variant="secondary" disabled={busy} loading={busy} loadingLabel="正在核对…" onClick={() => void query()}>查询原请求</Button> : <Button variant="destructive" disabled={busy || text !== confirmation} loading={busy} loadingLabel="正在处理…" onClick={() => void submit()}>确认本地删除</Button>}</>}><div className="stack"><Alert tone="warning">{addressID === null ? '停止主号及所属邮箱的访问，撤销取件权限，并清理可证明归属的本地正文。不会删除 Apple 账号或远端邮箱。' : historical ? '清理这个已移除邮箱的本地内容，保持原删除状态，不恢复邮箱。其他邮箱仍引用的正文继续保留。' : '清理这个已归档邮箱的本地邮件内容，不向 Apple 发起操作。其他邮箱仍引用的正文继续保留。'} 未领取凭据、消费、UID 和未决请求的必要事实保留；受保护或证据不完整的内容会明确显示为未完成。</Alert>{receipt ? <Alert>{description(receipt)}<details className="operation-details"><summary>查看清理明细</summary>{cleanupDetails(receipt)}</details></Alert> : recovery ? <Alert tone="warning">请查询原请求确认结果。关闭页面后仍可在清理进度提示中查询，不会重发删除。</Alert> : <Field label={`输入完整${addressID === null ? '主号命名空间' : '邮箱地址'}确认`}><Input value={text} onChange={event => setText(event.target.value)} autoComplete="off" /></Field>}{!!error && <Alert error={error} attention="focus" />}</div></Modal>
}
