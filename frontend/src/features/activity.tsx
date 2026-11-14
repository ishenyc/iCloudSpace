import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { useControl } from '../lib/control'
import { useResource } from '../lib/hooks'
import type { EventsModel } from '../control/events'
import type { AuditRecord, EventLevel, RuntimeEvent, RuntimeEventsPage, RuntimeEventsQuery, RuntimeStream } from '../control/event-contracts'
import type { AccountPage } from '../control/contracts'
import type { SyncEvent, SyncProgress } from '../control/sync-contracts'
import { TableTransition } from '../components/table-transition'
import { TablePlaceholder } from '../components/table-placeholder'
import { RefreshButton } from '../components/refresh-button'
import { RefreshRegion } from '../components/refresh-region'
import { useWindowTable } from '../components/use-window-table'
import { AnimatedSection } from '../lib/motion'
import { Alert, Badge, Button, CopyButton, Field, Input, Loading, Modal, PageHeader, Pagination, Panel, Select, Switch, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui'
import { formatMailTime } from '../mail/display'
import { runtimeStage, runtimeStageLabel, runtimeMessage, terminalRuntimeEvent } from '../control/event-presentation'

type Log = RuntimeEvent & { stream: RuntimeStream; generation: string | null; record_key: string; synchronization?: SyncProgress }
type RuntimeWindow = Omit<RuntimeEventsPage, 'items'> & { items: Log[] }
type Column<T> = { label: string; width: number; render: (row: T) => ReactNode }
const pageSizes = [20, 50, 100, 500, 1000, 0]
const time = (value: string) => formatMailTime(value)
const tone = (level: string): 'danger' | 'warning' | 'neutral' => level === 'error' ? 'danger' : level === 'warn' ? 'warning' : 'neutral'
const levels: Record<string, string> = { debug: '调试', info: '信息', warn: '警告', error: '错误' }
const phases: Record<string, string> = {
  directory: '同步隐私邮箱目录', mail: '同步邮件', finalize: '写入同步结果', resolve: '核对同步结果',
  round_queued: '本轮已排队', round_succeeded: '本轮完成', round_degraded: '本轮完成，目录存在警告', round_failed: '本轮最终失败',
  round_cancelled: '本轮已取消', round_superseded: '本轮已被替代', round_unknown: '本轮结果待核对',
  attempt_failed: '本次尝试失败', attempt_unknown: '本次尝试结果待核对', attempt_completed: '本次尝试完成',
  segment_pending: '继续下一批邮件', directory_degraded: '目录同步存在警告', admission_failed: '等待同步资源',
  creation_claimed: '开始自动创建', creation_confirmed: '自动创建完成', creation_not_created: '本次未创建',
  creation_rate_cooldown: '远端限流，进入冷却', creation_paused: '自动创建已暂停',
}
const actionLabels: Record<string, string> = {
  'management.session_issued': '登录后台', 'management.logout': '退出登录', 'management.credential_changed': '修改登录密码',
  'account.created': '创建主号', 'account.updated': '更新主号', 'account.deleted': '删除主号',
  'local_cleanup.source_delete': '退休主号并清理本地数据', 'local_cleanup.address_purge': '清理本地归档邮箱',
  'address.created': '创建邮箱', 'address.random_created': '随机创建邮箱', 'address.updated': '更新邮箱', 'address.deleted': '删除邮箱', 'address.archived': '归档邮箱', 'address.moved': '移动邮箱',
  'group.created': '创建分组', 'group.renamed': '修改分组', 'group.deleted': '删除分组',
  'credentials.issue': '发行邮箱凭据', 'credentials.supplement': '补全邮箱凭据', 'credentials.rotate_api_key': '轮换 API Key',
  'credentials.rotate_bundle': '轮换整套凭据', 'credentials.rotate_all': '轮换全部凭据', 'credentials.rotation_cancelled': '取消待处理轮换',
}
const resourceLabels: Record<string, string> = { operator: '管理员', source: '主号', address: '邮箱', address_group: '邮箱分组', installation: '当前安装', credential_rotation: '凭据轮换', address_set: '邮箱集合' }
function auditActionLabel(row: AuditRecord): string {
  if (row.action === 'credential_export') return ({ authorized: '授权凭据导出', prepared: '准备凭据导出', failed: '凭据导出失败' } as Record<string, string>)[row.fields.operation_kind?.split('.')[0]] || '导出邮箱凭据'
  return actionLabels[row.action] || row.action
}
const sourceLabel = (log: Log) => log.synchronization ? 'synchronization' : log.fields.component || (log.stream === 'history' ? '历史记录' : 'system')
const stageLabel = (log: Log) => runtimeStageLabel(log) || phases[log.phase] || log.phase
const attributesText = (fields: Record<string, string>) => Object.entries(fields).map(([key, value]) => key + ': ' + value).join('\n')

const logRowKey = (row: { id: string }) => row.id
function LogTable<T extends { id: string }>({ rows, columns, loading }: { rows: T[]; columns: Column<T>[]; loading: boolean }) {
  const { body, virtualized, virtualizer, items, paddingTop, paddingBottom } = useWindowTable({ rows, rowKey: logRowKey, rowHeight: 60, overscan: 10 })
  const minWidth = columns.reduce((total, column) => total + column.width, 0)
  return <div className="table-wrap log-table" role="region" aria-label="日志列表，可横向滚动" tabIndex={0} aria-busy={loading}>
    <Table className="data-table" containerClassName="overflow-visible" aria-rowcount={rows.length + 1} style={{ tableLayout: 'fixed', minWidth, width: '100%' }}>
      <colgroup>{columns.map(column => <col key={column.label} style={{ width: column.width }} />)}</colgroup>
      <TableHeader><TableRow>{columns.map(column => <TableHead key={column.label} scope="col" style={{ width: column.width }}>{column.label}</TableHead>)}</TableRow></TableHeader>
      <TableBody ref={body}>
        {paddingTop > 0 && <TableRow aria-hidden="true"><TableCell colSpan={columns.length} style={{ height: paddingTop, padding: 0, border: 0 }} /></TableRow>}
        {items.map(item => <TableRow key={item.key} ref={virtualized ? virtualizer.measureElement : undefined} data-index={item.index} aria-rowindex={item.index + 2}>{columns.map(column => <TableCell key={column.label} style={{ height: 60 }}>{column.render(rows[item.index])}</TableCell>)}</TableRow>)}
        {paddingBottom > 0 && <TableRow aria-hidden="true"><TableCell colSpan={columns.length} style={{ height: paddingBottom, padding: 0, border: 0 }} /></TableRow>}
      </TableBody>
    </Table>
  </div>
}

export function mergeRuntimeEntries(next: RuntimeEvent[], previous: RuntimeEvent[], limit: number, earliest: string | null = null): RuntimeEvent[] {
  const unique = new Map<string, RuntimeEvent>()
  for (const entry of [...previous, ...next]) if (earliest === null || BigInt(entry.id) >= BigInt(earliest)) unique.set(entry.id, entry)
  return [...unique.values()].sort((a, b) => BigInt(a.id) > BigInt(b.id) ? -1 : BigInt(a.id) < BigInt(b.id) ? 1 : 0).slice(0, limit)
}
function projectRuntime(page: RuntimeEventsPage): RuntimeWindow {
  return { ...page, items: page.items.map(entry => ({ ...entry, stream: page.stream, generation: page.generation, record_key: page.stream + ':' + (page.generation || '') + ':' + entry.id })) }
}
async function readRuntimeWindow(events: EventsModel, options: RuntimeEventsQuery, count: number, signal: AbortSignal): Promise<RuntimeWindow> {
  const maximum = count || 2000
  let first: RuntimeEventsPage | null = null, before = options.before_id, after = options.after_id
  let items: RuntimeEvent[] = [], nextBefore: string | null = null
  const cursors = new Set<string>()
  while (items.length < maximum) {
    const page = (await events.runtime({ ...options, before_id: before, after_id: after, limit: Math.min(200, maximum - items.length) }, signal)).result
    if (first && (first.stream !== page.stream || first.generation !== page.generation)) throw new Error('日志进程已变化，请刷新最新记录。')
    first ??= page
    items = mergeRuntimeEntries(page.items, items, maximum, page.earliest_id)
    nextBefore = page.next_before_id
    if (!nextBefore || cursors.has(nextBefore)) break
    cursors.add(nextBefore); before = nextBefore; after = undefined
  }
  if (!first) throw new Error('日志响应不可用。')
  return projectRuntime({ ...first, items, next_before_id: nextBefore })
}
function syncLog(event: SyncEvent, stream: RuntimeStream, generation: string | null): Log {
  const p = event.progress
  return { id: event.sequence, occurred_at: event.at, level: event.level, source_id: p.source.source_id, round_key: p.round_id,
    attempt: 0, phase: event.name, outcome: event.outcome || p.state, error_code: p.error_code,
    message: (phases[event.name] || event.name) + ' · ' + (phases[p.phase] || p.phase),
    fields: { attempts: p.attempts, failed_attempts: p.failed_attempts, retries: p.retries, segments: p.segments, discovered: p.counters.discovered, archived: p.counters.archived, links: p.counters.links, bytes: p.counters.bytes },
    stream, generation, record_key: 'synchronization:' + p.round_id + ':' + event.sequence, synchronization: p }
}
function instantOrder(value: string): bigint {
  const fraction = /\.(\d{1,9})(?:Z|[+-]\d{2}:\d{2})$/.exec(value)?.[1] || ''
  return BigInt(Date.parse(value)) * 1000000n + BigInt(fraction.padEnd(9, '0').slice(3) || '0')
}
function chronological(logs: Log[]): Log[] {
  return [...new Map(logs.map(entry => [entry.record_key, entry])).values()].sort((a, b) => {
    const left = instantOrder(a.occurred_at), right = instantOrder(b.occurred_at)
    if (left !== right) return left < right ? -1 : 1
    const sameSequence = a.synchronization && b.synchronization && a.round_key === b.round_key
      || !a.synchronization && !b.synchronization && a.stream === b.stream && a.generation === b.generation
    if (sameSequence && a.id !== b.id) return BigInt(a.id) < BigInt(b.id) ? -1 : 1
    return a.record_key.localeCompare(b.record_key)
  })
}
function diagnosticPairs(log: Log) {
  return [
    ...(log.error_code ? [{ label: '诊断码', value: log.error_code }] : []),
    ...(log.synchronization?.directory_error_code ? [{ label: '目录诊断码', value: log.synchronization.directory_error_code }] : []),
    ...(log.attempt ? [{ label: '本次尝试', value: String(log.attempt) }] : []),
    ...Object.entries(log.fields).map(([key, value]) => ({ label: ({ attempts: '尝试次数', failed_attempts: '失败尝试', retries: '重试次数', segments: '批次数', duration_ms: '耗时（毫秒）', request_id: '请求编号' } as Record<string, string>)[key] || key, value })),
  ]
}
function entryText(log: Log) {
  return ['[' + time(log.occurred_at) + '] ' + log.level.toUpperCase() + ' · ' + sourceLabel(log),
    '步骤: ' + stageLabel(log), '消息: ' + runtimeMessage(log), log.source_id ? '主号: #' + log.source_id : '',
    log.round_key ? '流程编号: ' + log.round_key : '', '状态: ' + log.outcome,
    ...diagnosticPairs(log).map(pair => pair.label + ': ' + pair.value)].filter(Boolean).join('\n')
}
function terminal(log: Log | undefined) {
  return !!log && (log.synchronization?.state === 'finished' || terminalRuntimeEvent(log))
}

export function RuntimeLogDialog({ log, onClose }: { log: Log | null; onClose: () => void }) {
  const { events, synchronization } = useControl()
  const runId = log?.round_key || '', creation = !!log && runtimeStage(log).startsWith('creation_')
  const flow = useResource(async signal => {
    if (!log || !runId) return { items: [] as Log[], partial: false, warning: null as unknown }
    const runtime = readRuntimeWindow(events, { stream: log.stream, round_key: runId, ...(log.source_id ? { source_id: log.source_id } : {}) }, 0, signal)
    const progress = log.source_id && /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/.test(runId)
      ? synchronization.events(log.source_id, { round_id: runId }, signal) : Promise.resolve(null)
    const [retained, current] = await Promise.allSettled([runtime, progress])
    if (retained.status === 'rejected' && current.status === 'rejected') throw retained.reason
    const changedGeneration = retained.status === 'fulfilled' && log.stream === 'live' && retained.value.generation !== log.generation
    const runtimeItems = retained.status === 'fulfilled' && !changedGeneration ? retained.value.items : []
    const sync = current.status === 'fulfilled' ? current.value?.result ?? null : null
    return { items: [...runtimeItems, ...(sync?.items.map(event => syncLog(event, log.stream, log.generation)) || [])],
      partial: changedGeneration || retained.status === 'rejected' || current.status === 'rejected' || retained.status === 'fulfilled' && (retained.value.evicted || retained.value.next_before_id !== null) || sync !== null && sync.lost !== '0',
      warning: changedGeneration ? new Error('原日志进程已变化，当前窗口不能补全旧流程。') : retained.status === 'rejected' ? retained.reason : current.status === 'rejected' ? current.reason : null }
  }, [log?.record_key, runId, log?.source_id, log?.stream])
  const ordered = useMemo(() => chronological([...(flow.data?.items || []), ...(log ? [log] : [])]), [flow.data, log])
  const partial = !!runId && (flow.data?.partial || !ordered.some(entry => runtimeStage(entry) === 'round_queued' || runtimeStage(entry) === 'creation_claimed'))
  const copyValue = runId ? [creation ? '自动创建流程' : '运行流程', '流程编号: ' + runId, '仅包含当前保留窗口中的记录。', ...ordered.map(entryText)].join('\n\n') : log ? entryText(log) : ''
  return <Modal open={!!log} onOpenChange={open => { if (!open) onClose() }} title={runId ? creation ? '自动创建流程' : '邮件同步流程' : '日志详情'} description={runId ? ordered.length + ' 条流程记录' : '查看消息、请求编号和诊断上下文。'} wide>
    {log && <div className="stack">
      <div className="toolbar"><Badge tone={tone(log.level)}>{levels[log.level]}</Badge><span className="text-muted">{time(log.occurred_at)}</span><span className="mono">{sourceLabel(log)}</span><CopyButton value={copyValue} label={runId ? '复制流程记录' : '复制日志'} /></div>
      <div className="detail-grid"><div><small className="text-muted">主号</small><div>{log.source_id ? <Link className="text-link" to={'/accounts/' + log.source_id}>主号 #{log.source_id}</Link> : '系统'}</div></div><div><small className="text-muted">{runId ? '流程编号' : '请求编号'}</small><div className="mono" style={{ overflowWrap: 'anywhere' }}>{runId || log.fields.request_id || '-'}</div></div></div>
      {runId ? <>
        {flow.loading && !flow.manualRefreshing && <Loading label="正在加载当前窗口中的流程记录…" />}
        {flow.error && <><Alert error={flow.error} /><p className="text-muted">目前仅展示已取得的记录，不能据此推断任务的最终状态。</p><RefreshButton variant="outline" pending={flow.loading || flow.manualRefreshing} onRefresh={flow.refresh}>重新加载流程</RefreshButton></>}
        {flow.data?.warning != null && <Alert error={flow.data.warning}>仅展示已取得的流程记录，请刷新后继续核对。</Alert>}
        <RefreshRegion loading={flow.manualRefreshing} label="正在刷新流程记录…"><div className="stack">
          {!flow.loading && !flow.error && partial && <Alert tone="warning">当前流程记录不完整，较早记录可能已被保留窗口覆盖。任务结果以主号状态和操作记录为准。</Alert>}
          {!flow.loading && !flow.error && !ordered.some(entry => terminal(entry)) && <Alert tone="info">当前窗口尚无本轮结束记录；某次尝试失败不代表本轮最终失败。刷新流程查看后续状态。</Alert>}
          <ol className="stack" style={{ listStyle: 'none', padding: 0, margin: 0 }}>{ordered.map(entry => <li key={entry.record_key} style={{ borderLeft: '2px solid var(--border)', padding: '4px 0 14px 18px' }}>
            <div className="toolbar"><Badge tone={tone(entry.level)}>{stageLabel(entry)}</Badge><time className="text-muted">{time(entry.occurred_at)}</time>{entry.synchronization && <span className="text-muted">第 {entry.synchronization.segments} 批 · {entry.synchronization.trigger === 'automatic' ? '自动同步' : entry.synchronization.trigger === 'manual' ? '手动同步' : '公开读取触发'}</span>}</div>
            <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{runtimeMessage(entry)}</p>
            <p className="text-muted mono">{sourceLabel(entry)}{entry.fields.request_id ? ' · ' + entry.fields.request_id : ''}</p>
            {entry.error_code && <Alert tone="danger">诊断码：{entry.error_code}</Alert>}
            {diagnosticPairs(entry).length > 0 && <dl className="detail-grid">{diagnosticPairs(entry).map(pair => <div key={pair.label}><dt className="text-muted">{pair.label}</dt><dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{pair.value}</dd></div>)}</dl>}
            {entry.synchronization && <details><summary className="text-link">步骤上下文</summary><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(entry.synchronization, null, 2)}</pre></details>}
          </li>)}</ol>
        </div></RefreshRegion>
        <div><RefreshButton variant="outline" pending={flow.loading || flow.manualRefreshing} onRefresh={flow.refresh}>刷新流程</RefreshButton></div>
      </> : <>
        <p style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{runtimeMessage(log)}</p>
        {diagnosticPairs(log).length > 0 && <dl className="detail-grid">{diagnosticPairs(log).map(pair => <div key={pair.label}><dt className="text-muted">{pair.label}</dt><dd style={{ margin: 0 }}>{pair.value}</dd></div>)}</dl>}
        {attributesText(log.fields) && <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{attributesText(log.fields)}</pre>}
      </>}
    </div>}
  </Modal>
}

function RuntimeLogs() {
  const { events, accounts: accountModel } = useControl()
  const [params, setParams] = useSearchParams()
  const rawLevel = params.get('level') || ''
  const level = ['debug', 'info', 'warn', 'error'].includes(rawLevel) ? rawLevel as EventLevel : undefined
  const sourceID = params.get('source_id') || params.get('account_id') || ''
  const query = params.get('query') || '', roundKey = params.get('round_key') || params.get('sync_run_id') || params.get('auto_create_run_id') || ''
  const stream: RuntimeStream = params.get('stream') === 'history' ? 'history' : 'live'
  const [keyword, setKeyword] = useState(query), [roundSearch, setRoundSearch] = useState(roundKey), [accountSearch, setAccountSearch] = useState('')
  const [size, setSize] = useState(20), [autoRefresh, setAutoRefresh] = useState(true), [selected, setSelected] = useState<Log | null>(null)
  const key = JSON.stringify([level, sourceID, query, roundKey, stream, size])
  const [cursorState, setCursorState] = useState<{ key: string; pages: string[] }>({ key, pages: [''] })
  const cursors = cursorState.key === key ? cursorState.pages : [''], beforeID = cursors[cursors.length - 1]
  const latest = useRef<{ key: string; value: RuntimeWindow } | null>(null)
  const generation = useRef<{ key: string; value: string | null } | null>(null)
  const [generationNotice, setGenerationNotice] = useState(false)
  useEffect(() => { setKeyword(query); setRoundSearch(roundKey) }, [query, roundKey])
  const accounts = useResource<AccountPage>(async signal => (await accountModel.list({ query: accountSearch, page_size: 50 }, signal)).result, [accountSearch])
  const logs = useResource<RuntimeWindow>(async signal => {
    const filter: RuntimeEventsQuery = { stream, ...(level ? { level } : {}), ...(sourceID ? { source_id: sourceID } : {}), ...(query ? { query } : {}), ...(roundKey ? { round_key: roundKey } : {}) }
    const cached = !beforeID && stream === 'live' && latest.current?.key === key ? latest.current.value : null
    let value = await readRuntimeWindow(events, { ...filter, ...(beforeID ? { before_id: beforeID } : cached?.items[0] ? { after_id: cached.items[0].id } : {}) }, size, signal)
    if (cached && value.generation !== cached.generation) value = await readRuntimeWindow(events, filter, size, signal)
    else if (cached) {
      const maximum = size || 2000
      const items = mergeRuntimeEntries(value.items, cached.items, maximum, value.earliest_id)
      const next = value.total > items.length && items.length ? items[items.length - 1].id : null
      value = { ...value, items: projectRuntime({ ...value, items }).items, after_id: null, next_before_id: next }
    }
    if (!signal.aborted && !beforeID) latest.current = { key, value }
    return value
  }, [key, beforeID], { poll: autoRefresh && stream === 'live' && !beforeID && !selected, keepPreviousData: true, initialLoadingFeedback: true })
  useEffect(() => {
    if (!logs.data || logs.stale || stream !== 'live') return
    const previous = generation.current
    if (previous?.key === key && previous.value !== logs.data.generation) { setGenerationNotice(true); setCursorState({ key, pages: [''] }) }
    generation.current = { key, value: logs.data.generation }
  }, [logs.data, logs.stale, key, stream])
  const rows = logs.data?.items || [], accountOptions = accounts.data?.items || []
  function changeFilter(name: string, value: string) {
    const next = new URLSearchParams(params)
    if (name === 'source_id') next.delete('account_id')
    if (name === 'round_key') { next.delete('sync_run_id'); next.delete('auto_create_run_id') }
    value ? next.set(name, value) : next.delete(name)
    setGenerationNotice(false); setSelected(null); setParams(next, { replace: true })
  }
  function search(event: FormEvent) {
    event.preventDefault()
    const next = new URLSearchParams(params)
    keyword.trim() ? next.set('query', keyword.trim()) : next.delete('query')
    roundSearch.trim() ? next.set('round_key', roundSearch.trim()) : next.delete('round_key')
    next.delete('sync_run_id'); next.delete('auto_create_run_id')
    setSelected(null); setGenerationNotice(false); setParams(next, { replace: true })
  }
  function refreshLatest() { latest.current = null; if (beforeID) setCursorState({ key, pages: [''] }); else return logs.refresh() }
  const columns: Column<Log>[] = [
    { label: '时间', width: 172, render: row => <time className="text-muted" dateTime={row.occurred_at}>{time(row.occurred_at)}</time> },
    { label: '级别', width: 90, render: row => <Badge tone={tone(row.level)}>{levels[row.level]}</Badge> },
    { label: '来源 / 主号', width: 250, render: row => <div className="log-source"><span className="mono" title={sourceLabel(row)}>{sourceLabel(row)}</span>{row.source_id && <small className="text-muted">主号 #{row.source_id}</small>}</div> },
    { label: '消息', width: 390, render: row => <Button variant="link" className="log-message h-auto max-w-full justify-start overflow-hidden p-0 text-left font-normal" title={runtimeMessage(row)} onClick={() => setSelected(row)}><span className="truncate">{runtimeMessage(row) || '查看日志详情'}</span></Button> },
    { label: '详情', width: 110, render: row => <Button variant="secondary" size="sm" onClick={() => setSelected(row)}>{row.round_key ? '查看流程' : '详情'}</Button> },
  ]
  return <div className="stack">
    <Panel title="运行日志" description="查看当前进程与保留历史中的同步、自动创建和请求诊断。" actions={<RefreshButton variant="outline" pending={logs.loading || logs.manualRefreshing} onRefresh={refreshLatest}>刷新最新</RefreshButton>}>
      <form className="stack" onSubmit={search}>
        <div className="toolbar" style={{ alignItems: 'end' }}>
          <Field label="级别"><Select aria-label="日志级别" value={level || ''} onChange={e => changeFilter('level', e.target.value)}><option value="">全部级别</option><option value="debug">调试</option><option value="info">信息</option><option value="warn">警告</option><option value="error">错误</option></Select></Field>
          <Field label="主号"><Select aria-label="筛选主号" value={sourceID} onChange={e => changeFilter('source_id', e.target.value)}><option value="">全部主号</option>{sourceID && !accountOptions.some(account => account.id === sourceID) && <option value={sourceID}>主号 #{sourceID}</option>}{accountOptions.map(account => <option key={account.id} value={account.id}>{account.display_name || account.address_namespace} · #{account.id}</option>)}</Select></Field>
          <Field label="查找主号"><Input aria-label="查找日志主号" placeholder="名称或邮箱" value={accountSearch} maxLength={200} onChange={e => setAccountSearch(e.target.value)} /></Field>
          <Field label="关键词"><Input aria-label="日志关键词" placeholder="搜索消息和上下文" maxLength={200} value={keyword} onChange={e => setKeyword(e.target.value)} /></Field>
          <Button type="submit" variant="outline"><Search size={14} />筛选</Button>
          {(level || sourceID || query || roundKey) && <Button type="button" variant="ghost" onClick={() => { setKeyword(''); setRoundSearch(''); setAccountSearch(''); setParams(stream === 'history' ? { stream } : {}, { replace: true }) }}>重置</Button>}
        </div>
        <div className="toolbar" style={{ alignItems: 'end' }}>
          <Field label="日志范围"><Select aria-label="日志范围" value={stream} onChange={e => changeFilter('stream', e.target.value)}><option value="live">当前进程</option><option value="history">保留历史</option></Select></Field>
          <Field label="流程编号"><Input aria-label="日志流程编号" placeholder="按原流程编号筛选" value={roundSearch} maxLength={128} onChange={e => setRoundSearch(e.target.value)} /></Field>
          <label className="checkbox-label"><Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />自动刷新最新页</label><span className="text-muted">{beforeID ? '浏览历史页时自动刷新暂停' : stream === 'history' ? '保留历史使用独立编号，不与当前进程合并。' : '进程重启或窗口覆盖会使旧记录不可用。'}</span>
        </div>
        {roundKey && <div className="notice mono">已限定流程：{roundKey}</div>}
      </form>
    </Panel>
    {generationNotice && <Alert tone="info">服务进程已变化，已切换到新的日志窗口。</Alert>}
    {accounts.error && <Alert error={accounts.error}>主号选项加载失败，仍可使用当前主号筛选。</Alert>}
    {logs.error && <Alert error={logs.error} />}
    <TableTransition dataKey={logs.dataKey} stale={logs.stale} pending={logs.loading} refreshing={logs.refreshing} manualRefreshing={logs.manualRefreshing} initialLoadingVisible={logs.initialLoadingVisible} label="正在更新运行日志">
      {rows.length ? <LogTable rows={rows} columns={columns} loading={logs.loading} /> : <TablePlaceholder columns={columns} loading={logs.loading} rowHeight={60} label="正在加载日志" title={logs.error ? '日志暂不可用' : '暂无匹配日志'} description="调整筛选条件，或等待新的运行记录。" action={<RefreshButton variant="secondary" pending={logs.loading || logs.manualRefreshing} onRefresh={refreshLatest}>重新加载</RefreshButton>} />}
    </TableTransition>
    <div className="toolbar" style={{ justifyContent: 'space-between' }}>
      <span className="text-muted">本页 {rows.length} 条{size === 0 ? ' · 最多显示 2,000 条' : ' · 第 ' + cursors.length + ' 页'}</span>
      <div className="row-actions"><Select aria-label="运行日志每页条数" value={size} onChange={e => setSize(Number(e.target.value))}>{pageSizes.map(value => <option key={value} value={value}>{value ? value + ' 条/页' : '当前窗口全部'}</option>)}</Select>
        <Button variant="outline" size="sm" disabled={logs.loading || logs.stale || cursors.length === 1 || size === 0} onClick={() => setCursorState({ key, pages: cursors.slice(0, -1) })}><ChevronLeft size={14} />上一页</Button>
        <Button variant="outline" size="sm" disabled={logs.loading || logs.stale || !logs.data?.next_before_id || size === 0 || cursors.includes(logs.data.next_before_id)} onClick={() => setCursorState({ key, pages: [...cursors, logs.data!.next_before_id!] })}>更早记录<ChevronRight size={14} /></Button>
      </div>
    </div>
    <RuntimeLogDialog log={selected} onClose={() => setSelected(null)} />
  </div>
}

async function readAuditWindow(events: EventsModel, page: number, size: number, signal: AbortSignal) {
  if (size > 0 && size <= 100) return { ...(await events.audits({ page, page_size: size }, signal)).result, changed: false }
  const start = size ? (page - 1) * size : 0
  let serverPage = Math.floor(start / 100) + 1, total = 0, changed = false, initialTotal: number | null = null
  const items = new Map<string, AuditRecord>()
  while (!signal.aborted) {
    const current = (await events.audits({ page: serverPage, page_size: 100 }, signal)).result
    initialTotal ??= current.total
    total = current.total; changed ||= total !== initialTotal
    for (const item of current.items) { if (items.has(item.id)) changed = true; items.set(item.id, item) }
    if (!current.items.length || size && items.size >= size || serverPage * 100 >= total) break
    serverPage++
  }
  return { items: [...items.values()].sort((a, b) => BigInt(a.id) > BigInt(b.id) ? -1 : BigInt(a.id) < BigInt(b.id) ? 1 : 0).slice(0, size || undefined), total, page, page_size: size, changed }
}
function AuditLogs() {
  const { events } = useControl()
  const [page, setPage] = useState(1), [size, setSize] = useState(20)
  const logs = useResource(async signal => readAuditWindow(events, page, size, signal), [page, size], { keepPreviousData: true, initialLoadingFeedback: true })
  const rows = logs.data?.items || [], total = size === 0 ? rows.length : logs.data?.total || 0
  useEffect(() => { if (!logs.loading && !logs.stale && logs.data && size > 0 && page > Math.max(1, Math.ceil(total / size))) setPage(Math.max(1, Math.ceil(total / size))) }, [logs.loading, logs.stale, logs.data, total, page, size])
  const columns: Column<AuditRecord>[] = [
    { label: '时间', width: 172, render: row => <time className="text-muted" dateTime={row.occurred_at}>{time(row.occurred_at)}</time> },
    { label: '管理员', width: 140, render: row => <span className="log-source">{row.actor_display}</span> },
    { label: '操作', width: 160, render: row => <strong>{auditActionLabel(row)}</strong> },
    { label: '对象', width: 140, render: row => row.resource_kind === 'address_set' ? ({ filter: '筛选结果', selection: '选中邮箱' } as Record<string, string>)[row.resource_ref] || '邮箱集合' : (resourceLabels[row.resource_kind] || row.resource_kind) + (row.resource_ref ? ' #' + row.resource_ref : '') },
    { label: '结果', width: 100, render: row => <Badge tone={row.outcome === 'success' ? 'success' : row.outcome === 'failure' || row.outcome === 'rejected' ? 'danger' : 'neutral'}>{({ success: '成功', failure: '失败', rejected: '已拒绝', unknown: '未确认' } as Record<string, string>)[row.outcome]}</Badge> },
    { label: '请求编号', width: 260, render: row => <span className="log-source mono" title={row.fields.request_id || row.correlation_key}>{row.fields.request_id || row.correlation_key || '-'}</span> },
    { label: '复制', width: 92, render: row => <CopyButton value={['时间: ' + time(row.occurred_at), '管理员: ' + row.actor_display, '操作: ' + row.action, '对象: ' + row.resource_kind + ' ' + row.resource_ref, '结果: ' + row.outcome, '来源: ' + row.origin, '关联编号: ' + row.correlation_key, row.detail, attributesText(row.fields)].join('\n')} label="复制" /> },
  ]
  return <div className="stack">
    <Panel title="操作记录" description="持久保存的后台登录、配置变更与敏感导出记录。导出授权和材料准备不代表客户端已收到文件；记录不包含密码、完整 Key 或邮件内容。" actions={<RefreshButton variant="outline" pending={logs.loading || logs.manualRefreshing} onRefresh={logs.refresh}>刷新</RefreshButton>}>{null}</Panel>
    {logs.error && <Alert error={logs.error} />}
    {logs.data?.changed && <Alert tone="info">读取期间操作记录发生变化，当前结果已去重。请刷新核对最新记录。</Alert>}
    <TableTransition dataKey={logs.dataKey} stale={logs.stale} pending={logs.loading} refreshing={logs.refreshing} manualRefreshing={logs.manualRefreshing} initialLoadingVisible={logs.initialLoadingVisible} label="正在更新操作记录">
      {rows.length ? <LogTable rows={rows} columns={columns} loading={logs.loading} /> : <TablePlaceholder columns={columns} loading={logs.loading} rowHeight={60} label="正在加载操作记录" title={logs.error ? '操作记录暂不可用' : '暂无操作记录'} description="新的登录和配置操作会显示在这里。" action={logs.error ? <RefreshButton variant="secondary" pending={logs.loading || logs.manualRefreshing} onRefresh={logs.refresh}>重新加载</RefreshButton> : undefined} />}
    </TableTransition>
    <Pagination page={page} size={size} total={total} disabled={logs.stale} onPage={setPage} onSize={value => { setPage(1); setSize(value) }} />
  </div>
}

export function ActivityPage() {
  const [params, setParams] = useSearchParams()
  const [animateTabs, setAnimateTabs] = useState(false)
  useEffect(() => { setAnimateTabs(true) }, [])
  const audit = params.get('tab') === 'audit'
  function switchTab(next: 'runtime' | 'audit') {
    const values = new URLSearchParams(params)
    next === 'audit' ? values.set('tab', 'audit') : values.delete('tab')
    setParams(values)
  }
  return <div className="stack">
    <PageHeader eyebrow="WORKSPACE" title="活动与日志" description="查看服务运行情况，追踪同步流程和后台操作。" />
    <Tabs value={audit ? 'audit' : 'runtime'} onValueChange={value => switchTab(value as 'runtime' | 'audit')} className="gap-5">
      <TabsList aria-label="活动类型"><TabsTrigger value="runtime">运行日志</TabsTrigger><TabsTrigger value="audit">操作记录</TabsTrigger></TabsList>
      <TabsContent value="runtime"><AnimatedSection enter={animateTabs}><RuntimeLogs /></AnimatedSection></TabsContent>
      <TabsContent value="audit"><AnimatedSection enter={animateTabs}><AuditLogs /></AnimatedSection></TabsContent>
    </Tabs>
  </div>
}
