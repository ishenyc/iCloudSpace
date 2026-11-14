import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, Navigate, useSearchParams } from 'react-router-dom'
import { Copy, Download, Eye, EyeOff, FolderCog, KeyRound, Mail, RotateCcw, Trash2, Search, Send } from 'lucide-react'
import { useControl, useControlSession } from '../lib/control'
import { LocalCleanupDialog } from './local-cleanup'
import { HistoricalRemovals } from './historical-removals'
import { useResource } from '../lib/hooks'
import { Alert, Badge, Button, Checkbox, CopyButton, Empty, Field, Input, Modal, PageHeader, Pagination, Select, Sheet, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, useErrorFeedback, useToast } from '../components/ui'
import { VirtualTable } from '../components/virtual-table'
import { TableTransition } from '../components/table-transition'
import { TablePlaceholder } from '../components/table-placeholder'
import { RefreshButton } from '../components/refresh-button'
import { MailComposer } from './mail-compose'
import { MailViewer } from './mail-view'
import { AnimatePresence, AnimatedSection } from '../lib/motion'
import { aliasAccess, aliasViewArchiveFilter, legacyAliasArchivePath, confirmedAliasDeletion } from './alias-archive'
import type { AliasView } from './alias-archive'
import { AliasArchiveNotice } from './alias-archive-notice'
import { AliasActions, aliasFilter, credentialLabel, formatAliasTime, loadAliasRows, saveAliasDownload } from './aliases/model'
import type { AliasRows, AliasRotationKind, PendingAliasAction } from './aliases/model'
import type { AddressMetadata as Alias, AddressGroup as Group } from '../control/address-contracts'
import type { Account } from '../control/contracts'
import type { CredentialBundle } from '../control/credential-contracts'
import type { CredentialExportKind, CredentialExportFormat } from '../control/credential-exports'
import type { CredentialCopyFormat } from '../control/credential-copy'
import { credentialCopyURL } from '../control/credential-copy'
import { copyText } from '../lib/clipboard'

const notifyAliases = (sourceID?: string) => window.dispatchEvent(new CustomEvent('icloudspace:aliases-changed', { detail: { accountId: sourceID } }))
const notifyGroups = () => window.dispatchEvent(new Event('icloudspace:groups'))
const sourceLabel = (source: Account) => source.kind === 'custom' ? '@' + source.address_suffix : source.apple?.apple_id || source.address_namespace

function AliasStatus({ alias }: { alias: Alias }) {
  if (alias.lifecycle === 'archived') return <Badge tone="neutral">已归档</Badge>
  if (alias.lifecycle === 'pending') return <Badge tone="warning">等待目录确认</Badge>
  if (alias.lifecycle === 'deletion_pending') return <Badge tone="warning">删除状态待核对</Badge>
  if (!alias.enabled) return <Badge tone="neutral">已停用</Badge>
  if (['error', 'failed'].includes(alias.last_sync_state)) return <Badge tone="danger">同步异常</Badge>
  if (['ok', 'success', 'synced'].includes(alias.last_sync_state)) return <Badge tone="success">同步正常</Badge>
  return <Badge tone="neutral">{alias.last_sync_state === 'syncing' ? '同步中' : '已启用'}</Badge>
}
export function AliasesPage({ view = 'current' }: { view?: AliasView }) {
  const [params] = useSearchParams(), legacyPath = legacyAliasArchivePath(params)
  return legacyPath ? <Navigate replace to={legacyPath} /> : <AliasList view={view} />
}

export function AliasList({ accountId, embedded = false, view = 'current' }: { accountId?: string; embedded?: boolean; view?: AliasView }) {
  const control = useControl(), session = useControlSession(), toast = useToast(), reportError = useErrorFeedback()
  const [params, setParams] = useSearchParams(), groupId = params.get('groupId') || '', archiveValue = aliasViewArchiveFilter(view)
  const archived = view === 'archived'
  const [selectedAccount, setSelectedAccount] = useState(() => params.get('sourceId') || ''), [selectedAccountOption, setSelectedAccountOption] = useState<Account | null>(null)
  const scope = accountId || selectedAccount, interactionScope = JSON.stringify([scope, view]), scopeRef = useRef(interactionScope); scopeRef.current = interactionScope
  const [queryDraft, setQueryDraft] = useState(''), [query, setQuery] = useState(''), [withoutMail, setWithoutMail] = useState(false), [size, setSize] = useState(20)
  const filterKey = JSON.stringify([scope, query, groupId, withoutMail, archiveValue, size]), filterRef = useRef(filterKey); filterRef.current = filterKey
  const [pagination, setPagination] = useState({ key: filterKey, page: 1 }), page = pagination.key === filterKey ? pagination.page : 1
  const setPage = (value: number) => setPagination({ key: filterKey, page: value })
  const filters = { source: scope, group: groupId, query, withoutMail, archive: archiveValue }
  const actions = useMemo(() => {
    const key = 'space.aliases.operations.v1:' + control.basePath + ':' + (session.operator?.id || 'unresolved')
    try { return new AliasActions(control, { key, storage: window.sessionStorage }) } catch { return new AliasActions(control, { key, storage: { getItem() { throw new Error() }, setItem() { throw new Error() } } }) }
  }, [control, session.operator?.id])
  const [selection, setSelection] = useState<Set<string>>(new Set()), [busy, setBusy] = useState(''), busyRef = useRef(false)
  const [actionError, setActionError] = useState<unknown>(null), [, operationChanged] = useState(0)
  const [groupManager, setGroupManager] = useState(false), [moveTarget, setMoveTarget] = useState('')
  const [credentialAlias, setCredentialAlias] = useState<Alias | null>(null), [composeAlias, setComposeAlias] = useState<Alias | null>(null), [mailAlias, setMailAlias] = useState<Alias | null>(null)
  const [confirmation, setConfirmation] = useState<{ kind: 'rotate' | 'delete'; alias: Alias } | null>(null), [deleteText, setDeleteText] = useState('')
  const [rotationKind, setRotationKind] = useState<AliasRotationKind>('bundle')
  const [exportChoice, setExportChoice] = useState<{ kind: CredentialExportKind; ids?: string[] } | null>(null), [exportFormat, setExportFormat] = useState<CredentialExportFormat>('jsonl')
  const exportAbort = useRef<AbortController | null>(null)
  const [accountSearch, setAccountSearch] = useState(''), [accountQuery, setAccountQuery] = useState(''), [showAccountSearch, setShowAccountSearch] = useState(false)
  const groups = useResource<Group[]>(async signal => (await control.addresses.groups(signal)).result, [], { poll: false })
  const accounts = useResource(async signal => (await control.accounts.list({ page: 1, page_size: 50, query: accountQuery }, signal)).result, [accountQuery], { poll: false })
  const rows = useResource<AliasRows>(signal => loadAliasRows(control.addresses, aliasFilter(filters), page, size, signal), [scope, query, groupId, withoutMail, archiveValue, page, size], { poll: true, keepPreviousData: true, initialLoadingFeedback: true })
  const aliases = rows.data?.items || [], total = rows.data?.total || 0, blocked = !!busy || rows.stale
  const selected = useMemo(() => rows.stale ? [] : aliases.filter(row => selection.has(row.id)), [aliases, selection, rows.stale])
  const allSelected = !rows.stale && aliases.length > 0 && selected.length === aliases.length
  const accountOptions = selectedAccountOption && !accounts.data?.items.some(item => item.id === selectedAccount) ? [selectedAccountOption, ...(accounts.data?.items || [])] : accounts.data?.items || []
  const accountName = (row: Alias) => { if (row.source_label) return row.source_label; const source = accountOptions.find(item => item.id === row.source_id); return source ? sourceLabel(source) : '查看主号' }
  const groupName = (row: Alias) => groups.data?.find(group => group.id === row.group_id)?.name || '未分组'
  const unresolved = actions.pending
  const pendingFor = (row: Alias) => unresolved.some(item => item.addressID === row.id)

  useEffect(() => { if (params.get('manageGroups') === '1') { setGroupManager(true); const next = new URLSearchParams(params); next.delete('manageGroups'); setParams(next, { replace: true }) } }, [params, setParams])
  useEffect(() => { setSelectedAccount(params.get('sourceId') || '') }, [params.get('sourceId')])
  useEffect(() => { setCredentialAlias(null); setComposeAlias(null); setMailAlias(null); setConfirmation(null); setActionError(null) }, [scope, view])
  const previousView = useRef(view)
  useEffect(() => { if (previousView.current !== view) { setGroupManager(false); setShowAccountSearch(false); setMoveTarget(''); previousView.current = view } }, [view])
  useEffect(() => { const timer = setTimeout(() => setAccountQuery(accountSearch.trim()), 220); return () => clearTimeout(timer) }, [accountSearch])
  useEffect(() => { setPagination({ key: filterKey, page: 1 }); setSelection(new Set()); exportAbort.current?.abort(); setExportChoice(null) }, [filterKey])
  useEffect(() => { setSelection(new Set()) }, [page])
  useEffect(() => () => exportAbort.current?.abort(), [])
  useEffect(() => { if (rows.stale) return; if (rows.data && size > 0 && page > Math.max(1, Math.ceil(total / size))) setPage(Math.max(1, Math.ceil(total / size))); const ids = new Set(aliases.map(row => row.id)); setSelection(current => new Set([...current].filter(id => ids.has(id)))) }, [rows.data, rows.stale])
  useEffect(() => {
    const changed = (event: Event) => { const source = (event as CustomEvent<{ accountId?: string }>).detail?.accountId; if (!scope || !source || scope === source) { void rows.refresh(); void groups.refresh() } }
    const groupChanged = () => { void groups.refresh() }
    window.addEventListener('icloudspace:aliases-changed', changed); window.addEventListener('icloudspace:groups', groupChanged)
    return () => { window.removeEventListener('icloudspace:aliases-changed', changed); window.removeEventListener('icloudspace:groups', groupChanged) }
  }, [scope, rows.refresh, groups.refresh])
  function changeGroup(value: string) { const next = new URLSearchParams(params); value ? next.set('groupId', value) : next.delete('groupId'); setParams(next) }
  function resetFilters() { const next = new URLSearchParams(params); next.delete('archived'); next.delete('groupId'); next.delete('sourceId'); setParams(next); setQueryDraft(''); setQuery(''); setSelectedAccount(''); setWithoutMail(false); setPage(1) }
  function changed(sourceID?: string) { notifyAliases(sourceID || scope); notifyGroups() }
  async function run(key: string, action: () => Promise<void>, feedback: 'action' | 'read' = 'action') {
    if (busyRef.current) return
    const originalScope = interactionScope
    busyRef.current = true; setBusy(key); setActionError(null)
    try { await action() } catch (error) { if (scopeRef.current === originalScope) reportError(error, confirmation || exportChoice ? 'form' : feedback, setActionError) } finally { busyRef.current = false; setBusy(''); operationChanged(value => value + 1) }
  }
  function moveAliases(items: Alias[], group: string) { if (!items.length) return; void run('move', async () => { await control.addresses.move(items.map(row => ({ id: row.id, expected_revision: row.revision })), group === 'none' || !group ? null : group); setMoveTarget(''); setSelection(new Set()); changed(); toast(`已更新 ${items.length} 个邮箱的分组。`, 'success') }) }
  function toggleAlias(row: Alias) { if (!aliasAccess(row).canToggle) return; void run('toggle-' + row.id, async () => { await control.addresses.patch(row.id, { expected_revision: row.revision, enabled: !row.enabled }); changed(row.source_id); toast(row.enabled ? '邮箱已停用。' : '邮箱已启用。', 'success') }) }
  function queryOperation(operation: PendingAliasAction) { void run('query-' + operation.key, async () => { const state = await actions.query(operation); changed(operation.sourceID); toast(['confirmed', 'committed'].includes(state) ? '原请求已确认。' : `原请求状态：${state}；没有重复提交。`, ['confirmed', 'committed'].includes(state) ? 'success' : 'info') }) }
  function confirmMutation() {
    if (!confirmation) return
    const { alias, kind } = confirmation, originalScope = interactionScope
    if (kind === 'delete' && !confirmedAliasDeletion(alias.address, deleteText)) return
    void run(kind + '-' + alias.id, async () => {
      if (kind === 'rotate') {
        const result = await actions.rotate(alias, rotationKind)
        changed(alias.source_id)
        if (result.state === 'committed') toast(rotationKind === 'bundle' ? '整套凭证已轮换，新交付保持待确认。' : 'API Key 已轮换，独立 IMAP/OAuth 凭据保持原值。', 'success')
        else toast(result.state === 'cancelled' ? '原轮换请求已取消。' : '轮换尚未确认，请查询原请求；不会重复提交。', 'info')
      }
      else { const result = await actions.remove(alias, deleteText.trim()); changed(alias.source_id); if ('operation' in result && result.operation.state !== 'confirmed') toast('删除尚未确认，请查询原请求；不会自动重放。', 'info'); else toast(alias.kind === 'apple' && alias.lifecycle !== 'archived' ? '远端删除已确认，地址已归档，历史记录保留。' : '本地邮箱已归档并撤销访问，历史内容保留，可在归档页单独清理。', 'success'); if (credentialAlias?.id === alias.id) setCredentialAlias(null) }
      if (scopeRef.current === originalScope) { setConfirmation(null); setDeleteText('') }
    }, 'read')
  }
  function exportCredentials() {
    if (!exportChoice) return
    const choice = exportChoice, originalFilter = filterKey
    void run('export-' + choice.kind, async () => { exportAbort.current?.abort(); const controller = new AbortController(); exportAbort.current = controller; const download = await actions.export(choice.kind, exportFormat, aliasFilter(filters), choice.ids, controller.signal); if (controller.signal.aborted || filterRef.current !== originalFilter) return; saveAliasDownload(download); setExportChoice(null); toast(`已完整导出 ${download.count} 个邮箱的${choice.kind === 'api_key' ? ' API' : ' IMAP/OAuth'}凭证，未确认任何交付。`, 'success') })
  }
  function copyAliases(format: CredentialCopyFormat, ids?: string[]) {
    const originalFilter = filterKey
    void run('copy-' + format, async () => {
      exportAbort.current?.abort(); const controller = new AbortController(); exportAbort.current = controller
      const result = await control.credentialExports.copy(format, ids ? { selected_ids: ids } : { filter: aliasFilter(filters) }, window.location.origin, controller.signal)
      if (controller.signal.aborted || filterRef.current !== originalFilter) return
      if (!result.count) { toast('没有可复制的完整凭据；已跳过权限受限、归档和等待目录确认的邮箱。', 'info'); return }
      await copyText(result.text)
      const skipped = (ids?.length ?? total) - result.count
      toast(`已复制${ids ? '' : '当前筛选下'} ${result.count} 个邮箱的${format === 'otp' ? '取码' : 'IMAP/OAuth'}格式${skipped > 0 ? `，已跳过 ${skipped} 个无完整凭据的邮箱` : ''}。`, 'success')
    })
  }
  const hasFilters = !!(query || groupId || scope || withoutMail)
  const emptyTitle = archived ? hasFilters ? '没有匹配的归档邮箱' : '暂无归档邮箱' : hasFilters ? '没有匹配的邮箱' : '还没有邮箱'
  const emptyDescription = hasFilters ? '调整筛选条件，或重置当前视图的筛选后重试。' : archived ? '邮箱归档后会显示在这里，并保留已有历史邮件。' : '在主号详情中登记邮箱、同步 Apple 目录或生成自定义地址。'
  const listActions = <>
    <Button variant="secondary" size={embedded ? 'sm' : undefined} onClick={() => setGroupManager(true)}><FolderCog size={15} />管理分组</Button>
    {!archived && <><Button variant="secondary" size={embedded ? 'sm' : undefined} disabled={blocked || !total} onClick={() => setExportChoice({ kind: 'api_key' })}><Download size={15} />全部 API</Button><Button variant="secondary" size={embedded ? 'sm' : undefined} disabled={blocked || !total} onClick={() => setExportChoice({ kind: 'mailbox' })}>全部 IMAP</Button></>}
    <RefreshButton variant="secondary" size={embedded ? 'sm' : undefined} pending={rows.loading || rows.manualRefreshing} onRefresh={rows.refresh}>刷新</RefreshButton>
  </>
  const columns: { key: string; label: ReactNode; width?: number; render: (row: Alias) => ReactNode }[] = [
    { key: 'select', label: <Checkbox disabled={rows.stale || !aliases.length} checked={allSelected ? true : selected.length ? 'indeterminate' : false} aria-label="勾选当前显示的邮箱" onCheckedChange={checked => setSelection(checked === true ? new Set(aliases.map(row => row.id)) : new Set())} />, width: 44, render: row => <Checkbox aria-label={`勾选 ${row.address}`} disabled={rows.stale} checked={selection.has(row.id)} onCheckedChange={checked => setSelection(current => { const next = new Set(current); checked === true ? next.add(row.id) : next.delete(row.id); return next })} /> },
    { key: 'address', label: '邮箱 / 用途', width: 220, render: row => <div><Button variant="link" className="mailbox-address-link" type="button" disabled={rows.stale} title={row.address} aria-label={`查看 ${row.address} 的${aliasAccess(row).archived ? '归档详情' : '详情与凭证'}`} onClick={() => setCredentialAlias(row)}><span className={`mailbox-address-text${aliasAccess(row).archived ? ' text-muted-foreground' : ''}`}>{row.address}</span></Button><div className="text-muted mailbox-purpose" title={row.label}>{row.label || '未填写用途备注'}</div>{row.registration_banned && <Badge tone="danger">注册账户封禁</Badge>}</div> },
    ...(!embedded ? [{ key: 'account', label: '所属主号', width: 170, render: (row: Alias) => <Link className="text-link" title={accountName(row)} style={{ display: 'block', maxWidth: 142, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} to={`/accounts/${row.source_id}`}>{accountName(row)}</Link> }] : []),
    { key: 'group', label: '分组', width: 154, render: row => <Select className="w-[126px] text-xs data-[size=default]:h-8" title={groupName(row)} aria-label={`${row.address} 的分组`} value={row.group_id || ''} disabled={blocked} onChange={event => moveAliases([row], event.target.value)}><option value="">未分组</option>{(groups.data || []).map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</Select> },
    { key: archived ? 'archivedAt' : 'lastAccessed', label: archived ? '归档时间 / 原因' : '最近调用 / 最新邮件', width: 160, render: row => <div style={{ whiteSpace: 'nowrap' }}><span>{formatAliasTime(archived ? row.archive_notice?.archived_at : row.last_accessed_at)}</span><div className="text-muted">{archived ? row.archive_notice?.reason === 'remote_missing' ? '目录已无此地址' : '保留历史归档' : formatAliasTime(row.latest_received_at)}</div></div> },
    { key: 'status', label: '状态', width: 120, render: row => <div className="stack" style={{ gap: 5 }}><AliasStatus alias={row} /><span className="text-muted" style={{ whiteSpace: 'nowrap' }}>{aliasAccess(row).archived ? '接入已停用' : credentialLabel(row)}</span></div> },
    { key: 'actions', label: '操作', width: 196, render: row => <div className="row-actions" style={{ gap: 4 }}>{!aliasAccess(row).archived && <Button size="sm" variant="secondary" className="text-xs" title={`复制 ${row.address} 的取码格式`} disabled={blocked || !aliasAccess(row).canExport || row.credential_profile === 'legacy_latest'} onClick={() => copyAliases('otp', [row.id])}>取码</Button>}<Button size="sm" variant="secondary" className="text-xs" disabled={rows.stale || !aliasAccess(row).canReceive} onClick={() => setMailAlias(row)}>{aliasAccess(row).archived ? '历史邮件' : '邮件'}</Button>{!aliasAccess(row).archived && <Button size="icon-sm" variant="secondary" title={`从 ${row.address} 发信`} aria-label={`从 ${row.address} 发信`} disabled={blocked || !aliasAccess(row).canSend} onClick={() => setComposeAlias(row)}><Send size={14} /></Button>}<Button size="icon-sm" variant="secondary" title={`管理 ${row.address}`} aria-label={`管理 ${row.address}`} disabled={rows.stale} onClick={() => setCredentialAlias(row)}><KeyRound size={15} /></Button></div> },
  ]
  return <section className="stack">
    {!embedded ? <PageHeader title={archived ? '归档邮箱' : '邮箱'} eyebrow={archived ? 'ARCHIVE' : 'MAILBOXES'} description={archived ? '查看归档地址的历史邮件并整理分组。接入凭据与发信已停用；历史记录继续保留。' : '管理当前隐私地址、分组与接入凭证。已归档地址可从归档邮箱入口查看。'} actions={listActions} /> : <div className="toolbar alias-inline-toolbar">{listActions}</div>}
    {!archived && <div className="toolbar" aria-label="复制邮箱接入格式"><Button variant="secondary" size="sm" disabled={blocked || !total} onClick={() => copyAliases('otp')}><Copy size={14} />全部取码</Button><Button variant="secondary" size="sm" disabled={blocked || !total} onClick={() => copyAliases('imap')}>全部 IMAP/OAuth</Button>{selected.length > 0 && <><span className="text-muted">已选 {selected.length} 项</span><Button variant="outline" size="sm" disabled={blocked} onClick={() => copyAliases('otp', selected.map(row => row.id))}>复制选中取码</Button><Button variant="outline" size="sm" disabled={blocked} onClick={() => copyAliases('imap', selected.map(row => row.id))}>复制选中 IMAP</Button></>}</div>}
    <div><form className="toolbar" style={{ alignItems: 'flex-end' }} role="search" onSubmit={event => { event.preventDefault(); const next = queryDraft.trim(); setQuery(next); setPage(1); if (next === query && page === 1) void rows.refresh() }}>
      <Field label="邮箱或用途备注"><Input style={{ width: 220, minWidth: 160, maxWidth: '100%' }} value={queryDraft} maxLength={200} placeholder="搜索邮箱地址或用途" onChange={event => setQueryDraft(event.target.value)} /></Field>
      {!accountId && <Field label="所属主号"><div style={{ display: 'flex', alignItems: 'center', gap: 5 }}><Select style={{ width: 175, minWidth: 0, maxWidth: '100%' }} value={selectedAccount} onChange={event => { setSelectedAccount(event.target.value); setSelectedAccountOption(accountOptions.find(item => item.id === event.target.value) || null) }}><option value="">全部主号</option>{accountOptions.map(account => <option key={account.id} value={account.id}>{sourceLabel(account)}{account.display_name ? ` · ${account.display_name}` : ''}</option>)}</Select><Button variant="secondary" size="icon" type="button" title="搜索更多主号" aria-label="搜索更多主号" aria-expanded={showAccountSearch} onClick={() => setShowAccountSearch(!showAccountSearch)}><Search size={14} /></Button></div></Field>}
      <Field label="分组"><Select style={{ minWidth: 0, width: 140 }} value={groupId} onChange={event => changeGroup(event.target.value)}><option value="">全部分组</option><option value="none">未分组</option>{(groups.data || []).map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</Select></Field>
      <Field label="邮件"><Select style={{ minWidth: 0, width: 125 }} value={withoutMail ? 'none' : ''} onChange={event => setWithoutMail(event.target.value === 'none')}><option value="">全部</option><option value="none">{archived ? '无历史邮件' : '无邮件'}</option></Select></Field>
      <Button type="submit" variant="secondary"><Search size={15} />查询</Button><Button type="button" variant="secondary" onClick={resetFilters}>重置</Button>
    </form><AnimatePresence initial={false}>{showAccountSearch && !accountId && <AnimatedSection key="account-search" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} style={{ overflow: 'hidden', maxWidth: 360 }}><div style={{ paddingTop: 14 }}><Field label="检索主号" description="从服务端搜索主号，每次最多显示 50 个匹配项。"><Input value={accountSearch} placeholder="主号邮箱或名称" onChange={event => setAccountSearch(event.target.value)} /></Field></div></AnimatedSection>}</AnimatePresence></div>
    {(rows.error || groups.error || accounts.error || actionError && !confirmation && !credentialAlias && !exportChoice) && <Alert error={!confirmation && !credentialAlias && !exportChoice && actionError || rows.error || groups.error || accounts.error} attention={actionError ? "focus" : "notify"} />}
    {actions.recoveryRequired && <Alert tone="warning">本页的待查请求记录暂不可读取或保存。原记录未覆盖；请保留当前页面并检查浏览器存储。</Alert>}
    {unresolved.length > 0 && <div className="notice stack"><span>以下原请求尚未确认；仅查询原标识，不会重复提交。</span>{unresolved.map(operation => <div className="toolbar" key={[operation.kind,operation.sourceID,operation.addressID,operation.key].join(':')}><code className="mono">{operation.key}</code><Button size="sm" variant="secondary" disabled={!!busy} loading={busy === 'query-' + operation.key} loadingLabel="正在查询…" onClick={() => queryOperation(operation)}>查询原请求</Button></div>)}</div>}
    {busy.startsWith('export') && <Alert tone="neutral">正在验证完整导出。只有全部所选凭据及终止记录验证成功后才会保存文件；不会跳过不完整项或确认交付。</Alert>}
    <AnimatePresence initial={false}>{selected.length > 0 && <AnimatedSection key="batch-actions" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} style={{ overflow: 'hidden' }}><div className="notice toolbar"><span>已选择当前显示的 {selected.length} 个邮箱</span>{!archived && <><Button size="sm" variant="outline" disabled={blocked || !selected.every(row => aliasAccess(row).canExport)} onClick={() => setExportChoice({ kind: 'api_key', ids: selected.map(row => row.id) })}>导出 API（{selected.length}）</Button><Button size="sm" variant="outline" disabled={blocked || !selected.every(row => aliasAccess(row).canExportMailbox)} onClick={() => setExportChoice({ kind: 'mailbox', ids: selected.map(row => row.id) })}>导出 IMAP</Button></>}<Select value={moveTarget} aria-label="将勾选邮箱移动到分组" disabled={blocked} onChange={event => { setMoveTarget(event.target.value); if (event.target.value) moveAliases(selected, event.target.value) }}><option value="">移动到分组…</option><option value="none">未分组</option>{(groups.data || []).map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</Select><Button variant="secondary" size="sm" onClick={() => setSelection(new Set())}>清空选择</Button></div></AnimatedSection>}</AnimatePresence>
    <TableTransition dataKey={rows.dataKey} stale={rows.stale} pending={rows.loading} refreshing={rows.refreshing} manualRefreshing={rows.manualRefreshing} initialLoadingVisible={rows.initialLoadingVisible} label="正在更新邮箱列表">
    {rows.loading && !rows.data ? <TablePlaceholder columns={columns} loading rowHeight={88} label="正在读取邮箱…" /> : aliases.length ? <>
      {size === 0 || size > 100 ? <VirtualTable isRowSelected={row => selection.has(row.id)} rows={aliases} columns={columns} rowKey={row => row.id} rowHeight={88} /> : <div className="table-wrap" aria-busy={rows.loading} tabIndex={0} aria-label="邮箱列表，可横向滚动"><Table className="data-table" style={{ minWidth: columns.reduce((width, column) => width + (column.width || 120), 0) }} containerClassName="overflow-visible"><colgroup>{columns.map(column => <col key={column.key} style={{ width: column.width }} />)}</colgroup><TableHeader><TableRow>{columns.map(column => <TableHead key={column.key} scope="col" style={{ width: column.width }}>{column.label}</TableHead>)}</TableRow></TableHeader><TableBody>{aliases.map(row => <TableRow key={row.id} data-state={selection.has(row.id) ? 'selected' : undefined} aria-selected={selection.has(row.id)}>{columns.map(column => <TableCell key={column.key}>{column.render(row)}</TableCell>)}</TableRow>)}</TableBody></Table></div>}
    </> : <TablePlaceholder columns={columns} title={rows.error ? '邮箱暂不可用' : emptyTitle} description={rows.error ? '请重新读取邮箱列表。' : emptyDescription} action={rows.error ? <RefreshButton variant="secondary" pending={rows.loading || rows.manualRefreshing} onRefresh={rows.refresh}>重新加载</RefreshButton> : hasFilters ? <Button variant="secondary" onClick={resetFilters}>重置筛选</Button> : !embedded ? <Link to={archived ? '/aliases' : '/accounts'} className="text-link">{archived ? '查看当前邮箱' : '前往主号'}</Link> : undefined} />}
    </TableTransition>
    <Pagination page={size === 0 ? 1 : page} size={size} total={total} disabled={rows.stale} onPage={setPage} onSize={setSize} />
    {archived&&<HistoricalRemovals key={scope} sourceID={scope}/>}
    {size === 0 && <p className="text-muted">已逐页读取当前筛选下的全部邮箱，并以虚拟表格显示。{!archived && '完整凭据导出仍由服务端重新读取全部筛选集合。'}</p>}
    <GroupManager open={groupManager} onOpenChange={setGroupManager} groups={groups.data || []} refresh={groups.refresh} onDeleted={id => { if (groupId === id) changeGroup('') }} />
    <Modal open={!!exportChoice} onOpenChange={open => { if (!open && !busy) setExportChoice(null) }} title="导出接入凭据" description={exportChoice?.kind === 'mailbox' ? '完整 IMAP/OAuth 长期凭据' : 'API Key 与其实际用途'} footer={<><Button variant="ghost" disabled={!!busy} onClick={() => setExportChoice(null)}>取消</Button><Button disabled={!!busy} onClick={exportCredentials}>{busy ? '验证完整导出…' : '保存完整文件'}</Button></>}><div className="stack"><Field label="格式"><Select value={exportFormat} disabled={!!busy} onChange={event => setExportFormat(event.target.value as CredentialExportFormat)}><option value="jsonl">JSONL</option><option value="csv">CSV</option></Select></Field><p className="section-note">{exportChoice?.ids ? `导出明确选择的 ${exportChoice.ids.length} 个邮箱。` : '导出当前筛选下的全部邮箱，不受当前分页限制。'} 不会自动轮换、补发或确认接收；失败不会保存不完整文件。</p>{!!actionError && <Alert error={actionError} attention="focus" />}</div></Modal>
    <AnimatePresence initial={false} mode="wait">{exportChoice ? null : mailAlias ? <MailViewer key={'mail-' + mailAlias.id} addressID={mailAlias.id} address={mailAlias.address} archived={mailAlias.lifecycle === 'archived'} onClose={() => setMailAlias(null)} /> : composeAlias ? <MailComposer key={'compose-' + composeAlias.id} alias={{ id: composeAlias.id, address: composeAlias.address }} onClose={() => setComposeAlias(null)} /> : confirmation?.kind === 'delete' && confirmation.alias.lifecycle === 'archived' ? <LocalCleanupDialog key={'cleanup-' + confirmation.alias.id} sourceID={confirmation.alias.source_id} addressID={confirmation.alias.id} revision={confirmation.alias.revision} confirmation={confirmation.alias.address} onClose={() => setConfirmation(null)} onAccepted={() => { changed(confirmation.alias.source_id); setConfirmation(null); setCredentialAlias(null) }} /> : confirmation ? <Modal key="alias-confirmation" open onOpenChange={open => { if (!open && !busy) setConfirmation(null) }} title={confirmation.kind === 'delete' ? confirmation.alias.kind !== 'apple' ? '归档本地邮箱' : '删除邮箱' : rotationKind === 'bundle' ? '轮换整套凭证' : '轮换 API Key'} description={confirmation.alias.address} footer={<><Button variant="ghost" disabled={!!busy} onClick={() => setConfirmation(null)}>取消</Button><Button variant={confirmation.kind === 'delete' ? 'destructive' : 'default'} disabled={!!busy || confirmation.kind === 'delete' && !confirmedAliasDeletion(confirmation.alias.address, deleteText)} onClick={confirmMutation}>{busy ? '处理请求…' : confirmation.kind === 'delete' ? confirmation.alias.kind !== 'apple' ? '确认归档' : '确认删除' : '确认轮换'}</Button></>}><div className="stack">{confirmation.kind === 'delete' ? <><Alert tone="warning">{confirmation.alias.lifecycle === 'archived' || confirmation.alias.kind !== 'apple' ? '将此本地邮箱归档、停用并撤销访问；原邮件、凭据和未决请求保留。之后可在归档页明确清理，不向 Apple 发起操作。' : '将向 Apple 发起明确的一次删除请求。只有远端确认后才归档；历史与消费事实保留。不确定结果只查询原请求。'}</Alert><Field label="输入完整邮箱地址确认"><Input value={deleteText} onChange={event => setDeleteText(event.target.value)} autoComplete="off" /></Field></> : <>{confirmation.alias.credential_profile === 'mailbox' && <Field label="轮换范围"><Select value={rotationKind} disabled={!!busy} onChange={event => setRotationKind(event.target.value === 'key' ? 'key' : 'bundle')}><option value="bundle">整套凭证</option><option value="key">仅 API Key</option></Select></Field>}<Alert tone="warning">{rotationKind === 'bundle' ? '旧 API Key、IMAP 密码、OAuth 元组与已签发访问将被撤销。新的交付仍需明确保存与确认。' : '仅轮换 API Key 及其派生访问；独立 IMAP/OAuth 凭据保持原值与代次。'} 不改变邮件消费与远端已读事实。</Alert></>}{!!actionError && <Alert error={actionError} attention="focus" />}</div></Modal> : credentialAlias ? <CredentialSheet key={'detail-' + credentialAlias.id} alias={credentialAlias} accountName={accountName(credentialAlias)} groupName={groupName(credentialAlias)} error={actionError} onClose={() => setCredentialAlias(null)} onCompose={setComposeAlias} onMail={setMailAlias} onExport={(row, kind) => setExportChoice({ kind, ids: [row.id] })} onToggle={toggleAlias} onConfirm={(kind, alias) => { setActionError(null); setDeleteText(''); setRotationKind(alias.credential_profile === 'mailbox' ? 'bundle' : 'key'); setConfirmation({ kind, alias }) }} busy={blocked || pendingFor(credentialAlias) || actions.recoveryRequired} /> : null}</AnimatePresence>
  </section>
}

function CredentialSheet({ alias: initial, accountName, groupName, error, onClose, onCompose, onMail, onExport, onToggle, onConfirm, busy }: { alias: Alias; accountName: string; groupName: string; error: unknown; onClose: () => void; onCompose: (row: Alias) => void; onMail: (row: Alias) => void; onExport: (row: Alias, kind: CredentialExportKind) => void; onToggle: (row: Alias) => void; onConfirm: (kind: 'rotate' | 'delete', row: Alias) => void; busy: boolean }) {
  const control = useControl(), toast = useToast(), reportError = useErrorFeedback(), detail = useResource(async signal => (await control.addresses.get(initial.id, signal)).result, [initial.id, initial.revision], { poll: false })
  const alias = detail.data?.id === initial.id ? detail.data : initial, access = aliasAccess(alias)
  const [material, setMaterial] = useState<CredentialBundle | { api: { key: string } } | null>(null), [revealing, setRevealing] = useState(false), [revealError, setRevealError] = useState<unknown>(null)
  const [copying, setCopying] = useState(false), copyGuard = useRef(false)
  async function copyAccess(format: CredentialCopyFormat | 'recent' | 'raw') {
    if (copyGuard.current) return
    copyGuard.current = true; setCopying(true); setRevealError(null)
    try {
      let value: string
      if (format === 'recent') {
        const key = (await control.credentials.revealAPIKey(alias.id)).result.api.key
        value = credentialCopyURL('/api/v1/mail/recent?api_key=' + encodeURIComponent(key), window.location.origin)
      } else {
        const result = await control.credentialExports.copy(format === 'imap' ? 'imap' : 'otp', { selected_ids: [alias.id] }, window.location.origin)
        value = format === 'raw' ? credentialCopyURL(result.links[0]?.raw || '', window.location.origin) : result.text
      }
      await copyText(value); toast('已复制。', 'success')
    } catch (error) { reportError(error, 'read', setRevealError) } finally { copyGuard.current = false; setCopying(false) }
  }
  const revealController = useRef<AbortController | null>(null)
  useEffect(() => { revealController.current?.abort(); setMaterial(null); setRevealError(null); setRevealing(false); return () => revealController.current?.abort() }, [alias.id, alias.auth_generation, alias.credential_profile, alias.lifecycle, alias.revision])
  useEffect(() => {
    const changed = (event: Event) => {
      const sourceID = (event as CustomEvent<{ accountId?: string }>).detail?.accountId
      if (!sourceID || sourceID === alias.source_id) { revealController.current?.abort(); setMaterial(null); setRevealing(false); void detail.refresh() }
    }
    window.addEventListener('icloudspace:aliases-changed', changed)
    return () => window.removeEventListener('icloudspace:aliases-changed', changed)
  }, [alias.source_id, detail.refresh])
  async function reveal() { if (material) { setMaterial(null); return }; if (revealing || !access.canReveal) return; const controller = new AbortController(); revealController.current = controller; setRevealing(true); setRevealError(null); try { const next = alias.credential_profile === 'mailbox' ? (await control.credentials.revealBundle(alias.id, controller.signal)).result.bundle : { api: (await control.credentials.revealAPIKey(alias.id, controller.signal)).result.api }; if (!controller.signal.aborted) setMaterial(next) } catch (error) { if (!controller.signal.aborted) setRevealError(error) } finally { if (!controller.signal.aborted) setRevealing(false) } }
  const secret = (label: string, value?: string) => <div className="credential-item" key={label}><div className="credential-item-heading"><span>{label}</span>{value && <CopyButton value={value} label={`复制 ${label}`} />}</div><code className="mono credential-value">{value || (revealing ? '正在读取凭证…' : '点击显示明文后按需复制')}</code></div>
  return <Sheet open onOpenChange={open => { if (!open) onClose() }} title="邮箱详情" description={alias.address} footer={<><div className="detail-footer-start"><Button variant="secondary" onClick={onClose}>关闭</Button></div><div className="detail-footer-actions">{!access.archived && <Button variant="secondary" disabled={busy || !access.canRotate} onClick={() => onConfirm('rotate', alias)}><RotateCcw size={14} />{alias.credential_profile === 'mailbox' ? '轮换凭证' : '轮换 Key'}</Button>}<Button variant="destructive" disabled={busy || !access.canDelete} onClick={() => onConfirm('delete', alias)}><Trash2 size={14} />{access.archived ? '清理本地数据' : alias.kind === 'apple' ? '删除邮箱' : '归档本地邮箱'}</Button></div></>}>
    <div className="stack mailbox-detail">{!!(detail.error || error || revealError) && <Alert error={error || revealError || detail.error} attention={error || revealError ? "focus" : "notify"} />}<div className="toolbar detail-status"><AliasStatus alias={alias} /><Badge>{credentialLabel(alias)}</Badge>{alias.registration_banned && <Badge tone="danger">检测到注册账户被封禁</Badge>}</div>
      {alias.archive_notice && <AliasArchiveNotice archivedAt={alias.archive_notice.archived_at} reason={alias.archive_notice.reason} />}
      {alias.archive_notice&&alias.kind!=='apple'&&<p className="section-note">此邮箱已在本地归档并撤销访问。历史内容保留，需要移除时请单独确认清理。</p>}
      <div className="detail-primary-actions">{access.archived ? <Button variant="secondary" onClick={() => onMail(alias)}><Eye size={15} />查看历史邮件</Button> : <><Button disabled={!access.canSend || busy} onClick={() => onCompose(alias)}><Mail size={15} />撰写邮件</Button><Button variant="secondary" disabled={!access.canReceive} onClick={() => onMail(alias)}><Eye size={15} />查看邮件</Button></>}</div>
      <section className="detail-section"><div className="detail-section-heading"><h3>邮箱信息</h3></div><dl className="detail-list"><dt>用途备注</dt><dd>{alias.label || '未填写'}</dd><dt>所属主号</dt><dd><Link to={`/accounts/${alias.source_id}`} className="text-link" onClick={onClose}>{accountName}</Link></dd><dt>邮箱分组</dt><dd>{groupName}</dd><dt>最近调用</dt><dd>{formatAliasTime(alias.last_accessed_at)}</dd><dt>最新邮件</dt><dd>{formatAliasTime(alias.latest_received_at)}</dd><dt>最近同步</dt><dd>{formatAliasTime(alias.last_synced_at)}</dd></dl></section>
      {access.pending && <Alert tone="warning">此地址正在等待 Apple 目录确认。确认前不允许发布凭据、启用、轮换或删除。</Alert>}
      {access.deleting && <Alert tone="warning">原删除请求尚未完成确认。仅查询原请求，不会再次提交删除。</Alert>}
      {alias.registration_banned && <Alert tone="warning">该标记来自可信归档邮件中的注册账户封禁证据，不代表邮箱自身被封禁。检测时间：{formatAliasTime(alias.registration_banned_at)}</Alert>}
      {alias.last_sync_error && !access.pending && !access.archived && <Alert tone="danger">{alias.last_sync_error}</Alert>}
      {!access.archived && !access.pending && !access.deleting && <section className="detail-section"><div className="detail-section-heading"><div><h3>接入凭证</h3><p className="section-note">{alias.credential_profile === 'legacy_latest' ? '此 API 保留最新快照与获授权的精确消费；查看或导出不会升级 IMAP/OAuth 权限。' : '仅在明确查看时读取明文，不会确认待交付凭据。'}</p></div><Button variant="secondary" size="sm" disabled={revealing || !access.canReveal} onClick={() => void reveal()}>{material ? <EyeOff size={14} /> : <Eye size={14} />}{material ? '隐藏明文' : revealing ? '读取中…' : '显示明文'}</Button></div><div className="credential-grid">{secret('API Key', material?.api.key)}{alias.credential_profile === 'mailbox' && <>{secret('IMAP 密码', material && 'imap' in material ? material.imap.password : undefined)}{secret('client ID', material && 'oauth' in material ? material.oauth.client_id : undefined)}{secret('refresh token', material && 'oauth' in material ? material.oauth.refresh_token : undefined)}</>}</div><div className="detail-primary-actions"><Button variant="secondary" disabled={!access.canExport || busy} onClick={() => onExport(alias, 'api_key')}><Download size={14} />导出 API</Button><Button variant="secondary" disabled={!access.canExportMailbox || busy} onClick={() => onExport(alias, 'mailbox')}><Download size={14} />导出 IMAP/OAuth</Button></div></section>}
      {!access.archived && !access.pending && !access.deleting && <section className="detail-section"><div className="detail-section-heading"><h3>复制与接入</h3></div><div className="detail-primary-actions"><Button variant="secondary" disabled={busy || copying || !access.canExport || alias.credential_profile === 'legacy_latest'} onClick={() => void copyAccess('otp')}><Copy size={14} />复制取码格式</Button><Button variant="secondary" disabled={busy || copying || !access.canExportMailbox} onClick={() => void copyAccess('imap')}>复制 IMAP/OAuth</Button><Button variant="secondary" disabled={busy || copying || !access.canReveal} onClick={() => void copyAccess('recent')}>复制收件链接</Button><Button variant="secondary" disabled={busy || copying || !access.canExport || alias.credential_profile === 'legacy_latest'} onClick={() => void copyAccess('raw')}>复制原文链接</Button></div><p className="section-note">取码和原文查看不消费邮件。收件链接仅在明确打开时取走最近一小时尚未消费的邮件，并排入已读同步；请勿自动预加载或重试。</p></section>}
      <AliasDiagnostics alias={alias} />
      <section className="detail-secondary-actions"><div><h3>邮箱状态</h3><p className="section-note">{access.archived ? '已归档并停用；历史邮件保留。' : alias.enabled ? '地址当前已启用；实际接入用途由独立凭据权限决定。' : '当前邮箱已停用；管理备份不会重新启用接入。'}</p></div><Button variant="secondary" disabled={busy || !access.canToggle} onClick={() => onToggle(alias)}>{access.archived ? '已归档' : alias.enabled ? '停用邮箱' : '启用邮箱'}</Button></section>
    </div>
  </Sheet>
}

function AliasDiagnostics({ alias }: { alias: Alias }) {
  const { synchronization } = useControl(), [open, setOpen] = useState(false)
  const diagnostics = useResource(async signal => {
    if (!open) return null
    const state = (await synchronization.get(alias.source_id, signal)).result
    const events = (await synchronization.events(alias.source_id, state.progress ? { round_id: state.progress.round_id } : {}, signal)).result
    return { state, events }
  }, [alias.source_id, open], { poll: false })
  return <details className="detail-section operation-details" open={open} onToggle={event => setOpen(event.currentTarget.open)}><summary>同步诊断与接入详情</summary><dl className="detail-list"><dt>凭据代次</dt><dd>{alias.auth_generation}</dd><dt>最近同步</dt><dd>{formatAliasTime(alias.last_synced_at, true)}</dd></dl>{diagnostics.error && <Alert error={diagnostics.error} />}{diagnostics.loading ? <p>正在读取本轮同步记录…</p> : diagnostics.data ? <><p>所属主号本轮：{diagnostics.data.state.progress?.phase || '暂无运行记录'}</p>{diagnostics.data.events.items.length ? diagnostics.data.events.items.slice(-12).map(item => <p key={item.sequence}>{formatAliasTime(item.at, true)} · {item.progress.phase} · {item.progress.outcome || item.progress.state}</p>) : <p>本轮没有事件记录。</p>}</> : null}</details>
}

function GroupManager({ open, onOpenChange, groups, refresh, onDeleted }: { open: boolean; onOpenChange: (open: boolean) => void; groups: Group[]; refresh: () => Promise<void>; onDeleted: (id: string) => void }) {
  const control = useControl(), toast = useToast(), [name, setName] = useState(''), [editing, setEditing] = useState<Group | null>(null), [deleting, setDeleting] = useState<Group | null>(null), [busy, setBusy] = useState(false), guard = useRef(false), [error, setError] = useState<unknown>(null)
  async function mutate(action: () => Promise<void>) { if (guard.current) return; guard.current = true; setBusy(true); setError(null); try { await action(); await refresh(); notifyGroups(); notifyAliases() } catch (failure) { setError(failure) } finally { guard.current = false; setBusy(false) } }
  return <Modal open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }} title="邮箱分组" description="分组只组织本地邮箱；删除分组会将其中邮箱恢复为未分组。" footer={<Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>完成</Button>}>
    <div className="stack">{!!error && <Alert error={error} attention="focus" />}<form className="stack" onSubmit={event => { event.preventDefault(); if (!name.trim()) return; void mutate(async () => { editing ? await control.addresses.renameGroup(editing.id, editing.revision, name.trim()) : await control.addresses.createGroup(name.trim()); setEditing(null); setName(''); toast('分组已保存。', 'success') }) }}><Field label={editing ? '重命名分组' : '新建分组'}><Input value={name} maxLength={100} disabled={busy} placeholder="例如：工作、购物、注册" onChange={event => setName(event.target.value)} /></Field><div className="toolbar"><Button type="submit" disabled={busy || !name.trim()}>{editing ? '保存名称' : '创建分组'}</Button>{editing && <Button variant="ghost" type="button" disabled={busy} onClick={() => { setEditing(null); setName('') }}>取消编辑</Button>}</div></form>
      {groups.length ? <div className="stack">{groups.map(group => <div className="toolbar" key={group.id}><div style={{ flex: 1 }}><strong>{group.name}</strong><div className="text-muted">{group.address_count} 个邮箱</div></div><Button variant="secondary" size="sm" disabled={busy} onClick={() => { setEditing(group); setName(group.name); setDeleting(null) }}>重命名</Button><Button variant="secondary" size="sm" disabled={busy} onClick={() => setDeleting(group)}>删除</Button></div>)}</div> : <Empty title="还没有分组" description="创建分组后即可移动单个或勾选的邮箱。" />}
      {deleting && <div className="notice stack"><p>删除“{deleting.name}”？其中 {deleting.address_count} 个邮箱将恢复为未分组，邮箱本身不会删除。</p><div className="toolbar"><Button variant="ghost" disabled={busy} onClick={() => setDeleting(null)}>取消</Button><Button variant="destructive" disabled={busy} onClick={() => void mutate(async () => { await control.addresses.deleteGroup(deleting.id, deleting.revision); onDeleted(deleting.id); if (editing?.id === deleting.id) { setEditing(null); setName('') }; setDeleting(null); toast('分组已删除，邮箱已恢复为未分组。', 'success') })}>确认删除分组</Button></div></div>}
    </div>
  </Modal>
}
