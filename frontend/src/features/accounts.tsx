import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { VirtualTable, type TableColumn } from '../components/virtual-table'
import { TableTransition } from '../components/table-transition'
import { TablePlaceholder } from '../components/table-placeholder'
import { RefreshButton } from '../components/refresh-button'
import { RefreshRegion } from '../components/refresh-region'
import { RefreshIcon } from '../components/animated-icon'
import { ArrowLeft, ArrowUpRight, LogIn, LogOut, Plus, Server, ShieldCheck } from 'lucide-react'
import { useControl, useControlSession } from '../lib/control'
import { AccountRecoveryStore } from '../control/account-recovery'
import type { AccountRecovery, AccountRecoveryInput, AccountRecoverySnapshot } from '../control/account-recovery'
import { ClientStateError, safeBrowserStorage } from '../control/client-state-handoff'
import { AccountRecoveryActions, accountRecoveryCopyValue, accountRecoveryLabel, appleReceiptError, deviceDispatchAccepted, providerLabels, appleVerificationAction, nextAppleLoginAction, providerRecoveryDisposition, recoveriesNeedingAttention, retainReadableAccountRecoveries, sameAccountRecovery } from './accounts/recovery'
import { LocalCleanupDialog } from './local-cleanup'
import { useResource } from '../lib/hooks'
import { AnimatePresence, AnimatedSection } from '../lib/motion'
import { Alert, Badge, Button, Checkbox, CopyButton, Empty, Field, Input, Loading, Modal, PageHeader, Pagination, Panel, Progress, Select, Switch, useErrorFeedback, useToast } from '../components/ui'
import { AliasList } from './aliases'
import { AliasArchiveSyncNotice } from './alias-archive-notice'
import type { AccountCreate, AccountPatch } from '../control/contracts'
import type { ProviderAction, ProviderActionInput, ProviderAuthResult } from '../control/provider-session-contracts'
import type { HMEReconciliation } from '../control/hme-contracts'
import { feedbackDetails, ReceiptError } from '../lib/feedback'
import { diagnosticMessage } from '../lib/diagnostic-message'
import { hmeResultHint } from '../control/hme-presentation'
import { ControlError } from '../transport'
import { accountSubmission, imapSourceChanged, validateAccountForm, accountView, allAccountMetadata, initialAccountForm, formFromAccount, accountDetail, accountIdentity,
  receiveLabel, formatTime, formatIMAPEndpoint, isForwardedICloudIMAP, syncProgressPresentation, unknownMutation, newOperationKey, emailPattern, pendingKeyExports, pendingKeyStatus, pendingKeyMaterialStatus, accountErrorHint, accountListProgress,
  type AccountForm, type AccountView, type AccountDetail, type PendingKeyView } from './accounts/model'

const appleInvalid = (error: unknown) => error instanceof ControlError && ['PROVIDER_LOGIN_REQUIRED', 'HME_LOGIN_REQUIRED'].includes(error.code)
function changed(accountId: string) { window.dispatchEvent(new CustomEvent('icloudspace:aliases-changed', { detail: { accountId } })) }

function SyncState({ account, details = false }: { account: AccountView, details?: boolean }) {
  const progress = syncProgressPresentation(account.syncProgress)
  const label = !account.enabled ? '已停用' : !account.syncObserved ? '详情查看' : progress.active ? progress.label : account.syncProgress===null&&account.lastSyncedAt&&account.lastSyncStatus==='pending' ? '暂无当前进度' : ({ok:'同步正常',error:'同步异常',degraded:'部分完成',unknown:'结果待确认',cancelled:'已取消',superseded:'配置已变更',pending:'待同步'}[account.lastSyncStatus])
  const tone = !account.enabled ? 'neutral' : progress.active ? 'neutral' : account.lastSyncStatus==='degraded'||account.lastSyncStatus==='unknown' ? 'warning' : account.lastSyncStatus === 'ok' ? 'success' : account.lastSyncStatus === 'error' ? 'danger' : 'neutral'
  return <div className="stack" style={{ gap: 5 }}><Badge tone={tone}>{label}</Badge>{progress.active && account.enabled && <><small className="text-muted">{progress.stageLabel}{progress.percentage !== null ? ` · ${Math.round(progress.percentage)}%` : ''}</small>{details && <Progress aria-label={progress.stageLabel} value={progress.percentage} className="mt-1 h-1.5" />}</>}</div>
}

const accountColumns: TableColumn[] = [
    { key: 'identity', label: '主号 / 后缀', width: 250, render: account => <><Link className="text-link" to={`/accounts/${account.id}`}>{accountIdentity(account)}</Link><div className="text-muted">{account.name || '未填写备注'}</div></> },
    { key: 'source', label: '收件来源', width: 220, render: account => <><div>{receiveLabel(account)}</div><small className="text-muted mono">{formatIMAPEndpoint(account)}</small></> },
    { key: 'aliasCount', label: '隐私邮箱', width: 100, render: account => account.aliasCount ?? '—' },
    { key: 'status', label: '同步状态', width: 150, render: account => <SyncState account={account} /> },
    { key: 'time', label: '最近同步', width: 185, render: account => <span className="text-muted">{formatTime(account.lastSyncedAt, { seconds: true })}</span> },
    { key: 'actions', label: '操作', width: 95, render: account => <Button asChild variant="secondary" size="sm"><Link to={`/accounts/${account.id}`}>管理 <ArrowUpRight size={14} /></Link></Button> },
  ]
function AccountRows({ accounts }: { accounts: AccountView[] }) {
  return <VirtualTable rows={accounts} rowHeight={78} columns={accountColumns} />
}

export function AccountsPage() {
  const control = useControl()
  const [exporting,setExporting]=useState(false),[exportOpen,setExportOpen]=useState(false),[exportError,setExportError]=useState<unknown>(null)
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)
  const [draft, setDraft] = useState('')
  const [query, setQuery] = useState('')
  const list = useResource<{items: AccountView[]; total: number}>(async signal => {
    if (size === 0) { const items = await allAccountMetadata(control.accounts, query, signal); return { items: await accountListProgress(control.synchronization,items,signal), total: items.length } }
    const result = (await control.accounts.list({ query, page, page_size: size }, signal)).result
    return { items: await accountListProgress(control.synchronization,result.items,signal), total: result.total }
  }, [page, size, query], { poll: true, keepPreviousData: true, initialLoadingFeedback: true })
  const accounts = list.data?.items || []
  const total = list.data?.total ?? accounts.length
  async function exportAccounts(){if(exporting)return;setExporting(true);setExportError(null);try{const stream=await control.accounts.export({format:'csv',filter:{query}});const blob=await new Response(stream).blob();const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='accounts.csv';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);setExportOpen(false)}catch(error){setExportError(error)}finally{setExporting(false)}}
  useEffect(() => { if (!list.stale && size && list.data && page > Math.max(1, Math.ceil(total / size))) setPage(Math.max(1, Math.ceil(total / size))) }, [total, page, size, list.data, list.stale])
  return <div className="stack"><PageHeader eyebrow="WORKSPACE / ACCOUNTS" title="主号管理" description="管理 iCloud 与自定义邮箱来源，查看每个主号的实时同步状态。" actions={<Button asChild><Link to="/accounts/new"><Plus size={15} /> 添加主号</Link></Button>} />
    <div className="toolbar"><form className="field-row" onSubmit={e => { e.preventDefault(); setPage(1); setQuery(draft.trim()) }}><Input aria-label="搜索主号" placeholder="搜索邮箱、备注或 IMAP 用户名" value={draft} onChange={e => setDraft(e.target.value)} /><Button variant="secondary" type="submit">搜索</Button>{query && <Button variant="ghost" type="button" onClick={() => { setQuery(''); setDraft(''); setPage(1) }}>清除</Button>}</form><div className="row-actions"><Button variant="outline" onClick={()=>{setExportError(null);setExportOpen(true)}}>导出主号凭据</Button><RefreshButton variant="outline" pending={list.loading || list.manualRefreshing} onRefresh={list.refresh}>刷新</RefreshButton></div></div>
    {list.error && <Alert context="read" error={list.error} />}
    <TableTransition dataKey={list.dataKey} stale={list.stale} pending={list.loading} refreshing={list.refreshing} manualRefreshing={list.manualRefreshing} initialLoadingVisible={list.initialLoadingVisible} label="正在更新主号列表">
      {list.loading && !list.data ? <TablePlaceholder columns={accountColumns} loading rowHeight={78} label="正在读取主号…" /> : accounts.length ? <div className="stack"><div className="stat-row"><div className="stat-cell"><small>匹配主号</small><strong>{total}</strong></div><div className="stat-cell"><small>当前列表</small><strong>{accounts.length}</strong></div><div className="stat-cell"><small>状态刷新</small><strong className="whitespace-nowrap">每 5 秒</strong></div></div><AccountRows accounts={accounts} /></div> : <TablePlaceholder columns={accountColumns} title={list.error ? '主号暂不可用' : query ? '没有匹配的主号' : '添加第一个邮箱来源'} description={list.error ? '请重新读取主号列表。' : query ? '调整关键词后重新搜索。' : '连接 iCloud 或自定义 IMAP 邮箱，然后同步和管理地址。'} action={list.error ? <RefreshButton variant="secondary" pending={list.loading || list.manualRefreshing} onRefresh={list.refresh} loadingLabel="重新加载中…">重新加载</RefreshButton> : !query && <Button asChild><Link to="/accounts/new"><Plus size={15} /> 添加主号</Link></Button>} />}
    </TableTransition>
    {accounts.length > 0 && <Pagination page={page} size={size} total={total} disabled={list.stale} onPage={setPage} onSize={value => { setSize(value); setPage(1) }} />}<Modal open={exportOpen} onOpenChange={open=>{if(!exporting)setExportOpen(open)}} title="导出主号连接凭据" description="按当前筛选导出全部匹配主号，文件包含敏感连接密码，请保存到可信位置。" footer={<><Button variant="outline" disabled={exporting} onClick={()=>setExportOpen(false)}>取消</Button><Button disabled={exporting} loading={exporting} loadingLabel="正在导出…" onClick={()=>void exportAccounts()}>导出 CSV</Button></>}><div className="stack"><dl className="detail-facts"><div><dt>导出范围</dt><dd>{query ? '匹配“' + query + '”的主号' : '全部主号'}</dd></div>{list.data && !list.stale && <div><dt>当前列表匹配</dt><dd>{total} 个主号</dd></div>}</dl>{Boolean(exportError) && <Alert error={exportError} attention="focus"/>}</div></Modal>
  </div>
}

const initialForm = initialAccountForm

export function AccountFormPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const control = useControl()
  const toast = useToast()
  const [form, setForm] = useState<AccountForm>(initialForm)
  const [baseline, setBaseline] = useState<AccountView | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)
  const lock = useRef(false)
  const [pending, setPending] = useState<AccountPatch | null>(null)
  const [uncertain, setUncertain] = useState<ControlError | null>(null)
  const currentId = useRef(id)
  const formMounted = useRef(true)
  currentId.current = id
  useEffect(() => { formMounted.current = true; return () => { formMounted.current = false } }, [])
  const account = useResource<{account:AccountView}|null>(async signal => {
    if (!id) return null
    const [source, addresses] = await Promise.all([control.accounts.get(id, signal), control.addresses.list({source_id:id,page:1,page_size:1},signal)])
    return { account: accountView(source.result, null, addresses.result.total) }
  }, [id])
  useEffect(() => { setForm(initialForm()); setBaseline(null); setError(null); setPending(null); setUncertain(null) }, [id])
  useEffect(() => {
    const value = account.data?.account
    if (!id || !value || value.id !== id) return
    setBaseline(value)
    setForm(formFromAccount(value.raw))
  }, [account.data, id])
  const isCustom = form.mailboxType === 'custom'
  const genericPassword = isCustom || isForwardedICloudIMAP(form)
  const lockedIdentity = Boolean(id && baseline && BigInt(baseline.aliasCount) > 0n)
  function field<K extends keyof AccountForm>(key: K, value: AccountForm[K]) { setForm(previous => ({ ...previous, [key]: value })) }
  async function save(payload: AccountCreate | AccountPatch) {
    if (lock.current) return
    lock.current = true; setBusy(true); setError(null)
    const submittedId = id
    try {
      const result = submittedId && 'expected_revision' in payload ? (await control.accounts.patch(submittedId, payload)).result.source : !('expected_revision' in payload) ? (await control.accounts.create(payload)).result : null
      if (!result) throw new Error('主号和修订版本不匹配，请重新读取。')
      if (!formMounted.current || currentId.current !== submittedId) return
      setForm(previous => ({ ...previous, imapPassword: '' })); setPending(null)
      toast(submittedId ? '主号设置已保存。' : '主号已添加。', 'success')
      navigate(`/accounts/${result.id}`, { replace: true })
    } catch (failure) { if (formMounted.current && currentId.current === submittedId) { setError(failure); if (unknownMutation(failure) && failure instanceof ControlError) setUncertain(failure); setPending(null); setForm(previous => ({ ...previous, imapPassword: '' })) } }
    finally { if (payload.credentials) payload.credentials.imap_password = ''; lock.current = false; if (formMounted.current) setBusy(false) }
  }
  function submit(event: FormEvent) {
    event.preventDefault(); if (busy) return
    const invalid = validateAccountForm(form, Boolean(id))
    if (invalid) { setError(new Error(invalid)); return }
    if (uncertain) return
    const payload = id && baseline ? accountSubmission(form, true, baseline.raw) : accountSubmission(form, false)
    const sourceChanged = id && baseline && imapSourceChanged(baseline.raw, payload)
    if (sourceChanged && 'expected_revision' in payload) { setPending({...payload,require_source_change:true}); return }
    void save(payload)
  }
  async function queryCandidate(){if(!uncertain||busy)return;setBusy(true);try{const result=await control.accounts.queryUnknownResource(uncertain);if(result&&formMounted.current){toast('已读取候选主号，请核对实际设置。','success');navigate(`/accounts/${result.result.id}`)}else setError(new Error('服务器未提供可查询的候选主号 ID。请先从主号列表核对本次结果，不要重新提交。'))}catch(error){setError(error)}finally{if(formMounted.current)setBusy(false)}}
  return <div className="stack"><PageHeader eyebrow="WORKSPACE / ACCOUNTS" title={id ? '编辑主号' : '添加主号'} description="配置用于收取邮件的 IMAP 来源。Apple 网页登录在主号详情中单独管理。" actions={<Button variant="ghost" onClick={() => navigate(id ? `/accounts/${id}` : '/accounts')}><ArrowLeft size={14} /> 返回</Button>} />
    {id && account.error && <Alert context="read" error={account.error} />}
    {id && !baseline ? <Panel>{(account.loading || account.manualRefreshing) && <Loading label="正在读取主号设置…" />}{account.error && <RefreshButton variant="outline" pending={account.loading || account.manualRefreshing} onRefresh={account.refresh} loadingLabel="重新读取中…">重新读取</RefreshButton>}</Panel> : <form className="stack" onSubmit={submit}><Panel title="邮箱来源" description="支持直连 iCloud、iCloud 转发至第三方 IMAP，以及自定义域名邮箱。"><div className="grid-2"><Field label="备注"><Input value={form.name} maxLength={80} disabled={busy} onChange={e => field('name', e.target.value)} placeholder="例如：个人主号" /></Field><Field label="邮箱类型" description={lockedIdentity ? '已有隐私邮箱，不能更改邮箱模式、身份或后缀。' : undefined}><Select disabled={busy || lockedIdentity} value={form.mailboxType} onChange={e => field('mailboxType', e.target.value)}><option value="icloud">iCloud 隐私邮箱</option><option value="custom">自定义邮箱</option></Select></Field>{isCustom ? <Field label="邮箱后缀" description="同一后缀只能配置一个主号。随机地址会在此后缀下生成。"><Input required disabled={busy || lockedIdentity} value={form.emailSuffix} onChange={e => field('emailSuffix', e.target.value)} placeholder="example.com" /></Field> : <Field label="iCloud 主号邮箱"><Input required type="email" disabled={busy || lockedIdentity} value={form.email} onChange={e => field('email', e.target.value)} placeholder="name@icloud.com" autoComplete="email" /></Field>}<Field label="实际收件邮箱" description="填写邮件最终投递的邮箱地址；它与 Apple ID 和 IMAP 登录用户名分别保存。"><Input required type="email" disabled={busy||lockedIdentity} value={form.receivingAddress} onChange={e=>field('receivingAddress',e.target.value)} /></Field>{!isCustom && <Field label="Apple 服务区域"><Select disabled={busy||lockedIdentity} value={form.appleRegion} onChange={e=>{if(e.target.value==='global'||e.target.value==='china')field('appleRegion',e.target.value)}}><option value="global">全球</option><option value="china">中国大陆</option></Select></Field>}<Field label="IMAP 用户名" description="如经第三方转发，填写最终物理投递邮箱的 IMAP 登录身份。"><Input required disabled={busy} value={form.imapUsername} onChange={e => {const value=e.target.value;setForm(previous=>({...previous,imapUsername:value,receivingAddress:previous.receivingAddress||(emailPattern.test(value)?value:'')}))}} autoComplete="username" /></Field><Field label="IMAP 主机" description="填写主机名或 IP，不包含协议、端口或路径。"><Input required disabled={busy} value={form.imapHost} onChange={e => field('imapHost', e.target.value)} /></Field><Field label="IMAP 端口" description="使用隐式 TLS，默认 993。"><Input required type="number" min={1} max={65535} disabled={busy} value={form.imapPort} onChange={e => field('imapPort', e.target.value)} /></Field><Field label={genericPassword ? 'IMAP 密码' : 'App 专用密码'} description={id ? '留空保留原密码；密码不会回显。' : '密码加密保存，不会在页面回显。'}><Input type="password" disabled={busy} required={!id} value={form.imapPassword} onChange={e => field('imapPassword', e.target.value)} autoComplete="new-password" /></Field></div><div className="notice"><strong>{receiveLabel(form)}</strong><p className="text-muted">{isCustom ? '按原始收件标头识别自定义地址，不调用 Apple 目录与创建接口。' : genericPassword ? '邮箱类型保持 iCloud；从第三方 IMAP 读取转发邮件，需保留可验证的原始投递标头。' : '按 Apple 原始投递标头匹配隐私邮箱；这里使用 App 专用密码。'}</p></div>{id && <label className="checkbox-label"><Switch checked={form.enabled} disabled={busy} onCheckedChange={checked => field('enabled', checked)} aria-label="启用主号同步" /><span>启用主号同步<small className="text-muted" style={{ display: 'block' }}>停用后，所属隐私邮箱的全部取件凭据立即失效。</small></span></label>}</Panel>{Boolean(error) && <Alert error={error} attention="focus">{accountErrorHint(error)}</Alert>}{uncertain && <Alert tone="warning"><div className="stack"><span>本次保存未确认，请保留原结果并查询候选主号，不能重新提交。</span><Button type="button" variant="outline" disabled={busy} loading={busy} loadingLabel="正在读取…" onClick={()=>void queryCandidate()}>查询候选主号</Button></div></Alert>}<div className="row-actions"><Button type="submit" disabled={busy||uncertain!==null} loading={busy} loadingLabel="正在保存…">保存主号</Button><Button type="button" variant="outline" disabled={busy} onClick={() => navigate(id ? `/accounts/${id}` : '/accounts')}>取消</Button></div></form>}
    <Modal open={Boolean(pending)} onOpenChange={open => { if (!open && !busy) setPending(null) }} title="确认切换 IMAP 来源" description="确认后建立新的收件来源代际。历史邮件保留，旧来源工作不能推进新游标；请核对实际收件邮箱、IMAP 主机和登录身份。" footer={<><Button variant="outline" disabled={busy} onClick={() => setPending(null)}>取消</Button><Button variant="destructive" disabled={busy} loading={busy} loadingLabel="正在切换…" onClick={() => pending && void save(pending)}>确认切换</Button></>}><div className="stack"><div className="notice"><small className="text-muted">旧来源</small><p className="mono">{baseline?.imapUsername} · {baseline && formatIMAPEndpoint(baseline)}</p></div><div className="notice"><small className="text-muted">新来源</small><p className="mono">{pending?.endpoint?.username} · {pending?.endpoint && formatIMAPEndpoint(pending.endpoint.host, pending.endpoint.port)}</p></div></div></Modal>
  </div>
}

type Intent = 'sync-aliases' | 'enable-auto' | null
type Confirm = 'delete' | 'enable' | 'disable' | 'disconnect' | null
const autoStatus: Record<string, string> = { unconfigured: '尚未配置', disabled: '已关闭', scheduled: '已安排', paused: '已暂停', login_required: '需要 Apple 登录', error: '最近执行异常', running: '正在创建', capacity_reached: '容量已满', unresolved_attempt: '原创建结果待确认' }
const creationAttemptLabels: Record<string, string> = { scheduled: '已安排', claimed: '处理中', confirmed: '已创建', not_created: '未创建', unknown: '结果待确认', cancelled: '已取消' }
type Recovery = { kind: 'metadata' | 'auto' | 'sync' } | {kind:'attempt';id:string}


export function AccountDetailPage() {
  const reportError = useErrorFeedback()
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const control = useControl()
  const session = useControlSession()
  const operatorID = session.operator?.id || ''
  const sourceScope = control.basePath + ':' + operatorID + ':' + id
  const recoveryStore = useMemo(() => operatorID ? new AccountRecoveryStore(safeBrowserStorage(() => window.localStorage), control.basePath, operatorID) : null, [control.basePath, operatorID])
  const toast = useToast()
  const resource = useResource<AccountDetail>(signal => accountDetail(control, id, signal), [id], { poll: true })
  const account = resource.data?.account
  const apple = resource.data?.appleSession
  const schedule = resource.data?.autoCreation
  const custom = account?.mailboxType === 'custom'
  const authenticated = apple?.status === 'authenticated'
  const directoryLoginRestored = authenticated && ['login_required','authentication_required','directory_authentication_required'].includes(account?.lastSyncError || '')
  const [busy, setBusy] = useState('')
  const [actionError, setActionError] = useState<unknown>(null)
  const [recovery, setRecovery] = useState<Recovery | null>(null)
  const [confirm, setConfirm] = useState<Confirm>(null)
  const [errorOpen, setErrorOpen] = useState(false)
  const [summary, setSummary] = useState<HMEReconciliation | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [aliasDraft, setAliasDraft] = useState({ address: '', label: '' })
  const [appleCreate, setAppleCreate] = useState(false)
  const [count, setCount] = useState('5')
  const [appleOpen, setAppleOpen] = useState(false)
  const [appleStep, setAppleStep] = useState<'login' | 'verification'>('login')
  const appleStepPanel = useRef<HTMLDivElement>(null)
  const focusAppleStep = () => { if (appleStepPanel.current && !appleStepPanel.current.inert) appleStepPanel.current.querySelector<HTMLInputElement>('input')?.focus() }
  const [appleForm, setAppleForm] = useState({ appleId: '', password: '', region: 'global', code: '', challengeId: '', flow: '' })
  const [appleError, setAppleError] = useState<unknown>(null)
  const [appleResult, setAppleResult] = useState<ProviderAuthResult | null>(null)
  const [inFlightRecord, setInFlightRecord] = useState<AccountRecovery | null>(null)
  const knownProviderRef = useRef<AccountRecovery | null>(null)
  const [savedRecovery, setSavedRecovery] = useState<{ scope: string; snapshot: AccountRecoverySnapshot }>({ scope: '', snapshot: { records: [], blocked: true, error: null, preserved: [] } })
  const [phone, setPhone] = useState('')
  const [factor, setFactor] = useState<'device'|'sms'>('device')
  const [keysOpen, setKeysOpen] = useState(false)
  const [keys, setKeys] = useState<PendingKeyView[] | null>(null)
  const [keysMore,setKeysMore]=useState(false)
  const [keysSaved, setKeysSaved] = useState(false)
  const [keysError, setKeysError] = useState<unknown>(null)
  const [sourceSecret, setSourceSecret] = useState<string | null>(null)
  const [keysRefreshFeedback, setKeysRefreshFeedback] = useState(false)
  const lock = useRef(false)
  const intent = useRef<Intent>(null)
  const generation = useRef(0)
  const route = useRef(id); route.current = id
  const mounted = useRef(true)
  const view = useRef({ scope: sourceScope, epoch: 0 })
  if (view.current.scope !== sourceScope) view.current = { scope: sourceScope, epoch: view.current.epoch + 1 }
  const viewEpoch = view.current.epoch
  const alive = (accountId: string) => mounted.current && route.current === accountId && view.current.epoch === viewEpoch && view.current.scope === sourceScope
  const recoveryActions = useMemo(() => recoveryStore ? new AccountRecoveryActions(recoveryStore, id, () => alive(id)) : null, [recoveryStore, id, viewEpoch])
  const recoverySnapshot = savedRecovery.scope === sourceScope ? savedRecovery.snapshot : { records: [], blocked: true, error: null, preserved: [] }
  const visibleRecoveries = recoveriesNeedingAttention(recoverySnapshot.records, inFlightRecord, knownProviderRef.current)
  const applePending = visibleRecoveries.filter(record => record.kind === 'provider').at(-1)
  function refreshSavedRecovery() {
    if (!alive(id)) return
    if (!recoveryStore) { setSavedRecovery({ scope: sourceScope, snapshot: { records: [], blocked: true, error: new ClientStateError('account_session_unconfirmed'), preserved: [] } }); return }
    try { const next=recoveryStore.inspect(id);setSavedRecovery(previous=>({scope:sourceScope,snapshot:previous.scope===sourceScope?retainReadableAccountRecoveries(previous.snapshot,next):next})) }
    catch { setSavedRecovery({ scope: sourceScope, snapshot: { records: [], blocked: true, error: null, preserved: [] } }) }
  }
  const secretReads=useRef(new AbortController())
  useEffect(()=>{const controller=new AbortController();secretReads.current=controller;return()=>controller.abort()},[sourceScope])
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; lock.current = false; intent.current = null } }, [])
  useEffect(() => { generation.current++; lock.current = false; setBusy(''); setActionError(null); setRecovery(null); setConfirm(null); setSummary(null); setAddOpen(false); setAppleOpen(false); setAppleError(null); setAppleResult(null); setInFlightRecord(null); knownProviderRef.current = null; setSourceSecret(null); setAppleForm({ appleId: '', password: '', region: 'global', code: '', challengeId: '', flow: '' }); intent.current = null; setKeysOpen(false); setKeys(null); setKeysMore(false); setKeysSaved(false); setKeysError(null); setKeysRefreshFeedback(false); refreshSavedRecovery() }, [sourceScope])
  useEffect(() => { const refresh = () => refreshSavedRecovery(); window.addEventListener('storage', refresh); return () => window.removeEventListener('storage', refresh) }, [sourceScope, recoveryStore])
  useEffect(() => {
    const refresh = (event: Event) => { const changedId: unknown = (event as CustomEvent).detail?.accountId; if (!changedId || changedId === id) void resource.refresh() }
    window.addEventListener('icloudspace:aliases-changed', refresh)
    return () => window.removeEventListener('icloudspace:aliases-changed', refresh)
  }, [id, resource.refresh])
  async function run(name: string, operation: () => Promise<void>, failure?: (error: unknown) => void, queryOnly = false, knownAuthResume=false) {
    const stored = recoveryStore?.inspect(id)
    const storageBlocked = !stored || stored.blocked || stored.records.some(record => !sameAccountRecovery(knownProviderRef.current, record))
    if (!alive(id) || lock.current || !queryOnly && (storageBlocked || recovery && !knownAuthResume)) return false
    lock.current = true; const ticket = ++generation.current; setBusy(name); setActionError(null)
    try { await operation(); return true }
    catch (error) { if (alive(id)) { if (unknownMutation(error) && !queryOnly && !recoveryStore?.inspect(id).records.some(record => !sameAccountRecovery(knownProviderRef.current, record))) setRecovery(previous => previous || {kind:'metadata'}); if (failure) failure(error); else reportError(error, confirm || addOpen ? 'form' : queryOnly ? 'read' : 'action', setActionError) }; return false }
    finally { if (ticket === generation.current && alive(id)) { lock.current = false; setBusy(''); setInFlightRecord(null); refreshSavedRecovery() } }
  }
  function openApple(next: Intent = null) {
    intent.current = next; setAppleStep(applePending || knownProviderRef.current ? 'verification' : 'login'); setAppleError(null)
    setAppleForm({ appleId: apple?.appleId || account?.email || '', password: '', region: apple?.region || 'global', code: '', challengeId: '', flow: '' }); if (!applePending && !knownProviderRef.current) {setAppleResult(null);setAppleStep('login')}; setAppleOpen(true)
    if (applePending) void querySaved(applePending)
  }
  function closeApple() {
    if (busy) return
    setAppleOpen(false); intent.current = null; setAppleError(null)
    setAppleForm(previous => ({ ...previous, password: '', code: '', challengeId: '', flow: '' }))
  }
  function appleFailure(error: unknown, next: Intent) { if (appleInvalid(error)) openApple(next); else setActionError(error) }
  async function syncAliases() {
    if (!authenticated) { openApple('sync-aliases'); return }
    await performSyncAliases()
  }
  async function performSyncAliases(knownAuthResume=false) {
    await run('aliases-sync', async () => {
      const result = await control.hme.reconcile(id, {expected_revision:account!.raw.revision,credential_profile:'mailbox'})
      if (!alive(id)) return
      const receipt = result.result
      setSummary(receipt); changed(id); await resource.refresh()
      const skipped = receipt.skipped_forward ? `，${receipt.skipped_forward} 个因转发目的地不同而跳过` : ''
      toast(`目录同步完成，新登记 ${receipt.imported} 个地址${skipped}。`, 'success')
    }, error => appleFailure(error, 'sync-aliases'),false,knownAuthResume)
  }
  async function setAuto(enabled: boolean) {
    if (enabled && !account?.enabled) { setActionError(new Error('主号已停用，请先启用主号。')); return }
    if (enabled && !authenticated) { openApple('enable-auto'); return }
    await performAuto(enabled)
  }
  async function performAuto(enabled: boolean,knownAuthResume=false) {
    await run('auto', async () => {
      let policy = schedule?.raw
      try {if (!policy) policy = (await control.creation.set(id,{expected_revision:'0',maximum_addresses:0,attempts_per_round:5})).result
        if(!alive(id))return
        if (enabled) await control.creation.enable(id,{expected_revision:policy.revision}); else await control.creation.disable(id,{expected_revision:policy.revision}) }
      catch(error) { if(alive(id)&&unknownMutation(error)) setRecovery({kind:'auto'}); throw error }
      if (!alive(id)) return; await resource.refresh(); toast(enabled ? '自动创建已开启。' : '自动创建已关闭。', 'success')
    }, error => appleFailure(error, enabled ? 'enable-auto' : null),false,knownAuthResume)
  }
  async function submitApple(event: FormEvent) {
    event.preventDefault(); if (busy || applePending || appleStep === 'verification' && appleAction === 'trust_browser') return
    if (appleStep === 'login' && !appleForm.password) { setAppleError(new Error('请填写 Apple 账户密码。')); return }
    const action = appleStep === 'login' ? 'login' : appleAction
    if (!action) return
    if ((action === 'verify_device_code' || action === 'verify_sms') && !/^\d{6}$/.test(appleForm.code.trim())) { setAppleError(new Error('请输入 6 位数字验证码。')); return }
    if (action === 'verify_security_key') {setAppleError(new Error('Apple 原站硬件安全密钥交接尚未完成，请勿将此流程视为成功。'));return}
    let resume:Intent=null
    setAppleError(null)
    await run('apple-auth', async () => {
      let step: ProviderAction | null = action
      let current = appleResult
      try {
        while (step && alive(id)) {
          const request_key = newOperationKey('apple')
          const body = step === 'login' ? null : providerInput(step,request_key,current)
          const original = prepareSaved({kind:'provider',source_id:id,action:step,request_key})
          try {
            const response = body === null ? await control.providerSessions.login(id,{request_key,password:appleForm.password}) : await control.providerSessions.action(id,body)
            if (!alive(id)) return
            current = response.result
            resume = await applyApple(current, original)
            step = nextAppleLoginAction(current)
          } catch(error) {providerFailure(original,error);throw error}
        }
      } finally {if(alive(id))setAppleForm(previous=>({...previous,password:'',code:''}))}
    },setAppleError)
    if(resume&&alive(id))await resumeAfterConfirmedAuth(resume)
  }
  function providerInput(action:Exclude<ProviderAction,'login'>,request_key:string,current=appleResult):ProviderActionInput {
    if(!current)throw new Error('请先读取原认证挑战。')
    const common={request_key,challenge_token:current.challenge_token}
    if(action==='verify_device_code')return {...common,action,code:appleForm.code.trim()}
    const selected=current.options?.phones.find(p=>p.id===phone)
    if(action==='send_sms'||action==='verify_sms'){if(!selected)throw new Error('请选择服务器返回的电话号码。');return action==='send_sms'?{...common,action,phone_id:selected.id,mode:selected.mode}:{...common,action,phone_id:selected.id,mode:selected.mode,code:appleForm.code.trim()}}
    if(action==='trust_browser')return {...common,action,confirm_browser_trust:true}
    if(action==='load_challenge'||action==='send_device_code'||action==='decline_trust'||action==='exchange_token'||action==='validate_session')return {...common,action}
    throw new Error('此认证步骤尚不可在当前页面执行。')
  }
  function prepareSaved(input: AccountRecoveryInput): AccountRecovery {
    if (!recoveryActions) throw new ClientStateError('account_session_unconfirmed')
    const original = recoveryActions.prepare(input)
    setInFlightRecord(original)
    setSavedRecovery(previous=>({scope:sourceScope,snapshot:{...(previous.scope===sourceScope?previous.snapshot:{blocked:false,error:null,preserved:[]}),records:[...(previous.scope===sourceScope?previous.snapshot.records.filter(record=>!sameAccountRecovery(original,record)):[]),original]}}))
    refreshSavedRecovery()
    return original
  }
  function settleSaved(original: AccountRecovery) {
    if (!recoveryActions?.settle(original)) return
    refreshSavedRecovery()
  }
  function providerFailure(original:AccountRecovery,error:unknown){
    if(!alive(id))return
    if(error instanceof ControlError&&error.outcome==='not_sent')settleSaved(original)
    else intent.current=null
  }
  async function applyApple(result:ProviderAuthResult,original:AccountRecovery,fromQuery=false):Promise<Intent>{
    if(!alive(id)||original.kind!=='provider')return null
    setAppleResult(result)
    setAppleStep(result.state==='failed' || result.state==='expired' || result.state==='password' && !result.next_action ? 'login' : 'verification')
    if (result.next_action === 'verify_sms' || result.next_action === 'verify_device_code') {
      setFactor(result.next_action === 'verify_sms' ? 'sms' : 'device')
    }
    setPhone(previous=>result.options?.phones.some(p=>p.id===previous)?previous:result.options?.phones[0]?.id||'')
    if(fromQuery)intent.current=null
    const disposition=providerRecoveryDisposition(result)
    setAppleError(appleReceiptError(result, providerLabels[original.action]))
    const previous=knownProviderRef.current
    if(previous&&!sameAccountRecovery(previous,original) && result.durable && result.receipt) settleSaved(previous)
    if(disposition==='pending'){intent.current=null;knownProviderRef.current=null;setAppleOpen(true);refreshSavedRecovery();return null}
    if(disposition==='continue'){knownProviderRef.current=original;setAppleOpen(true);refreshSavedRecovery()}
    else{settleSaved(original);knownProviderRef.current=null;refreshSavedRecovery()}
    if(original.action==='clear_authentication'&&result.receipt?.outcome==='accepted'){
      setAppleOpen(false);setRecovery(null);setSummary(null);await resource.refresh();return null
    }
    if(result.state==='complete'&&result.session?.authenticated&&result.durable&&result.receipt?.outcome==='accepted'){
      const resume=fromQuery?null:intent.current;intent.current=null;setAppleOpen(false);setRecovery(null);await resource.refresh();if(alive(id))toast('Apple 会话已确认。','success');return resume
    }
    return null
  }
  async function resumeAfterConfirmedAuth(next:Exclude<Intent,null>){if(next==='sync-aliases')await performSyncAliases(true);else await performAuto(true,true)}
  async function explicitAppleAction(action:'send_device_code'|'send_sms'|'trust_browser'|'decline_trust'){
    if(applePending || busy || (action==='trust_browser' || action==='decline_trust') && appleAction!=='trust_browser')return
    const request_key=newOperationKey('apple')
    let resume:Intent=null
    setAppleError(null)
    await run(action,async()=>{const body=providerInput(action,request_key),original=prepareSaved({kind:'provider',source_id:id,action,request_key});try{const result=await control.providerSessions.action(id,body);if(alive(id))resume=await applyApple(result.result,original)}catch(error){providerFailure(original,error);throw error}},setAppleError)
    if(resume&&alive(id))await resumeAfterConfirmedAuth(resume)
  }
  async function queryApple(){if(applePending){setAppleError(null);await querySaved(applePending)}}
  async function restartExpiredApple() {
    if (!appleResult || appleResult.state !== 'expired' || !recoveryStore || !recoveryActions) return
    const token = appleResult.challenge_token
    await run('apple-restart', async () => {
      for (const record of recoveryStore.read(id)) {
        if (record.kind !== 'provider') continue
        const query = await recoveryActions.query(control,record,secretReads.current.signal)
        if (!alive(id)) return
        if (query.kind !== 'provider' || query.result.challenge_token !== token || query.result.state !== 'expired' || !query.result.durable) {
          throw new Error('还有另一笔认证请求需要单独核对。')
        }
        recoveryStore.archiveExpiredProvider(record, query.result)
      }
      knownProviderRef.current=null; intent.current=null; setAppleResult(null); setAppleError(null); setAppleStep('login')
      setAppleForm(previous => ({...previous,password:'',code:''}));refreshSavedRecovery()
    },setAppleError,true)
  }
  async function syncMail() {
    await run('mail-sync', async () => { try {const result = await control.synchronization.wake(id); if (!alive(id)) return; await resource.refresh(); toast(result.result.disposition==='coalesced'?'已合并到当前同步轮次。':'同步已入队，将持续刷新处理进度。', 'success')}catch(error){if(alive(id)&&unknownMutation(error))setRecovery({kind:'sync'});throw error} })
  }
  async function confirmAction() {
    const action = confirm
    if (!action || !account) return
    const success = await run(action, async () => {
      if (action === 'disconnect') { const request_key=newOperationKey('apple_clear'),original=prepareSaved({kind:'provider',source_id:id,action:'clear_authentication',request_key});const result=await control.providerSessions.clear(id,{request_key});if(!alive(id))return;await applyApple(result.result,original);if(!alive(id))return;if(result.result.receipt?.outcome!=='accepted')throw appleReceiptError(result.result, '退出 Apple') ?? new Error('请查询原退出请求，核对登录状态。');setSummary(null);toast('Apple 认证已清除。','success') }
      else { await control.accounts.patch(id,{expected_revision:account.raw.revision,enabled:action==='enable'}); if (alive(id)) toast(action === 'enable' ? '主号已启用。' : '主号已停用。', 'success') }
      if (alive(id)) { setConfirm(null); changed(id); await resource.refresh() }
    })
    if (success && alive(id)) setConfirm(null)
  }
  async function addAlias(event: FormEvent) {
    event.preventDefault()
    if ((!appleCreate && !emailPattern.test(aliasDraft.address.trim())) || Array.from(aliasDraft.label).length > 100) { setActionError(new Error('请填写有效邮箱地址，备注最多 100 个字符。')); return }
    await run('add', async () => {
      if(appleCreate){
        const operation_key=newOperationKey('hme'),original=prepareSaved({kind:'hme',source_id:id,operation_key})
        const result=(await control.hme.create(id,{operation_key,expected_revision:account!.raw.revision,label:aliasDraft.label.trim(),group_id:null,credential_profile:'mailbox'})).result
        if(!alive(id))return
        if(result.operation.state==='confirmed'||result.operation.state==='failed')settleSaved(original)
        if(result.operation.state!=='confirmed'){setActionError(new ReceiptError(hmeResultHint(result), {code:result.operation.error_code || result.warning?.code,requestId:operation_key}));return}
      }else await control.addresses.create({source_id:id,address:aliasDraft.address.trim(),label:aliasDraft.label.trim(),group_id:null,enabled:true,credential_profile:'mailbox'})
      if (!alive(id)) return; setAddOpen(false); setAliasDraft({ address: '', label: '' }); changed(id); await resource.refresh(); if(alive(id))toast(appleCreate?'Apple 地址已确认。':'邮箱已登记，凭据可按需读取。', 'success')
    })
  }
  async function generate() {
    const value = Number(count)
    if (!Number.isInteger(value) || value < 1 || value > 1000) { setActionError(new Error('生成数量必须是 1 到 1000 之间的整数。')); return }
    await run('random', async () => { const result = await control.addresses.random({source_id:id,count:value,label:'',group_id:null,credential_profile:'mailbox'}); if (!alive(id)) return; changed(id); await resource.refresh(); toast(`已生成 ${result.result.length} 个随机邮箱。`, 'success') })
  }
  async function loadKeys() {
    setKeysOpen(true); setKeysSaved(false); setKeysError(null)
    await run('keys-load', async () => {
      const result=(await control.credentials.pending(id,{limit:1000})).result
      if(!alive(id))return
      setKeys(result.items.map(delivery=>({delivery})));setKeysMore(result.next_after_id!==null)
    }, setKeysError,true)
  }
  async function revealKeys(full=false){
    const selected=keys;if(!selected)return
    setKeysSaved(false)
    await run(full ? 'keys-reveal-full' : 'keys-reveal',async()=>{
      for(const entry of selected){if(!alive(id))return
        if(full){
          if(!entry.delivery.bundle_available||entry.revoked)continue
          const original=(await control.credentials.revealPending(id,entry.delivery.delivery_key,secretReads.current.signal)).result
          if(!alive(id))return
          if(original.revoked){setKeys(previous=>previous?.map(item=>item.delivery.delivery_key===entry.delivery.delivery_key?{delivery:original.delivery,apiKey:original.secret.api_key,revoked:true,links:null}:item)??null);continue}
          const result=(await control.credentials.revealPendingBundle(id,entry.delivery.delivery_key,entry.delivery.generation,secretReads.current.signal)).result
          if(alive(id))setKeys(previous=>previous?.map(item=>item.delivery.delivery_key===entry.delivery.delivery_key?{delivery:result.delivery,bundle:result.bundle,apiKey:result.bundle.api.key,links:result.links,revoked:false}:item)??null)
        }else{
          const result=(await control.credentials.revealPending(id,entry.delivery.delivery_key,secretReads.current.signal)).result
          if(alive(id))setKeys(previous=>previous?.map(item=>item.delivery.delivery_key===entry.delivery.delivery_key?{...item,delivery:result.delivery,apiKey:result.secret.api_key,revoked:result.revoked,links:result.links}:item)??null)
        }
      }
    },setKeysError,true)
  }
  async function completeKeys(){
    const selected=keys?.filter(entry=>entry.delivery.current&&!entry.delivery.deleted&&entry.delivery.lifecycle==='confirmed'&&!entry.delivery.bundle_available&&!entry.revoked)
    if(!selected?.length)return
    setKeysSaved(false)
    await run('keys-complete',async()=>{
      for(const entry of selected){if(!alive(id))return
        const original=prepareSaved({kind:'complete',source_id:id,delivery_key:entry.delivery.delivery_key,generation:entry.delivery.generation})
        const result=(await control.credentials.completePending(id,entry.delivery.delivery_key,entry.delivery.generation)).result
        if(alive(id)){settleSaved(original);setKeys(previous=>previous?.map(item=>item.delivery.delivery_key===entry.delivery.delivery_key?{...item,delivery:result}:item)??null)}
      }
    },setKeysError)
  }
  async function ackKeys() {
    if (!keysSaved || !keys?.length || !jsonlExport) return
    const selected=keys.filter(item=>item.apiKey||item.bundle).map(item=>item.delivery.delivery_key)
    if(selected.length!==keys.length)return
    await run('keys-ack', async () => { const original=prepareSaved({kind:'ack',source_id:id,delivery_keys:selected});await control.credentials.acknowledge(id,selected);if (!alive(id)) return;settleSaved(original);setKeys([]);setKeysSaved(false);await resource.refresh();if(alive(id))toast('已确认保存，未改变邮箱状态或凭据效力。','success') }, setKeysError)
  }
  async function querySaved(original:AccountRecovery){
    if(!recoveryActions||!alive(id))return
    intent.current=null
    await run('query-saved:'+accountRecoveryLabel(original),async()=>{
      const result=await recoveryActions.query(control,original,secretReads.current.signal)
      if(!alive(id))return
      if(result.kind==='provider'){await applyApple(result.result,original,true);return}
      if(result.kind==='hme'){
        if(result.result.operation.state==='confirmed'||result.result.operation.state==='failed')settleSaved(original)
        if(result.result.operation.state==='confirmed'){setAddOpen(false);changed(original.source_id)}
        else setActionError(new ReceiptError(hmeResultHint(result.result), {code:result.result.operation.error_code || result.result.warning?.code,requestId:result.result.operation.operation_key}))
      }else if(result.kind==='ack'){
        if(result.acknowledged){settleSaved(original);setKeys([]);setKeysSaved(false)}
        else setKeysError(new Error('原确认仍有待核对记录，请保留凭据，不要重新提交。'))
      }else{
        settleSaved(original);setKeysSaved(false);setKeysError(null);setKeysOpen(true)
        setKeys(previous=>previous?.some(item=>item.delivery.delivery_key===result.item.delivery.delivery_key)?previous.map(item=>item.delivery.delivery_key===result.item.delivery.delivery_key?result.item:item):[...(previous??[]),result.item])
      }
      if(alive(id))await resource.refresh()
    },original.kind === 'provider' ? error => { setAppleError(error); setAppleOpen(true) } : setActionError,true)
  }
  async function queryRecovery(){const original=recovery;if(!original)return;await run('query-original',async()=>{
    if(original.kind==='auto'){await control.creation.get(id);if(alive(id))setRecovery(null)}
    else if(original.kind==='sync'){const observed=await control.synchronization.get(id);if(alive(id)&&observed.result.progress!==null)setRecovery(null)}
    else if(original.kind==='attempt'){const fact=(await control.creation.attempt(id,original.id)).result;if(alive(id)&&['confirmed','not_created','cancelled'].includes(fact.state))setRecovery(null)}
    if(alive(id))await resource.refresh()
  },setActionError,true)}
  async function resolveAttempt(){const attempt=schedule?.raw?.pending_attempt;if(!attempt)return;await run('resolve-attempt',async()=>{try{await control.creation.resolve(id,attempt.id)}catch(error){if(alive(id)&&unknownMutation(error))setRecovery({kind:'attempt',id:attempt.id});throw error};if(alive(id))await resource.refresh()})}
  async function revealSource(){await run('source-reveal',async()=>{const value=await control.accounts.reveal(id);if(alive(id))setSourceSecret(value.result.credentials.imap_password)},undefined,true)}
  const exports=pendingKeyExports(keys??[],window.location.origin),otpExport=exports.otp,imapExport=exports.imap,jsonlExport=exports.jsonl
  const blocked=Boolean(busy)||recovery!==null||recoverySnapshot.blocked||visibleRecoveries.length>0
  const receiptError = appleError instanceof ReceiptError
  const appleErrorTitle = receiptError && appleResult?.receipt ? ({
    login: 'Apple 登录未完成', verify_device_code: '设备验证码未通过', verify_sms: '短信验证码未通过',
    send_device_code: '设备验证码发送未确认', send_sms: '短信发送未完成', trust_browser: '浏览器信任未完成',
    exchange_token: '登录会话未建立',
  } as Partial<Record<ProviderAction, string>>)[appleResult.receipt.action] : undefined
  const appleAction = appleVerificationAction(appleResult, factor)
  const submittingApple = busy === 'apple-auth'
  const appleLoadingLabel = inFlightRecord?.kind === 'provider' ? '正在' + providerLabels[inFlightRecord.action] + '…' : '正在登录…'
  const appleActionLabel = appleAction && providerLabels[appleAction] || (appleAction === 'verify_security_key' ? '验证安全密钥' : 'Apple 认证')
  const choosingTrust = appleStep === 'verification' && appleAction === 'trust_browser'
  const progressStep = inFlightRecord?.kind === 'provider' && busy ? inFlightRecord.action : null
  const appleNeedsCode = appleStep === 'verification' && (appleAction === 'verify_device_code' || appleAction === 'verify_sms')
  useEffect(() => {
    if (appleOpen && appleNeedsCode && !blocked && !appleError) appleStepPanel.current?.querySelector<HTMLInputElement>('input[autocomplete="one-time-code"]')?.focus()
  }, [appleOpen, appleNeedsCode, blocked, appleError])
  if (!account || account.id !== id) return <div className="stack"><PageHeader title="主号详情" actions={<Button variant="ghost" asChild><Link to="/accounts"><ArrowLeft size={14} /> 返回</Link></Button>} />{resource.error ? <><Alert context="read" error={resource.error} /><RefreshButton variant="outline" pending={resource.loading || resource.manualRefreshing} onRefresh={resource.refresh} loadingLabel="重新读取中…">重新读取</RefreshButton></> : <Panel><Loading label="正在读取主号…" /></Panel>}</div>
  return <div className="stack"><PageHeader eyebrow={<Link className="text-link" to="/accounts">WORKSPACE / ACCOUNTS</Link>} title={accountIdentity(account)} description={account.name || '管理连接、Apple 会话与所属隐私邮箱。'} actions={<><Button variant="outline" disabled={blocked || !account.enabled || account.syncProgress?.active} aria-busy={busy === 'mail-sync' || !!account.syncProgress?.active} onClick={() => void syncMail()}><RefreshIcon refreshing={busy === 'mail-sync' || !!account.syncProgress?.active} size={14} />{busy === 'mail-sync' || account.syncProgress?.active ? '同步处理中' : '同步邮件'}</Button><Button variant="secondary" asChild><Link to={`/accounts/${id}/edit`}>编辑主号</Link></Button></>} />
    {(actionError && !confirm && !addOpen || resource.error) && <Alert context={!confirm && !addOpen && actionError ? 'action' : 'read'} error={!confirm && !addOpen && actionError || resource.error} attention={actionError ? "focus" : "notify"} />}{resource.data?.errors.map((error,index)=><Alert key={index} context="read" error={error}/>)}{recovery && <Alert tone="warning"><div className="stack"><span>原操作结果尚未确认，保留原引用，仅查询，不会重新提交。</span>{recovery.kind==='attempt'&&<code>原尝试 #{recovery.id}</code>}<Button variant="outline" disabled={Boolean(busy)} loading={busy === 'query-original'} loadingLabel="正在查询…" onClick={()=>void queryRecovery()}>查询原操作结果</Button></div></Alert>}
    {recoverySnapshot.blocked&&<Alert tone="warning"><div className="stack"><span>原操作记录暂不可完整读取或保存。已读取的原标识仍可查询；新的提交暂时停用，请保留浏览器数据。</span><Button variant="outline" disabled={Boolean(busy)} onClick={refreshSavedRecovery}>重新读取操作记录</Button></div></Alert>}
    {visibleRecoveries.some(record => !appleOpen || record.kind !== 'provider')&&<Alert tone="warning"><div className="stack"><span>已保留主号 #{id} 的原操作引用。查询不会重新提交、确认凭据或发起新的认证动作。</span>{visibleRecoveries.filter(record => !appleOpen || record.kind !== 'provider').map(original=><div className="stack" key={accountRecoveryLabel(original)}><details><summary>查看原操作标识</summary><code className="mono break-all">{accountRecoveryLabel(original)}</code></details><div className="row-actions"><CopyButton value={accountRecoveryCopyValue(original)} label="复制原标识"/><Button variant="outline" disabled={Boolean(busy)} loading={busy === 'query-saved:'+accountRecoveryLabel(original)} loadingLabel="正在查询…" onClick={()=>void querySaved(original)}>查询原请求</Button></div></div>)}</div></Alert>}
    <Panel title={<span className="row-actions"><Server size={16} /> IMAP 连接与同步</span>} actions={<div className="row-actions">{!account.syncProgress?.active && <SyncState account={account} />}<Button variant="outline" size="sm" disabled={blocked} loading={busy === 'source-reveal'} loadingLabel="正在读取…" onClick={()=>void revealSource()}>查看连接凭据</Button></div>}><dl className="detail-facts"><div><dt>收件规则</dt><dd>{receiveLabel(account)}</dd></div><div><dt>IMAP 服务</dt><dd className="mono">{formatIMAPEndpoint(account)}</dd></div><div><dt>登录身份</dt><dd>{account.imapUsername}</dd></div><div><dt>最近同步</dt><dd>{formatTime(account.lastSyncedAt, { seconds: true })}</dd></div><div><dt>所属邮箱</dt><dd>{account.aliasCount ?? '未提供'} 个</dd></div><div><dt>邮箱类型</dt><dd>{custom ? `自定义 · @${account.emailSuffix}` : 'iCloud 隐私邮箱'}</dd></div></dl>{account.syncProgress?.active && <div className="account-sync-progress"><SyncState account={account} details /></div>}{account.lastSyncError && <div className="stack"><Alert tone={directoryLoginRestored ? 'info' : 'warning'} title="上次同步提示" diagnostics={{code:account.lastSyncError}}>{directoryLoginRestored ? '上次同步目录时 Apple 会话已失效。当前已登录，可以再次同步隐私邮箱。' : diagnosticMessage(account.lastSyncError, '本轮同步有步骤未完成，请查看同步诊断。')}</Alert><div className="panel-actions"><Button variant="secondary" size="sm" onClick={() => setErrorOpen(true)}>查看同步诊断</Button></div></div>}</Panel>
    {!custom ? <Panel title={<span className="row-actions"><ShieldCheck size={16} /> Apple 账户</span>} description="连接隐私邮箱目录，管理自动创建计划。" actions={<Badge tone={authenticated ? 'success' : apple?.status === 'expired' ? 'warning' : 'neutral'}>{authenticated ? 'Apple 已登录' : apple?.status === 'expired' ? 'Apple 登录已过期' : apple ? 'Apple 未登录' : '登录状态暂不可用'}</Badge>}>
      <div className="account-session"><div className="session-summary"><strong>{apple?.appleId || account.email}</strong><p>{apple?.region === 'cn' ? '中国大陆' : '全球'}{apple?.expiresAt ? ` · 有效期至 ${formatTime(apple.expiresAt)}` : authenticated ? ' · 会话已保存' : ' · 登录后即可同步目录'}</p></div><div className="session-actions"><Button variant="outline" size="sm" disabled={blocked||!account.enabled} onClick={()=>{setAppleCreate(true);setAliasDraft({address:'',label:''});setAddOpen(true)}}><Plus size={14}/>创建隐私邮箱</Button><Button variant="secondary" size="sm" disabled={blocked || !account.enabled} aria-busy={busy === 'aliases-sync'} onClick={() => void syncAliases()}><RefreshIcon refreshing={busy === 'aliases-sync'} size={14} />{busy === 'aliases-sync' ? '目录同步中…' : '同步隐私邮箱'}</Button><Button variant="outline" size="sm" disabled={Boolean(busy)} onClick={() => openApple()}><LogIn size={14} />{applePending?'查询原认证':authenticated ? '重新登录' : '登录 Apple'}</Button>{authenticated && <Button variant="outline" size="sm" disabled={blocked} onClick={() => { setActionError(null); setConfirm('disconnect') }}><LogOut size={14} />退出 Apple</Button>}</div></div>
      {summary && <div className="notice">上次目录同步共读取 {summary.active + summary.inactive} 个地址，新增 {summary.imported}，已存在 {summary.existing}，Apple 已停用 {summary.inactive}，因本地容量暂未启用 {summary.pending}，冲突 {summary.conflicts}。
        {summary.skipped_forward > 0 && <>其中 {summary.skipped_forward} 个地址的转发目的地与本主号配置的收件邮箱不同，已跳过。</>}
      </div>}
      <AliasArchiveSyncNotice accountId={id} summary={summary} />
      {schedule ? <section className="auto-create-section"><div className="automation-heading"><div><h3>自动创建隐私邮箱</h3><p>按当前服务器策略分轮安排，具体时间以返回的计划为准。</p></div><div className="session-actions"><Badge tone={schedule.status === 'error' ? 'danger' : schedule.enabled ? 'success' : 'neutral'}>{autoStatus[schedule.status] || '状态待核对'}</Badge><Button variant={schedule.enabled ? 'outline' : 'secondary'} size="sm" disabled={blocked || (!schedule.enabled && !account.enabled)} loading={busy === 'auto'} loadingLabel="正在更新…" onClick={() => void setAuto(!schedule.enabled)}>{schedule.enabled ? '关闭自动创建' : '开启自动创建'}</Button></div></div><dl className="detail-facts"><div><dt>下次执行</dt><dd>{formatTime(schedule.nextRunAt, { seconds: true })}</dd></div><div><dt>计划时间</dt><dd>{(schedule.plannedTimes?.length ? schedule.plannedTimes : schedule.plannedAt ? [schedule.plannedAt] : []).length ? (schedule.plannedTimes?.length ? schedule.plannedTimes : [schedule.plannedAt]).map((time: string|null) => <span className="schedule-time" key={time}>{formatTime(time, { seconds: true })}</span>) : '暂无计划'}</dd></div><div><dt>最近尝试</dt><dd>{formatTime(schedule.lastAttemptedAt, { seconds: true })}</dd></div><div><dt>最近创建</dt><dd>{formatTime(schedule.lastCreatedAt, { seconds: true })}{schedule.lastAliasAddress && <small className="mono">{schedule.lastAliasAddress}</small>}</dd></div></dl>{schedule.lastError && <Alert tone="warning" title="自动创建提示" diagnostics={{code:schedule.lastError}}>{diagnosticMessage(schedule.lastError, '自动创建遇到问题，请查看最近的创建记录。')}</Alert>}{schedule.raw?.pending_attempt && <div className="panel-actions"><span className="text-muted">原尝试 #{schedule.raw.pending_attempt.id} · {creationAttemptLabels[schedule.raw.pending_attempt.state] || '状态待核对'}</span><Button variant="outline" size="sm" disabled={blocked} loading={busy === 'resolve-attempt'} loadingLabel="正在核对…" onClick={()=>void resolveAttempt()}>解析原尝试</Button></div>}<div className="panel-actions"><Button variant="secondary" size="sm" disabled={blocked} onClick={() => void loadKeys()}>领取自动创建凭据</Button><Button variant="outline" size="sm" asChild><Link to={`/activity?account_id=${encodeURIComponent(id)}`}>查看主号日志<ArrowUpRight size={14} /></Link></Button></div></section> : <p className="text-muted">自动创建状态暂不可用。</p>}
    </Panel> : <Panel title="生成自定义邮箱" description={`按 8–12 位随机英文数字 + @${account.emailSuffix} 生成；不调用 Apple，主号累计数量不设上限。`}><div className="field-row"><Field label="本次生成数量（1–1000）"><Input type="number" min={1} max={1000} value={count} disabled={blocked} onChange={e => setCount(e.target.value)} /></Field><Button disabled={blocked || !account.enabled || account.syncProgress?.active} loading={busy === 'random'} loadingLabel="正在生成…" onClick={() => void generate()}>生成随机邮箱</Button></div></Panel>}
    <Panel title="所属隐私邮箱" description="搜索、分组、复制、轮换、停用和发信均使用当前主号范围。" actions={<Button variant="outline" disabled={blocked} onClick={() => { setAliasDraft({ address: '', label: '' }); setAppleCreate(false); setActionError(null); setAddOpen(true) }}><Plus size={14} /> 手动登记</Button>}><AliasList accountId={id} embedded /></Panel>
    <Panel title="主号操作" description="停用会阻止所属邮箱取件。删除主号会撤销本地访问并进入可查询的清理流程。远端 Apple 账号与邮箱保持。"><div className="row-actions"><Button variant="outline" disabled={blocked} onClick={() => { setActionError(null); setConfirm(account.enabled ? 'disable' : 'enable') }}>{account.enabled ? '停用主号' : '启用主号'}</Button><Button variant="destructive" disabled={blocked} onClick={() => setConfirm('delete')}>删除主号</Button></div></Panel>
    <Modal open={Boolean(confirm) && confirm !== 'delete'} onOpenChange={open => { if (!open && !busy) setConfirm(null) }} title={confirm === 'delete' ? '永久删除主号' : confirm === 'disconnect' ? '退出 Apple 登录' : confirm === 'disable' ? '停用主号' : '启用主号'} description={confirm === 'delete' ? `仅删除空主号 ${accountIdentity(account)}。如有关联数据，服务器会拒绝删除并保留它们。` : confirm === 'disconnect' ? '退出后，目录同步、自动创建和发信可能需要重新登录 Apple。IMAP 连接单独管理。' : confirm === 'disable' ? '所属隐私邮箱的全部取件凭据会立即失效，并停止此主号的同步。' : '恢复主号同步与所属邮箱的取件能力。'} footer={<><Button variant="outline" disabled={blocked} onClick={() => setConfirm(null)}>取消</Button><Button variant={confirm === 'delete' || confirm === 'disable' ? 'destructive' : 'default'} disabled={blocked} loading={Boolean(busy)} loadingLabel="正在处理…" onClick={() => void confirmAction()}>确认操作</Button></>}>{Boolean(actionError) && <Alert error={actionError} attention="focus">{accountErrorHint(actionError)}</Alert>}<p className="mono">{accountIdentity(account)}</p></Modal>
    {confirm === 'delete' && <LocalCleanupDialog key={id} sourceID={id} revision={account.raw.revision} confirmation={account.raw.address_namespace} onClose={() => setConfirm(null)} onAccepted={() => { changed(id); navigate('/accounts', { replace: true }) }} />}
    <Modal open={sourceSecret!==null} onOpenChange={open=>{if(!open)setSourceSecret(null)}} title="连接凭据" description="仅在本弹窗短暂持有，关闭后清除页面引用。" footer={<CopyButton value={sourceSecret||''} label="复制 IMAP 密码"/>}><Input type="password" readOnly value={sourceSecret||''} aria-label="当前连接密码"/></Modal><Modal open={errorOpen} onOpenChange={setErrorOpen} title="完整同步诊断" description="诊断是纯文本展示，不执行其中的 HTML。" wide footer={<CopyButton value={account.lastSyncErrorLog || account.lastSyncError || ''} label="复制完整诊断" />}><pre className="mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: '55vh', overflow: 'auto' }}>{account.lastSyncErrorLog || account.lastSyncError}</pre><Link className="text-link" to={`/activity?account_id=${encodeURIComponent(id)}`} onClick={() => setErrorOpen(false)}>查看主号运行日志</Link></Modal>
    <Modal open={addOpen} onOpenChange={open => { if (!busy) setAddOpen(open) }} title={appleCreate?'创建 Apple 隐私邮箱':'手动登记邮箱'} description={appleCreate?'只发送一次明确创建请求；结果未确认时查询原请求，不重新创建。':custom ? `填写 @${account.emailSuffix} 下的地址，仅登记本地取件身份。` : '登记已经存在的隐私邮箱地址；此操作不会在 Apple 创建新地址。'} footer={<><Button variant="outline" disabled={blocked} onClick={() => setAddOpen(false)}>取消</Button><Button type="submit" form="register-alias" disabled={blocked} loading={busy === 'add'} loadingLabel="正在处理…">{appleCreate?'创建隐私邮箱':'登记邮箱'}</Button></>}><form id="register-alias" className="stack" onSubmit={addAlias}>{!appleCreate && <Field label="邮箱地址"><Input required type="email" value={aliasDraft.address} disabled={blocked} onChange={e => setAliasDraft(previous => ({ ...previous, address: e.target.value }))} /></Field>}<Field label="用途备注"><Input maxLength={100} value={aliasDraft.label} disabled={blocked} onChange={e => setAliasDraft(previous => ({ ...previous, label: e.target.value }))} /></Field>{Boolean(actionError) && <Alert error={actionError} attention="focus">{accountErrorHint(actionError)}</Alert>}</form></Modal>
    <Modal open={appleOpen} onOpenChange={open => { if (!open) closeApple() }}
      title={applePending ? '核对 Apple 登录' : choosingTrust ? '要信任此登录环境吗？' : appleNeedsCode ? (appleAction === 'verify_sms' ? '输入短信验证码' : '输入设备验证码') : appleStep === 'verification' ? appleActionLabel : '登录 Apple 账户'}
      description={appleStep === 'verification' ? (appleNeedsCode ? '请输入受信任设备或手机上显示的六位数字。' : undefined) : '如需设备验证，继续后会请求一次验证码。'}
      footer={<>
        <Button variant="outline" disabled={Boolean(busy)} onClick={closeApple}>取消</Button>
        {appleStep === 'verification' && !choosingTrust && !applePending && <Button variant="ghost" disabled={blocked} onClick={() => { setAppleStep('login'); setAppleError(null); setAppleForm(previous => ({ ...previous, password: '', code: '' })) }}>返回登录</Button>}
        {choosingTrust && !applePending && <>
          <Button type="button" variant="outline" disabled={blocked} loading={busy === 'decline_trust'} loadingLabel="正在选择…" onClick={() => void explicitAppleAction('decline_trust')}>仅本次登录</Button>
          <Button type="button" variant="secondary" disabled={blocked} loading={busy === 'trust_browser'} loadingLabel="正在请求信任…" onClick={() => void explicitAppleAction('trust_browser')}>信任此登录环境</Button>
        </>}
        {!applePending && !choosingTrust && <Button type="submit" form="apple-auth" disabled={blocked || appleStep === 'verification' && (!appleAction || appleAction === 'verify_security_key')} aria-live="polite" loading={submittingApple} loadingLabel={appleLoadingLabel}>{appleStep === 'verification' ? (appleNeedsCode ? '验证验证码' : appleActionLabel) : '继续'}</Button>}
      </>}>
      <form id="apple-auth" className="stack" onSubmit={submitApple}>
        {applePending && <Alert tone="warning" title="核对上次登录" error={appleError || undefined} diagnostics={{ ...feedbackDetails(appleError), requestId:applePending.request_key }}><div className="stack"><span>{appleResult?.state === 'expired' ? '上次登录已过期，可以保留原回执并开始新的登录。' : !appleError && '上次请求尚无确认结果，请查询后继续。'}</span>
          <Button type="button" variant="outline" disabled={Boolean(busy)} loading={busy === 'query-saved:'+accountRecoveryLabel(applePending)} loadingLabel="正在查询…" onClick={()=>void queryApple()}>查询原认证结果</Button>
          {appleResult?.state === 'expired' && <Button type="button" disabled={Boolean(busy)} onClick={()=>void restartExpiredApple()}>保留回执并重新登录</Button>}
        </div></Alert>}
        {!applePending && Boolean(appleError) && <Alert error={appleError} title={appleErrorTitle} tone={receiptError && appleResult?.receipt?.action === 'send_device_code' && appleResult.receipt.outcome === 'rejected' ? 'warning' : undefined} attention="focus">{accountErrorHint(appleError)}</Alert>}
        {progressStep && !applePending && <p role="status" className="request-progress">{appleLoadingLabel}</p>}
        <AnimatePresence initial={false}>{applePending ? null : appleStep === 'login' ?
          <AnimatedSection key="apple-login" className="stack" ref={appleStepPanel} onAnimationComplete={focusAppleStep}>
            <Field label="Apple ID"><Input required autoComplete="username" value={appleForm.appleId} disabled /></Field>
            <Field label="Apple 账户密码"><Input required type="password" autoComplete="current-password" value={appleForm.password} disabled={blocked} onChange={e => setAppleForm(previous => ({ ...previous, password: e.target.value }))} /></Field>
            <Field label="Apple 服务区域"><Select value={appleForm.region} disabled><option value="global">全球</option><option value="cn">中国大陆</option></Select></Field>
          </AnimatedSection> :
          <AnimatedSection key="apple-verification" className="stack" ref={appleStepPanel} onAnimationComplete={focusAppleStep}>
            {choosingTrust && <div className="stack"><strong>身份验证已通过</strong><p>选择“仅本次登录”可继续建立当前会话。选择“信任此登录环境”会让 Apple 记住 iCloudSpace 的登录环境，以后可能减少验证次数。</p></div>}
            {appleAction === 'exchange_token' && <p role="status">{appleResult?.receipt?.action === 'trust_browser' ? 'Apple 已接受信任请求。' : appleResult?.receipt?.action === 'decline_trust' ? '已选择仅本次登录。' : 'Apple 已接受登录凭据。'}点击“完成登录”建立并保存主号会话。</p>}
            {appleAction === 'validate_session' && <p>请验证已保存的会话。验证成功后会更新主号登录状态。</p>}
            {!appleAction && !progressStep && !appleError && <p role="status">{appleResult?.state === 'complete' && appleResult.session?.authenticated ? '此认证流程已完成，主号已登录。可以关闭窗口。' : '本次认证尚无可执行的下一步。请关闭窗口后核对主号状态。'}</p>}
            {appleAction === 'verify_security_key' && <Alert tone="warning">此账户要求使用硬件安全密钥，请前往 Apple 完成验证。</Alert>}
            {appleAction === 'load_challenge' && <p>请重新读取 Apple 为本次登录提供的验证方式。</p>}
            {appleNeedsCode && <>
              {!busy && deviceDispatchAccepted(appleResult) && appleAction === 'verify_device_code' && <p role="status">Apple 已受理发码请求，请查看受信任设备上的验证码。</p>}
              {!busy && appleResult?.receipt?.action === 'send_sms' && appleResult.receipt.outcome === 'accepted' && appleAction === 'verify_sms' && <p role="status">已请求短信验证码，请查看接收短信的手机。</p>}
              <div className="row-actions">
                {appleResult?.options?.trusted_device && appleResult.options.sms && <Select aria-label="验证方式" value={appleAction === 'verify_sms' ? 'sms' : 'device'} disabled={blocked} onChange={e => { setFactor(e.target.value === 'sms' ? 'sms' : 'device'); setAppleError(null); setAppleForm(previous => ({...previous,code:''})) }}><option value="device">受信任设备</option><option value="sms">短信验证码</option></Select>}
                {appleAction === 'verify_device_code' && <Button type="button" variant="outline" disabled={blocked} loading={busy === 'send_device_code'} loadingLabel="正在发送…" onClick={() => void explicitAppleAction('send_device_code')}>重新发送设备验证码</Button>}
                {appleAction === 'verify_sms' && appleResult?.options && <><Select aria-label="电话号码" value={phone} disabled={blocked} onChange={e => {setPhone(e.target.value);setAppleError(null);setAppleForm(previous => ({...previous,code:''}))}}>{appleResult.options.phones.map(p => <option key={p.id} value={p.id}>{p.display}</option>)}</Select><Button type="button" variant="outline" disabled={blocked} loading={busy === 'send_sms'} loadingLabel="正在发送…" onClick={() => void explicitAppleAction('send_sms')}>发送短信</Button></>}
              </div>
              {!busy && appleAction === 'verify_device_code' && appleResult?.receipt?.action !== 'send_device_code' && <p>在受信任设备上允许登录，随后输入显示的验证码。</p>}
              <Field label="6 位验证码"><Input required inputMode="numeric" autoComplete="one-time-code" maxLength={6} pattern="[0-9]{6}" value={appleForm.code} disabled={blocked} onChange={e => setAppleForm(previous => ({ ...previous, code: e.target.value }))} /></Field>
            </>}
          </AnimatedSection>}</AnimatePresence>
        {intent.current && <p className="text-muted">会话确认后继续您已选择的{intent.current === 'sync-aliases' ? '同步隐私邮箱目录' : '开启自动创建'}。</p>}
      </form>
    </Modal>
    <Modal open={keysOpen} onOpenChange={open => { if (!busy) { setKeysOpen(open); if (!open) { setKeys(null); setKeysSaved(false); setKeysRefreshFeedback(false) } } }} title="凭据待领取" description="读取不会清空队列。保存到可信位置后，再明确确认；确认不会删除邮箱或改变其状态。" wide footer={<>
      <RefreshButton variant="outline" pending={busy === 'keys-load'} disabled={blocked} onRefresh={loadKeys} onBusyChange={setKeysRefreshFeedback} loadingLabel="正在查询…">重新查询</RefreshButton>
      <Button disabled={blocked || !keysSaved || !keys?.length || !jsonlExport || recovery!==null || keys?.some(k=>!k.apiKey&&!k.bundle)} loading={busy === 'keys-ack'} loadingLabel="正在确认…" onClick={() => void ackKeys()}>确认已保存</Button>
    </>}><div className="stack">
      {Boolean(keysError) && <Alert error={keysError} attention="focus">{accountErrorHint(keysError)}</Alert>}
      <RefreshRegion loading={busy === 'keys-load' || keysRefreshFeedback} label="正在读取凭据…"><div className="stack">{keys?.length ? <>
        <p>本批 {keys.length} 条待领取记录。凭据仅在明确读取后用于复制，不在列表中显示。</p>
        {keysMore&&<Alert tone="warning">当前批次最多1000条，保存并确认后重新查询余下记录。</Alert>}
        <div className="row-actions">
          <Button variant="outline" disabled={blocked} loading={busy === 'keys-reveal'} loadingLabel="正在读取…" onClick={()=>void revealKeys(false)}>读取取码凭据</Button>
          <Button variant="outline" disabled={blocked||!keys.some(k=>k.delivery.bundle_available&&!k.revoked)} loading={busy === 'keys-reveal-full'} loadingLabel="正在读取…" onClick={()=>void revealKeys(true)}>读取已生成的完整凭据</Button>
          {keys.some(k=>k.delivery.current&&!k.delivery.deleted&&k.delivery.lifecycle==='confirmed'&&!k.delivery.bundle_available&&!k.revoked)&&<Button variant="outline" disabled={blocked} loading={busy === 'keys-complete'} loadingLabel="正在补齐…" onClick={()=>void completeKeys()}>补齐缺少的完整凭据</Button>}
        </div>
        <div className="row-actions">{otpExport&&<CopyButton value={otpExport} label="复制取码格式" />}{imapExport&&<CopyButton value={imapExport} label="复制 IMAP/OAuth 格式" />}{jsonlExport&&<CopyButton value={jsonlExport} label="复制 JSONL 备份" />}</div>
        <p className="text-muted">标准格式仅包含当前未撤销凭据。旧凭据可单独保存在 JSONL 备份中；归档、停用和待确认邮箱仍不能取件。</p>
        <ul className="stack">{keys.map(key=><li key={key.delivery.delivery_key} className="detail-section">
          <div className="detail-section-heading"><strong className="break-all">{key.delivery.address}</strong><Badge>{pendingKeyStatus(key)}</Badge></div>
          <p className="text-muted">{key.delivery.label&&<>{key.delivery.label} · </>}{key.delivery.source_label} · {pendingKeyMaterialStatus(key)}</p>
          <details className="operation-details"><summary>查看交付标识</summary><p className="mono">地址 #{key.delivery.address_id} · 代次 {key.delivery.generation} · {key.delivery.delivery_key}</p></details>
        </li>)}</ul>
        <label className="checkbox-label"><Checkbox checked={keysSaved} onCheckedChange={checked=>setKeysSaved(checked===true)} /><span>我已将本批所需凭据保存到可信位置</span></label>
      </> : keys ? <Empty title={keysMore?'当前批次已确认':'没有待确认凭据'} description={keysMore?'请重新查询余下待领取记录。':'已签发的凭据仍可在邮箱列表按需复制。'} /> : <div className="min-h-24" />}</div></RefreshRegion>
    </div></Modal>
  </div>
}
