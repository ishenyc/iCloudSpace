import type { Account, AccountCreate, AccountPatch } from '../../control/contracts.ts'
import type { AccountsModel } from '../../control/accounts.ts'
import type { AddressesModel } from '../../control/addresses.ts'
import type { ProviderSessionsModel } from '../../control/provider-sessions.ts'
import type { ProviderSessionStatus } from '../../control/provider-session-contracts.ts'
import type { CreationModel } from '../../control/creation.ts'
import type { CreationPolicy } from '../../control/creation-contracts.ts'
import type { SynchronizationModel } from '../../control/synchronization.ts'
import type { SyncProgress, Synchronization } from '../../control/sync-contracts.ts'
import type { CredentialBundle, CredentialDelivery } from '../../control/credential-contracts.ts'
import type { CredentialsModel } from '../../control/credentials.ts'
import { credentialCopyText } from '../../control/credential-copy.ts'
import type { CredentialCopyLinks } from '../../control/credential-copy.ts'
import { ControlError } from '../../transport/index.ts'

export type AccountForm = { name: string; email: string; mailboxType: string; emailSuffix: string; receivingAddress: string; appleRegion: 'global' | 'china'; imapHost: string; imapPort: string; imapUsername: string; imapPassword: string; enabled: boolean }
export const DEFAULT_IMAP_HOST = 'imap.mail.me.com', DEFAULT_IMAP_PORT = 993
export const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
export const normalizeSuffix = (value: string) => value.trim().replace(/^@+/, '').replace(/\.$/, '').toLowerCase()
export function initialAccountForm(): AccountForm { return { name: '', email: '', mailboxType: 'icloud', emailSuffix: '', receivingAddress: '', appleRegion: 'global', imapHost: DEFAULT_IMAP_HOST, imapPort: '993', imapUsername: '', imapPassword: '', enabled: true } }
export function normalizeIMAPEndpoint(host: string, port: string | number) {
  host = host.trim().toLowerCase().replace(/\.$/, '')
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)
  return { host, port: Number(port) }
}
function validHost(value: string): boolean {
  if (!value || value.length > 253 || /[\s/@?#\\]/.test(value)) return false
  if (value.includes(':')) { try { return new URL('https://[' + value + ']/').hostname !== '' } catch { return false } }
  return value.split('.').every(part => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(part))
}
export function isForwardedICloudIMAP(form: Pick<AccountForm, 'mailboxType' | 'imapHost' | 'imapPort'> & Partial<Pick<AccountForm,'receivingAddress'|'email'>>): boolean {
  const endpoint = normalizeIMAPEndpoint(form.imapHost, form.imapPort)
  return form.mailboxType === 'icloud' && (endpoint.host !== DEFAULT_IMAP_HOST || endpoint.port !== DEFAULT_IMAP_PORT || Boolean(form.receivingAddress && form.email && form.receivingAddress.toLowerCase() !== form.email.toLowerCase()))
}
export function validateAccountForm(form: AccountForm, editing: boolean): string | null {
  const endpoint = normalizeIMAPEndpoint(form.imapHost, form.imapPort)
  if (!validHost(endpoint.host)) return '填写不含协议、路径或端口的有效 IMAP 主机。'
  if (!/^[1-9][0-9]{0,4}$/.test(form.imapPort) || endpoint.port > 65535) return 'IMAP 端口必须是 1 到 65535 的整数。'
  if (Array.from(form.name).length > 80) return '备注不能超过 80 个字符。'
  if (!['icloud', 'custom'].includes(form.mailboxType)) return '请选择有效邮箱类型。'
  if (!form.imapUsername.trim()) return '请填写 IMAP 用户名。'
  if (!emailPattern.test(form.receivingAddress.trim())) return '请填写实际收件邮箱；它与 IMAP 登录用户名分别保存。'
  if (form.mailboxType === 'icloud' && !emailPattern.test(form.email.trim())) return '请填写有效的 Apple ID。'
  if (form.mailboxType === 'custom' && (!validHost(normalizeSuffix(form.emailSuffix)) || normalizeSuffix(form.emailSuffix).includes(':'))) return '请填写有效的邮箱后缀。'
  if (!editing && form.imapPassword.length === 0) return '请填写 IMAP 密码。'
  if (new TextEncoder().encode(form.imapPassword).length > 16 << 10) return 'IMAP 密码长度超出限制。'
  for (const c of form.imapPassword) if (c.codePointAt(0)! >= 0xd800 && c.codePointAt(0)! <= 0xdfff) return '密码包含无效字符，请重新输入。'
  return null
}
export function accountSubmission(form: AccountForm, editing: false): AccountCreate
export function accountSubmission(form: AccountForm, editing: true, baseline: Account, confirmSourceChange?: boolean): AccountPatch
export function accountSubmission(form: AccountForm, editing: boolean, baseline?: Account, confirmSourceChange = false): AccountCreate | AccountPatch {
  const endpoint = normalizeIMAPEndpoint(form.imapHost, form.imapPort), custom = form.mailboxType === 'custom'
  const kind = custom ? 'custom' : isForwardedICloudIMAP(form) ? 'apple_forwarded' : 'apple_direct'
  const common = { kind, display_name: form.name.trim(), address_namespace: form.receivingAddress.trim(),
    address_suffix: custom ? normalizeSuffix(form.emailSuffix) : baseline?.address_suffix || 'icloud.com',
    endpoint: { ...endpoint, username: form.imapUsername.trim() }, enabled: form.enabled,
    ...(custom ? {} : { apple: { apple_id: form.email.trim(), region: form.appleRegion } }) } satisfies Omit<AccountCreate, 'credentials'>
  if (!editing) return { ...common, credentials: { version: 1, imap_password: form.imapPassword } }
  if (!baseline) throw new Error('先重新读取主号修订版本。')
  return { ...common, expected_revision: baseline.revision, require_source_change: confirmSourceChange,
    ...(form.imapPassword === '' ? {} : { credentials: { version: 1, imap_password: form.imapPassword } }) }
}
export function imapSourceChanged(baseline: Account, payload: AccountCreate | AccountPatch): boolean {
  const endpoint = payload.endpoint
  return payload.kind !== undefined && payload.kind !== baseline.kind || payload.address_namespace !== undefined && payload.address_namespace.toLowerCase() !== baseline.address_namespace.toLowerCase() ||
    payload.address_suffix !== undefined && payload.address_suffix.toLowerCase() !== baseline.address_suffix.toLowerCase() ||
    payload.apple !== undefined && (payload.apple.apple_id.toLowerCase() !== baseline.apple?.apple_id.toLowerCase() || payload.apple.region !== baseline.apple?.region) ||
    endpoint !== undefined && (endpoint.host !== baseline.endpoint.host || endpoint.port !== baseline.endpoint.port || endpoint.username !== baseline.endpoint.username)
}
export function formFromAccount(value: Account): AccountForm { return { name: value.display_name, email: value.apple?.apple_id || '', mailboxType: value.kind === 'custom' ? 'custom' : 'icloud',
  emailSuffix: value.address_suffix, receivingAddress: value.address_namespace, appleRegion: value.apple?.region === 'china' ? 'china' : 'global',
  imapHost: value.endpoint.host, imapPort: String(value.endpoint.port), imapUsername: value.endpoint.username, imapPassword: '', enabled: value.enabled } }
export function accountIdentity(value: AccountView): string { return value.mailboxType === 'custom' ? '@' + value.emailSuffix : value.email }
export function receiveLabel(value: Pick<AccountForm, 'mailboxType' | 'imapHost' | 'imapPort'>): string { return value.mailboxType === 'custom' ? '自定义邮箱' : isForwardedICloudIMAP(value) ? 'iCloud 转发至第三方 IMAP' : '直连 iCloud' }
export function formatIMAPEndpoint(value: Pick<AccountForm, 'imapHost' | 'imapPort'> | string, port?: number): string {
  const host = typeof value === 'string' ? value : value.imapHost, selectedPort = typeof value === 'string' ? port : value.imapPort
  return (host.includes(':') ? '[' + host + ']' : host) + ':' + selectedPort
}
export function formatTime(value: string | null | undefined, options?: { seconds?: boolean }): string {
  if (!value) return '—'
  const date = new Date(value)
  if (!Number.isFinite(date.getTime())) return '—'
  return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    ...(options?.seconds ? { second: '2-digit' } : {}), hour12: false })
}
export function unknownMutation(error: unknown): boolean { return error instanceof ControlError && error.outcome === 'unknown' }
export function accountErrorHint(error: unknown): string | undefined {
  if (!(error instanceof ControlError)) return undefined
  return ({ACCOUNT_HAS_DEPENDENT_STATE:'此主号有关联数据，必须使用退休流程；本页没有删除这些数据。',ACCOUNT_IDENTITY_IN_USE:'此主号已有地址，身份、收件命名空间、来源模式或后缀不能更改。',ACCOUNT_SOURCE_CHANGE_REQUIRED:'收件来源发生变化，需要重新核对并明确确认。',ACCOUNT_REVISION_CONFLICT:'主号已发生变化，请重新读取修订版本后编辑。',INSTALLATION_READ_ONLY:'安装当前只读，不能提交更改。'} as Record<string,string>)[error.code]
}
export function newOperationKey(prefix: string): string { return prefix + '_' + crypto.randomUUID().replace(/-/g, '') }

export interface AccountView extends Omit<AccountForm, 'imapPassword' | 'receivingAddress' | 'appleRegion'> {
  id: string; raw: Account; aliasCount: string | number; syncObserved:boolean; syncProgress: (SyncProgress & {active:boolean}) | null; lastSyncedAt: string | null
  lastSyncStatus: 'ok' | 'error' | 'degraded' | 'unknown' | 'cancelled' | 'superseded' | 'pending'; lastSyncError: string; lastSyncErrorLog: string
}
export function accountView(raw: Account, sync: Synchronization | null = null, total: number | null = null): AccountView {
  const p = sync?.progress ?? null, persisted=raw.last_sync_state.replace(/^mail_/,''), error = p ? p.error_code || p.directory_error_code : raw.last_sync_error
  const storedStatus:AccountView['lastSyncStatus']=persisted==='succeeded'||persisted==='ok'?'ok':persisted==='failed'||persisted==='error'?'error':persisted==='degraded'||persisted==='unknown'||persisted==='cancelled'||persisted==='superseded'?persisted:'pending'
  return { ...formFromAccount(raw), id: raw.id, raw, aliasCount: total ?? raw.address_count, syncObserved:sync!==null||raw.last_sync_state!=='', syncProgress: p ? {...p,active:p.state!=='finished'} : null, lastSyncedAt: p?.finished_at || raw.last_synced_at || sync?.last_terminal_at || raw.last_terminal_sync_at || null,
    lastSyncStatus: p===null ? storedStatus : p.state !== 'finished' || p.outcome === null ? 'pending' : p.outcome === 'succeeded' ? 'ok' : p.outcome === 'failed' ? 'error' : p.outcome, lastSyncError: error,
    lastSyncErrorLog: p ? JSON.stringify(p, null, 2) : JSON.stringify({state:raw.last_sync_state,error_code:raw.last_sync_error,last_synced_at:raw.last_synced_at,last_terminal_at:raw.last_terminal_sync_at??null},null,2) }
}
export function syncProgressPresentation(p: SyncProgress | null) {
  const active = p !== null && p.state !== 'finished'
  const phase = p?.phase === 'directory' ? '目录同步' : p?.phase === 'finalize' ? '保存终轮结果' : p?.phase === 'resolve' ? '查询原终轮结果' : p?.frontier?.backfill ? '历史回填' : '邮件同步'
  const frontier = p?.frontier?.backfill ?? p?.frontier
  const percentage = frontier && BigInt(frontier.captured_upper) > 0n ? Number(BigInt(frontier.committed) * 10000n / BigInt(frontier.captured_upper)) / 100 : null
  return { active, label: p?.state === 'waiting' ? '等待继续' : p?.state === 'queued' ? '已入队' : '处理中', stageLabel: phase, percentage }
}
export async function allAccountMetadata(owner: AccountsModel, query: string, signal: AbortSignal): Promise<Account[]> {
  const items: Account[] = [], seen = new Set<string>(); let total: number | undefined
  for (let page = 1; ; page++) {
    if (signal.aborted) throw new DOMException('Canceled', 'AbortError')
    const result = (await owner.list({ query, page, page_size: 1000 }, signal)).result
    if (signal.aborted) throw new DOMException('Canceled', 'AbortError')
    if (total !== undefined && result.total !== total) throw new Error('读取期间主号列表发生变化，请重新刷新。')
    total = result.total
    for (const item of result.items) { if (seen.has(item.id)) throw new Error('列表分页发生变化，请重新刷新。'); seen.add(item.id); items.push(item) }
    if (items.length === total) return items
    if (result.items.length === 0 || items.length > total) throw new Error('主号分页结果不完整，请重新刷新。')
  }
}
export async function accountListProgress(owner:SynchronizationModel,items:readonly Account[],signal:AbortSignal):Promise<AccountView[]> {
  const out:AccountView[]=[]
  for(let offset=0;offset<items.length;offset+=1000){
    if(signal.aborted)throw new DOMException('Canceled','AbortError')
    const slice=items.slice(offset,offset+1000),batch=(await owner.progress(slice.map(item=>item.id),signal)).result
    if(signal.aborted)throw new DOMException('Canceled','AbortError')
    for(let index=0;index<slice.length;index++){
      const raw=slice[index],p=batch.items[index].progress
      const matches=p===null||p.source.revision===raw.revision&&p.source.generation===raw.source_generation&&p.source.credential_generation===raw.credential_generation
      out.push(accountView(raw,matches?{source_id:raw.id,automatic_after:raw.automatic_sync_after??null,last_terminal_at:raw.last_terminal_sync_at??null,progress:p}:null))
    }
  }
  return out
}
export interface AppleSessionView { raw: ProviderSessionStatus; status: 'authenticated' | 'expired' | 'missing'; appleId: string; region: 'cn' | 'global'; expiresAt: string | null }
export interface ScheduleView { raw: CreationPolicy | null; enabled: boolean; status: string; nextRunAt: string | null; plannedAt:string|null; plannedTimes: string[]; lastAttemptedAt: string | null; lastCreatedAt: string | null; lastAliasAddress: string; lastError: string }
export function scheduleView(raw: CreationPolicy | null): ScheduleView {
  const error = raw?.last_error_detail || raw?.paused_reason || ''
  return { raw, enabled: raw?.enabled ?? false, status: !raw ? 'unconfigured' : raw.paused_reason ? 'paused' : raw.enabled ? 'scheduled' : 'disabled',
  nextRunAt: raw?.slots[0]?.scheduled_for ?? null, plannedAt: raw?.slots[0]?.scheduled_for ?? null, plannedTimes: raw?.slots.map(s => s.scheduled_for) ?? [], lastAttemptedAt: raw?.last_attempted_at ?? null,
  lastCreatedAt: raw?.last_confirmed_at ?? null, lastAliasAddress: raw?.last_address ?? '', lastError: error } }
export interface DetailOwners { accounts: AccountsModel; addresses: AddressesModel; providerSessions: ProviderSessionsModel; creation: CreationModel; synchronization: SynchronizationModel }
export interface AccountDetail { account: AccountView; appleSession: AppleSessionView | null; autoCreation: ScheduleView | null; errors: unknown[] }
export async function accountDetail(owners: DetailOwners, id: string, signal: AbortSignal): Promise<AccountDetail> {
  const raw = (await owners.accounts.get(id, signal)).result
  const results = await Promise.allSettled([owners.synchronization.get(id, signal), owners.addresses.list({ source_id: id, page: 1, page_size: 1 }, signal),
    raw.apple ? owners.providerSessions.status(id, signal) : Promise.resolve(null), raw.apple ? owners.creation.get(id, signal) : Promise.resolve(null)])
  if (signal.aborted) throw new DOMException('Canceled', 'AbortError')
  const [sync, count, apple, policy] = results, errors: unknown[] = []
  for (const r of results) if (r.status === 'rejected' && !(r === policy && r.reason instanceof ControlError && 'status' in r.reason && r.reason.status === 404)) errors.push(r.reason)
  const session = apple.status === 'fulfilled' ? apple.value?.result : undefined
  return { account: accountView(raw, sync.status === 'fulfilled' ? sync.value.result : null, count.status === 'fulfilled' ? count.value.result.total : null),
    appleSession: session && raw.apple ? { raw: session, status: session.authenticated ? 'authenticated' : session.expires_at ? 'expired' : 'missing', appleId: raw.apple.apple_id, region: raw.apple.region === 'china' ? 'cn' : 'global', expiresAt: session.expires_at } : null,
    autoCreation: raw.apple && (policy.status === 'fulfilled' || policy.status === 'rejected' && policy.reason instanceof ControlError && 'status' in policy.reason && policy.reason.status === 404) ? scheduleView(policy.status === 'fulfilled' ? policy.value?.result ?? null : null) : null, errors }
}
export interface PendingKeyView { delivery: CredentialDelivery; apiKey?: string; bundle?: CredentialBundle; revoked?: boolean; links?: CredentialCopyLinks | null }
export async function readPendingBundle(owners: {credentials:CredentialsModel}, sourceID:string, item:PendingKeyView, signal?:AbortSignal):Promise<CredentialBundle> {
  const current=()=>{if(signal?.aborted)throw new DOMException('Canceled','AbortError')}
  current()
  if(item.delivery.source_id!==sourceID)throw new Error('待领取记录不属于当前主号。')
  const result=(await owners.credentials.revealPendingBundle(sourceID,item.delivery.delivery_key,item.delivery.generation,signal)).result
  current()
  if(result.delivery.source_id!==sourceID||result.delivery.address_id!==item.delivery.address_id||result.delivery.generation!==item.delivery.generation||result.delivery.delivery_key!==item.delivery.delivery_key)throw new Error('读取凭据与原待领取记录不一致。')
  return result.bundle
}
export function pendingKeyStatus(item: PendingKeyView): string {
  if (item.delivery.deleted) return '已删除，仅历史保存'
  if (!item.delivery.current || item.revoked) return '旧凭据已撤销，仅历史保存'
  if (item.delivery.lifecycle === 'pending') return '等待邮箱确认，暂不可取件'
  if (item.delivery.lifecycle === 'deletion_pending') return '删除结果待确认，暂不可取件'
  if (item.delivery.lifecycle === 'archived') return '已归档，暂不可取件'
  return item.delivery.enabled ? item.apiKey||item.bundle?'当前凭据':'当前代待领取' : '邮箱或主号已停用'
}
export function pendingKeyMaterialStatus(item: PendingKeyView): string {
  if (item.bundle) return '完整凭据已读取'
  if (item.apiKey) return '取码凭据已读取'
  if (!item.delivery.current || item.revoked || item.delivery.deleted) return '历史交付，未读取'
  return item.delivery.bundle_available ? '完整凭据待读取' : '取码凭据待读取'
}
export function pendingKeyExports(keys: readonly PendingKeyView[], origin: string) {
  const ordered=[...keys].sort((a,b)=>a.delivery.address<b.delivery.address?-1:a.delivery.address>b.delivery.address?1:BigInt(a.delivery.id)<BigInt(b.delivery.id)?-1:1)
  const current=ordered.filter(k=>k.delivery.current&&!k.delivery.deleted&&!k.revoked)
  return { otp: credentialCopyText(current.filter(k=>k.links).map(k=>({address:k.delivery.address,links:k.links!})), 'otp', origin),
    imap: credentialCopyText(current.filter(k=>k.bundle).map(k=>({address:k.delivery.address,bundle:k.bundle})), 'imap', origin),
    jsonl: ordered.filter(k=>k.apiKey||k.bundle).map(k=>JSON.stringify({address:k.delivery.address,source_id:k.delivery.source_id,address_id:k.delivery.address_id,generation:k.delivery.generation,status:pendingKeyStatus(k),revoked:k.revoked===true,api_key:k.apiKey,bundle:k.bundle})).join('\n') }
}
