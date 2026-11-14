import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { KeyRound, LockKeyhole, ShieldCheck } from 'lucide-react'
import { useAuth } from '../lib/auth'
import { useControl } from '../lib/control'
import { AnimatePresence, AnimatedSection } from '../lib/motion'
import { Alert, Button, Field, Input, Modal, PageHeader, Panel, useToast } from '../components/ui'
import { FULL_ROTATION_CONFIRMATION } from '../control/credential-contracts'
import type { CredentialRotation, CredentialScope } from '../control/credential-contracts'
import { ControlError, HttpError, RequestConfigurationError } from '../transport'
import { previousControlBase } from '../control/entry-handoff'
import { inspectPendingRotations, persistPendingRotation, forgetPendingRotation } from '../control/rotation-recovery'
import type { PendingRotation, RotationRecovery } from '../control/rotation-recovery'

function rotationStoragePrefix(origin: string, basePath: string): string {
  return 'icloudspace:control:rotation-all:v1:' + encodeURIComponent(origin) + ':' + encodeURIComponent(basePath) + ':'
}
function readPendingRotations(prefix: string, previousPrefix?: string): RotationRecovery {
  try {
    return inspectPendingRotations(window.localStorage,prefix,previousPrefix)
  } catch {
    return { prefix, pending: [], error: new Error('无法读取或校验已保存的原操作引用。请先核对本入口的操作记录，本页不会发起新的全量轮换。') }
  }
}
function storePendingRotation(prefix: string, item: PendingRotation): void {
  // Each operation has its own entry, so another tab cannot overwrite an
  // uncertain original reference. Only the command key and exact scope persist.
  persistPendingRotation(window.localStorage,prefix,item)
}
function sameScope(left: CredentialScope, right: CredentialScope): boolean {
  return left.digest === right.digest && left.address_count === right.address_count && left.eligible_count === right.eligible_count
}
function matchRotation(result: CredentialRotation, original: PendingRotation): void {
  if (result.operation_key !== original.operation_key || result.kind !== 'all' || result.scope_digest !== original.scope.digest ||
    result.state === 'committed' && BigInt(result.items.length) !== BigInt(original.scope.eligible_count)) throw new Error('原操作回执与已确认范围不一致，请保留原引用并继续核对。')
}

export function SecurityPage() {
  const auth = useAuth()
  const { sessionModel, credentials, basePath } = useControl()
  const navigate = useNavigate()
  const toast = useToast()
  const [passwords, setPasswords] = useState({ current: '', next: '', confirmation: '' })
  const [passwordBusy, setPasswordBusy] = useState(false)
  const [passwordError, setPasswordError] = useState<any>(null)
  const [rotationOpen, setRotationOpen] = useState(false)
  const [rotationStep, setRotationStep] = useState(1)
  const rotationStepPanel = useRef<HTMLDivElement>(null)
  const [rotationPassword, setRotationPassword] = useState('')
  const [rotationConfirmation, setRotationConfirmation] = useState('')
  const [rotationError, setRotationError] = useState<any>(null)
  const [rotationBusy, setRotationBusy] = useState(false)
  const [rotationQueryKey, setRotationQueryKey] = useState<string | null>(null)
  const [rotationScope, setRotationScope] = useState<CredentialScope | null>(null)
  const storagePrefix = rotationStoragePrefix(window.location.origin, basePath)
  const previousBase = previousControlBase(basePath), previousPrefix = previousBase ? rotationStoragePrefix(window.location.origin, previousBase) : undefined
  const [recovery, setRecovery] = useState<RotationRecovery>(() => readPendingRotations(storagePrefix, previousPrefix))
  const [recoveryError, setRecoveryError] = useState<unknown>(null)
  const [recoveryNotice, setRecoveryNotice] = useState('')
  const recoveryReady = recovery.prefix === storagePrefix
  const pending = recoveryReady ? recovery.pending : []
  const rotationBlocked = !recoveryReady || recovery.error !== null || pending.length > 0
  const expectedConfirmation = rotationScope ? 'ROTATE_ALL ' + rotationScope.eligible_count : ''
  // State alone does not prevent two clicks before React commits a render.
  const actionLock = useRef(false)
  const byteLength = new TextEncoder().encode(passwords.next).length

  useEffect(() => {
    setRecovery(readPendingRotations(storagePrefix, previousPrefix))
    setRecoveryError(null)
    setRecoveryNotice('')
    setRotationOpen(false)
    setRotationScope(null)
    setRotationPassword('')
    setRotationConfirmation('')
    setRotationStep(1)
    const refresh = (event: StorageEvent) => {
      if (event.key === null || event.key.startsWith(storagePrefix) || previousPrefix && event.key.startsWith(previousPrefix)) setRecovery(readPendingRotations(storagePrefix, previousPrefix))
    }
    window.addEventListener('storage', refresh)
    return () => window.removeEventListener('storage', refresh)
  }, [storagePrefix])

  function leaveSession(notice: string) {
    auth.clearSession(notice)
    navigate(`/login?notice=${encodeURIComponent(notice)}`, { replace: true })
  }

  async function changePassword(event: FormEvent) {
    event.preventDefault()
    if (actionLock.current) return
    setPasswordError(null)
    if (!passwords.current) { setPasswordError(new Error('请填写当前密码。')); return }
    if (byteLength < 12 || byteLength > 72) {
      setPasswordError(new Error('新密码长度需要在 12 到 72 字节之间。')); return
    }
    if (passwords.next !== passwords.confirmation) {
      setPasswordError(new Error('两次填写的新密码不一致。')); return
    }
    actionLock.current = true
    setPasswordBusy(true)
    try {
      await sessionModel.changePassword({
        current_password: passwords.current,
        new_password: passwords.next,
        confirmation: passwords.confirmation,
      })
      setPasswords({ current: '', next: '', confirmation: '' })
      leaveSession('password_changed')
    } catch (error) {
      // Never retain submitted passwords after a response or transport error.
      setPasswords({ current: '', next: '', confirmation: '' })
      setPasswordError(error)
    } finally {
      actionLock.current = false
      setPasswordBusy(false)
    }
  }

  function toggleRotation(open: boolean) {
    if (rotationBusy) return
    setRotationOpen(open)
    setRotationStep(1)
    setRotationPassword('')
    setRotationConfirmation('')
    setRotationError(null)
    setRotationScope(null)
  }

  function removePending(original: PendingRotation): boolean {
    try {
      forgetPendingRotation(window.localStorage,storagePrefix,original)
      setRecovery(readPendingRotations(storagePrefix, previousPrefix))
      return true
    } catch {
      setRecoveryError(new Error('原操作已经核对，但本地引用暂时无法清除。请保留引用，勿再次发起轮换。'))
      return false
    }
  }

  async function queryOriginalRotation(original: PendingRotation) {
    if (actionLock.current || !pending.includes(original)) return
    actionLock.current = true
    setRotationBusy(true)
    setRotationQueryKey(original.operation_key)
    setRecoveryError(null)
    setRecoveryNotice('')
    try {
      const result = (await credentials.queryRotation(original.operation_key)).result
      matchRotation(result, original)
      if (result.state === 'prepared') {
        setRecoveryNotice('原操作尚未完成或取消，仍需核对。请保留原引用，勿再次发起轮换。')
        return
      }
      if (removePending(original)) {
        setRecoveryNotice(result.state === 'committed' ? `已确认原操作完成，轮换了 ${result.items.length} 个符合条件的地址。当前新登录会话不受这次只读查询影响。` : '已确认原操作已取消，未按该操作继续轮换。再次操作需要读取并确认新的范围。')
      }
    } catch (error) {
      setRecoveryError(error instanceof HttpError && error.status === 404
        ? new Error('原操作暂时不可见，引用已保留。请稍后再次查询，勿重复提交轮换。')
        : error instanceof ControlError || error instanceof Error ? error : new Error('无法核对原操作，引用已保留。'))
    } finally {
      actionLock.current = false
      setRotationBusy(false)
      setRotationQueryKey(null)
    }
  }

  async function rotateAll(event: FormEvent) {
    event.preventDefault()
    if (actionLock.current) return
    setRotationError(null)
    const currentRecovery = readPendingRotations(storagePrefix, previousPrefix)
    setRecovery(currentRecovery)
    if (currentRecovery.error || currentRecovery.pending.length > 0) {
      setRotationError(new Error('请先核对已保存的原操作。本页不会再次提交或取消结果不确定的轮换。')); return
    }
    if (!rotationPassword) { setRotationError(new Error('请输入当前管理员密码。')); return }
    if (rotationStep !== 1 && (!rotationScope || rotationConfirmation !== expectedConfirmation || rotationScope.eligible_count === '0')) {
      setRotationError(new Error('请按当前可轮换数量填写完整确认内容。')); return
    }
    actionLock.current = true
    setRotationBusy(true)
    let original: PendingRotation | undefined
    let dispatched = false
    try {
      const scope = (await credentials.scope()).result
      if (rotationStep === 1) {
        setRotationScope(scope)
        setRotationStep(2)
        setRotationConfirmation('')
        return
      }
      if (!rotationScope || !sameScope(scope, rotationScope)) {
        setRotationScope(null)
        setRotationStep(1)
        setRotationPassword('')
        setRotationConfirmation('')
        setRotationError(new Error('地址范围已经变化，旧确认已失效。请重新读取范围并确认。'))
        return
      }
      if (typeof globalThis.crypto?.randomUUID !== 'function') throw new Error('当前环境无法生成安全操作引用，未发起轮换。')
      original = { version: 1, operation_key: 'rotation_' + globalThis.crypto.randomUUID(), scope: { ...scope } }
      try { storePendingRotation(storagePrefix, original) } catch { throw new Error('无法保存原操作引用，尚未发起轮换。请允许本入口使用本地存储后重试。') }
      setRecovery(readPendingRotations(storagePrefix, previousPrefix))
      dispatched = true
      const write = credentials.rotateAll({ operation_key: original.operation_key, expected_scope_digest: scope.digest,
        confirmation: FULL_ROTATION_CONFIRMATION, current_password: rotationPassword })
      setRotationPassword('')
      setRotationConfirmation('')
      const result = (await write).result
      matchRotation(result, original)
      removePending(original)
      setRotationOpen(false)
      setRotationScope(null)
      toast(`已轮换 ${result.items.length} 个符合条件的地址凭据。请重新登录后按需获取新凭据。`, 'success')
    } catch (error) {
      setRotationPassword('')
      setRotationConfirmation('')
      if (!dispatched || error instanceof RequestConfigurationError && error.outcome === 'not_sent') {
        if (original) removePending(original)
        setRotationStep(1)
        setRotationScope(null)
        setRotationError(error instanceof ControlError || error instanceof Error ? error : new Error('未发起轮换，请重新确认。'))
        return
      }
      // The original reference was persisted before dispatch. Root invalidates
      // the uncertain session; a later login can only query this same key.
      setRotationOpen(false)
      setRotationScope(null)
      setRecoveryNotice('轮换结果尚未确认，原操作引用已保存。重新登录后请查询原操作，勿再次提交。')
      setRecoveryError(error instanceof ControlError ? error : new Error('轮换回执未能确认，原操作引用已保留。'))
    } finally {
      actionLock.current = false
      setRotationBusy(false)
    }
  }

  return <div className="stack">
    <PageHeader eyebrow="SETTINGS" title="安全设置" description="管理后台登录密码和邮箱访问凭据。" />
    <div className="grid-2" style={{ alignItems: 'start' }}>
      <Panel title="管理员密码" description="修改成功后，当前管理员的全部后台会话会失效。">
        <form className="stack" onSubmit={changePassword}>
          <div className="notice"><ShieldCheck size={17} /><span>当前登录：{auth.session?.username || '管理员'}</span></div>
          {passwordError && <Alert error={passwordError} attention="focus">{passwordError instanceof ControlError && passwordError.code === 'CURRENT_PASSWORD_INVALID' ? '当前管理员密码不正确。你仍保持登录，可以更正后重新提交。' : undefined}</Alert>}
          <Field label="当前密码"><Input type="password" autoComplete="current-password" required value={passwords.current} disabled={passwordBusy || rotationBusy} onChange={e => setPasswords({ ...passwords, current: e.target.value })} /></Field>
          <Field label="新密码" description={`12–72 字节，当前 ${byteLength} 字节。中文等字符可能占多个字节。`}><Input type="password" autoComplete="new-password" required value={passwords.next} disabled={passwordBusy || rotationBusy} onChange={e => setPasswords({ ...passwords, next: e.target.value })} /></Field>
          <Field label="确认新密码"><Input type="password" autoComplete="new-password" required value={passwords.confirmation} disabled={passwordBusy || rotationBusy} onChange={e => setPasswords({ ...passwords, confirmation: e.target.value })} /></Field>
          <div><Button type="submit" disabled={passwordBusy || rotationBusy} loading={passwordBusy} loadingLabel="正在更新…"><LockKeyhole size={15} />更新密码</Button></div>
        </form>
      </Panel>
      <Panel title="轮换全部邮箱凭据" description="在需要整体更换邮箱访问凭据时执行。">
        <div className="stack">
          <div className="notice"><KeyRound size={17} /><span>轮换全部未删除邮箱，包括停用、等待确认、归档和删除结果待确认的邮箱。</span></div>
          <p className="text-muted">本次范围内的旧 API Key、取码链接、IMAP 密码和 OAuth 凭据会失效；符合条件且仅有最新快照权限的地址会补齐完整邮箱凭据。邮件归档、消费记录与已读状态会保留。</p>
          <p className="text-muted">执行后需要重新登录。新凭据不会自动加载或保存，请在可信环境中按需获取。</p>
          {recovery.error && <Alert error={recovery.error} />}
          {recoveryError != null && <Alert error={recoveryError} attention="focus" />}
          {recoveryNotice && <Alert tone="warning">{recoveryNotice}</Alert>}
          {pending.length > 0 && <Alert tone="warning"><div className="stack">
            <span>本入口有 {pending.length} 笔待核对的原操作。确认结果前无法再发起全量轮换。</span>
            {pending.map(original=><div key={original.storage_key||original.operation_key}><details className="operation-details"><summary>查看原操作编号</summary><code>{original.operation_key}</code></details>
            <div><Button type="button" variant="outline" disabled={passwordBusy || rotationBusy || auth.checking || !auth.session} loading={rotationBusy && rotationQueryKey === original.operation_key} loadingLabel="正在查询…" onClick={()=>void queryOriginalRotation(original)}>查询原操作</Button></div></div>)}
          </div></Alert>}
          <div><Button variant="destructive" disabled={passwordBusy || rotationBusy || rotationBlocked} onClick={() => toggleRotation(true)}>轮换全部凭据</Button></div>
        </div>
      </Panel>
    </div>
    <Modal open={rotationOpen} onOpenChange={toggleRotation} title={rotationStep === 1 ? '验证身份' : '最终确认轮换'} description={rotationStep === 1 ? '输入当前管理员密码，继续读取并确认影响范围。' : '该操作不可撤销，已确认范围内的旧邮箱访问凭据会立即失效。'}>
      <form className="stack" onSubmit={rotateAll}>
        {rotationError && <Alert error={rotationError} attention="focus" />}
        <AnimatePresence initial={false} mode="wait"><AnimatedSection key={rotationStep} className="stack" ref={rotationStepPanel} onAnimationComplete={() => { if (rotationStepPanel.current && !rotationStepPanel.current.inert) rotationStepPanel.current.querySelector<HTMLInputElement>('input')?.focus() }}>{rotationStep === 1 ? <Field label="当前管理员密码"><Input type="password" autoComplete="current-password" value={rotationPassword} onChange={e => setRotationPassword(e.target.value)} disabled={rotationBusy} required /></Field>
          : <>
            <Alert tone="warning">全部后台会话将被撤销。若请求结果不确定，重新登录后只能查询已保存的原操作，不能重复轮换。</Alert>
            {rotationScope && <>
              <p className="text-muted">当前范围共有 {rotationScope.address_count} 个地址记录，其中 {rotationScope.eligible_count} 个未删除邮箱参与轮换。只更换凭据，不启用邮箱、不改变归档状态，也不重发待确认的删除请求。</p>
              <details className="operation-details"><summary>查看核对摘要</summary><code>{rotationScope.digest}</code></details>
              {rotationScope.eligible_count === '0' && <Alert tone="warning">当前没有符合条件的地址，无需发起轮换。</Alert>}
            </>}
            <Field label={`输入 ${expectedConfirmation || '确认内容'} 确认`}><Input value={rotationConfirmation} onChange={e => setRotationConfirmation(e.target.value)} autoComplete="off" spellCheck={false} disabled={rotationBusy} required /></Field>
          </>}</AnimatedSection></AnimatePresence>
        <div className="row-actions" style={{ justifyContent: 'flex-end' }}>
          <Button type="button" variant="outline" disabled={rotationBusy} onClick={() => toggleRotation(false)}>取消</Button>
          <Button type="submit" variant={rotationStep === 1 ? 'default' : 'destructive'} disabled={rotationBusy || rotationBlocked || (rotationStep === 1 ? !rotationPassword : !rotationScope || rotationScope.eligible_count === '0' || rotationConfirmation !== expectedConfirmation)} loading={rotationBusy} loadingLabel="正在处理…">{rotationStep === 1 ? '继续确认' : '永久轮换全部'}</Button>
        </div>
      </form>
    </Modal>
  </div>
}
