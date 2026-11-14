import { decodeIdentifier } from '../control/contracts.ts'
import { mailoutDraftInput } from '../control/mailout-contracts.ts'
import type { MailoutContext, MailoutDraft, MailoutSubmission } from '../control/mailout-contracts.ts'
import type { MailoutModel } from '../control/mailout.ts'
import { ControlError, HttpError, RequestConfigurationError } from '../transport/index.ts'
import { mailSendFeedback } from './draft-content.js'
import { CompositionHandoff } from '../control/client-state-handoff.ts'
import type { ClientStateStorage, PreservedClientState } from '../control/client-state-handoff.ts'

type MailoutPort = Pick<MailoutModel, 'refreshContext' | 'queryContext' | 'send' | 'query'>
export interface CompositionSnapshot {
  contextKey: string; submissionKey: string
  context: MailoutContext | null; submission: MailoutSubmission | null
  pending: 'context' | 'send' | 'query' | null
  contextUncertain: boolean; submissionNotSent: boolean; error: unknown
  recoveryBlocked?: boolean; recoveryKeys?: readonly string[]; recoveryContextKeys?: readonly string[]; preservedState?: readonly PreservedClientState[]
}

/** This store contains operation identifiers only. Bodies, recipients, files,
 * CSRF and credentials are deliberately absent, including on failed requests. */
export class Composition {
  private state: CompositionSnapshot = { contextKey: '', submissionKey: '', context: null, submission: null, pending: null, contextUncertain: false, submissionNotSent: false, error: null }
  private readonly handoff: CompositionHandoff
  private restored = false
  private readonly addressID: string
  private readonly owner: MailoutPort
  private readonly changed: (state: CompositionSnapshot) => void
  private readonly newKey: () => string

  constructor(owner: MailoutPort, basePath: string, addressID: string, storage: ClientStateStorage, changed: (state: CompositionSnapshot) => void, newKey = () => crypto.randomUUID()) {
    this.owner = owner; this.addressID = decodeIdentifier(addressID); this.changed = changed; this.newKey = newKey
    this.handoff = new CompositionHandoff(storage, basePath, this.addressID)
  }
  get snapshot(): CompositionSnapshot { return this.state }
  get canStartAnother(): boolean {
    return !this.state.recoveryBlocked && !this.state.pending && Boolean(this.state.submissionNotSent || this.state.submission?.state === 'finished' && this.state.submission.durable && this.state.submission.outcome !== 'unknown' && (this.state.submission.outcome === 'accepted' || this.state.submission.retryable !== false))
  }
  get canRetry(): boolean {
    return this.canStartAnother && Boolean(this.state.submissionNotSent || this.state.submission && ['not_sent', 'rejected'].includes(this.state.submission.outcome) && this.state.submission.retryable !== false)
  }

  async recover(): Promise<void> {
    if (this.state.pending) return
    try {
      this.restore()
      // A failed handoff keeps its error visible and its original keys ready
      // for explicit queries. Successful restoration may query, never submit.
      if (!this.state.recoveryBlocked) {
        if (this.state.submissionKey) await this.querySubmission()
        if (this.state.contextKey) await this.readContext(false)
      }
    } catch (error) { this.publish({ error }) }
  }

  /** Retained only for old callers: preparation is owned by Send, never UI. */
  async prepare(_recipient: string, _authorizeBootstrap: boolean): Promise<void> {
    this.restore()
    if (!this.state.recoveryBlocked && !this.state.pending) this.publish({error:new RequestConfigurationError('MAIL_PREPARATION_RETIRED',{outcome:'not_sent'})})
  }

  async readContext(refresh = true,key=this.state.contextKey): Promise<void> {
    if (this.state.pending || !key || key!==this.state.contextKey && !this.state.recoveryContextKeys?.includes(key)) return
    await this.perform('query', async () => {
      try {
        const response = await (refresh && !this.state.recoveryBlocked && key===this.state.contextKey ? this.owner.refreshContext(this.addressID, key) : this.owner.queryContext(this.addressID, key))
        this.publish({ contextKey:key,context: response.result, contextUncertain: response.result.query_only })
      } catch (error) {
        if (error instanceof HttpError && error.status === 404) this.publish({ contextUncertain: false })
        throw error
      }
    })
  }

  async submit(draft: MailoutDraft, retry = false): Promise<void> {
    this.restore()
    if (this.state.recoveryBlocked || this.state.pending || this.state.submissionKey && !retry || retry && !this.canRetry) return
    // A retry is one explicit click with the retained, validated draft. Keep
    // the old query identity if validation or saving the new pointer fails.
    try { mailoutDraftInput(draft) } catch(error) { this.publish({error});return }
    await this.perform('send', async () => {
      mailoutDraftInput(draft)
      const key = this.newKey()
      this.save(this.state.contextKey, key)
      this.publish({ submissionKey: key, submission: null, submissionNotSent: false })
      try {
        const response = await this.owner.send(this.addressID, { request_key: key, draft })
        this.publish({ submission: response.result })
      } catch (error) {
        this.publish({ submissionNotSent: error instanceof ControlError && error.outcome === 'not_sent' })
        throw error
      }
    })
  }

  async querySubmission(key = this.state.submissionKey): Promise<void> {
    if (this.state.pending || !key || key !== this.state.submissionKey && !this.state.recoveryKeys?.includes(key)) return
    await this.perform('query', async () => {
      const response = await this.owner.query(this.addressID, key)
      this.publish({ submissionKey: key, submission: response.result, submissionNotSent: false })
    })
  }

  startAnother(): boolean {
    if (!this.canStartAnother) return false
    try {
      this.save(this.state.contextKey, '')
      this.publish({ submissionKey: '', submission: null, submissionNotSent: false, recoveryKeys: [], error: null })
      return true
    } catch (error) { this.publish({ error }); return false }
  }
  retryDraft(): boolean { return this.canRetry && this.startAnother() }

  // Changing the recipient explicitly starts a different context only after
  // the previous context is settled. Unknown candidate/seed owners remain.
  changeRecipient(): boolean {
    this.restore()
    if (this.state.recoveryBlocked || this.state.pending || this.state.submissionKey || this.state.contextUncertain || this.state.context?.query_only) return false
    try {
      this.save('', '')
      this.publish({ contextKey: '', context: null, contextUncertain: false, error: null })
      return true
    } catch (error) { this.publish({ error }); return false }
  }

  private save(contextKey: string, submissionKey: string): void {
    try {
      this.handoff.commit({ version: 1, address_id: this.addressID, ...(contextKey ? { context_key: contextKey } : {}), ...(submissionKey ? { submission_key: submissionKey } : {}) })
      if (submissionKey) this.publish({ recoveryKeys: [submissionKey] })
    } catch (error) { this.publish({ recoveryBlocked: true }); throw error }
  }
  private restore(): void {
    if (this.restored) return
    const result = this.handoff.recover(readable => this.publish({ submissionKey: readable.queryKeys[0] ?? '', recoveryKeys: readable.queryKeys,recoveryContextKeys:readable.contextKeys, recoveryBlocked: true, preservedState: readable.preserved }))
    this.restored = true
    this.publish({ contextKey: result.record?.context_key ?? '', submissionKey: result.queryKeys[0] ?? '', contextUncertain: Boolean(result.record?.context_key),
      recoveryBlocked: result.blocked, recoveryKeys: result.queryKeys,recoveryContextKeys:result.contextKeys, preservedState: result.preserved, error: result.error })
  }
  private publish(next: Partial<CompositionSnapshot>): void {
    this.state = Object.freeze({ ...this.state, ...next })
    this.changed(this.state)
  }
  private async perform(pending: CompositionSnapshot['pending'], action: () => Promise<void>): Promise<void> {
    this.publish({ pending, error: null })
    try { await action() } catch (error) { this.publish({ error }) }
    finally { this.publish({ pending: null }) }
  }
}

export function compositionFeedback(state: CompositionSnapshot): { tone: 'success' | 'warning' | 'danger'; text: string } | null {
  if (state.submission) {
    const aliases:Record<string,string>={session_unavailable:'APPLE_LOGIN_REQUIRED',reference_pending:'MAIL_REFERENCE_PENDING',route_rejected:'HME_ROUTE_REJECTED',route_unknown:'HME_ROUTE_RESULT_UNKNOWN',provider_rejected:'APPLE_MAIL_REJECTED',historical_context_unknown:'HME_BOOTSTRAP_RESULT_UNKNOWN',bootstrap_unknown:'HME_BOOTSTRAP_RESULT_UNKNOWN',attachment_rejected:'MAIL_ATTACHMENT_REJECTED',attachment_unknown:'MAIL_ATTACHMENT_UPLOAD_UNKNOWN'}
    const original=mailSendFeedback({status:state.submission.outcome,code:aliases[state.submission.code]||state.submission.code})
    switch (state.submission.outcome) {
      case 'accepted': return { tone: 'success', text: original.text + (!state.submission.durable ? ' 本地结果待确认，请查询原发送编号。' : '') }
      case 'rejected': return { tone: 'danger', text: original.text + (state.submission.retryable === false ? ' 请查询原结果，勿重复提交。' : '') }
      case 'not_sent': return { tone: 'warning', text: original.text + (state.submission.retryable === false ? ' 请查询原结果，勿重复提交。' : '') }
      case 'unknown': return { tone: 'warning', text: '发送结果尚未确认。请查询原结果，不要重复发送。' }
    }
  }
  if (state.submissionKey && !state.pending) return { tone: 'warning', text: state.submissionNotSent ? '此次请求未发送，可以修改后明确建立新请求。' : '已保留原发送编号。正文和附件仅保存在当前窗口，查询不会重新发送。' }
  return null
}
