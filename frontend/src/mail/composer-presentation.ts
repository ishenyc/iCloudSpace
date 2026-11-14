import type { ComposerDraft } from './compose-adapter.ts'
import { compositionFeedback, type CompositionSnapshot } from './composition.ts'
import { validateMailDraft } from './draft-content.js'

export type ComposerIssue = { field: 'to' | 'subject' | 'body' | 'attachments'; message: string }

/** Keep validation owned by the proven draft validator; locate its first error for the form. */
export function composerIssue(draft: ComposerDraft): ComposerIssue | null {
  const message = validateMailDraft(draft)
  if (!message) return null
  if (validateMailDraft({ ...draft, to: 'recipient@example.invalid' }) !== message) return { field: 'to', message }
  if (validateMailDraft({ ...draft, subject: 'Subject' }) !== message) return { field: 'subject', message }
  if (validateMailDraft({ ...draft, text: 'Body', body_format: 'text' }) !== message) return { field: 'body', message }
  return { field: 'attachments', message }
}

export function composerHasDraft(draft: ComposerDraft): boolean {
  return Boolean(draft.to || draft.subject || draft.text || draft.attachments.length)
}

/** A restored operation is a result to inspect, never an empty disabled form. */
export function composerResult(state: CompositionSnapshot) {
  const feedback = compositionFeedback(state)
  if (state.pending === 'send' || state.pending === 'context') return {
    title: '正在发送邮件', tone: 'neutral' as const,
    detail: '正在准备并提交这封邮件。首次联系收件人时可能需要稍等，请勿重复发送。',
  }
  if (state.recoveryBlocked) return {
    title: '需要恢复上次操作', tone: 'warning' as const,
    detail: '浏览器无法完整读取上次操作记录。请先核对原结果，避免重复发送。',
  }
  if (state.submission?.outcome === 'accepted') return {
    title: '邮件已提交', tone: 'success' as const,
    detail: feedback!.text,
  }
  if (state.submission?.outcome === 'not_sent' || state.submissionNotSent) return {
    title: '这封邮件尚未发送', tone: 'warning' as const,
    detail: feedback?.text || '本次请求未提交邮件。',
  }
  if (state.submission?.outcome === 'rejected') return {
    title: '邮件未能发送', tone: 'danger' as const,
    detail: feedback!.text,
  }
  return {
    title: state.pending === 'query' && !state.submission ? '正在查询上次发送' : '发送结果待确认',
    tone: 'warning' as const,
    detail: feedback?.text || '正在读取原发送结果，查询不会重新发送邮件。',
  }
}
