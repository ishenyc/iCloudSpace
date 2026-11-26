import { ControlError, HttpError, controlErrorMessage } from '../transport/errors.ts'

import { diagnosticMessage } from './diagnostic-message.ts'

export type FeedbackDiagnostics = { code?: string; requestId?: string; providerCode?: string; httpStatus?: number }
export class ReceiptError extends Error {
  readonly diagnostics: FeedbackDiagnostics
  constructor(message: string, diagnostics: FeedbackDiagnostics) {
    super(message)
    this.diagnostics = diagnostics
  }
}

export type FeedbackContext = 'form' | 'action' | 'read'
export function feedbackPresentation(error: unknown, context: FeedbackContext): 'card' | 'toast' {
  if (context === 'form') return 'card'
  if (error instanceof ControlError && (error.outcome === 'unknown' || error.outcome === 'accepted' || error.submissionKey)) return 'card'
  // A copy/download failure has no business mutation to reconcile. Mutation
  // transport/response failures stay visible until their original result is known.
  if (context === 'read') return 'toast'
  if (error instanceof HttpError && (error.outcome === 'not_sent' || error.outcome === 'rejected')) return 'toast'
  return 'card'
}

export function feedbackMessage(error: unknown, context?: FeedbackContext): string {
  if (error instanceof ControlError) {
    if (context === 'read' && feedbackPresentation(error, context) === 'toast') {
      if (error.category === 'transport') return '本次读取未能完成，请检查连接后重试。'
      if (error.category === 'invalid_response') return '读取结果未能通过校验，请重新读取。'
    }
    return controlErrorMessage(error)
  }
  if (error instanceof Error && error.name === 'ClientStateError') return '浏览器无法保存或读取上次操作的记录。请保留当前页面，检查站点存储权限后查询原结果。'
  if (error instanceof Error && error.name === 'ContractError') return '页面无法读取服务器返回的数据，请刷新页面并核对当前状态。'
  const message = error instanceof Error ? error.message : typeof error === 'string' ? error : ''
  if (/[\u3400-\u9fff]/u.test(message)) return message
  return diagnosticMessage(message, context === 'read' ? '读取未完成，请刷新后再试。' : '操作未能完成，请核对当前状态。')
}

export function feedbackDetails(error: unknown): FeedbackDiagnostics | undefined {
  if (error instanceof ReceiptError) return error.diagnostics
  if (error instanceof ControlError) return { code: error.code, requestId: error.requestId }
  if (error instanceof Error && 'code' in error && typeof error.code === 'string') return { code: error.code }
  return undefined
}

export function feedbackSignature(error: unknown, message: string): string {
  // Polling may generate a new request ID on every failure. That is diagnostic
  // data, not a new reason to interrupt the same form or scroll position.
  return error instanceof ControlError ? JSON.stringify([error.category, error.code, error.outcome, message]) : message
}

type Bounds = { top: number; bottom: number; left: number; right: number }
export function feedbackIsVisible(rect: Bounds, clips: Bounds[]): boolean {
  return clips.every(clip => rect.top >= clip.top && rect.bottom <= clip.bottom && rect.left >= clip.left && rect.right <= clip.right)
}
