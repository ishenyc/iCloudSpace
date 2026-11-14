import { ControlError, HttpError, controlErrorMessage } from '../transport/errors.ts'

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
  return error instanceof Error ? error.message : typeof error === 'string' ? error : '操作未能完成，请核对当前状态。'
}

export function feedbackDetails(error: unknown) {
  return error instanceof ControlError ? { code: error.code, requestId: error.requestId } : undefined
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
