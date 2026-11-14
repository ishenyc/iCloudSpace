export interface RequestTicket {
  readonly signal: AbortSignal
  isCurrent(): boolean
  /** Applies a read result only while this ticket is current and has not been canceled. */
  commit(apply: () => void): boolean
  finish(): void
  cancel(): void
}

/** Coordinates replaceable reads. Starting another read invalidates even non-abortable late work. */
export class RequestSequence {
  private active?: AbortController

  start(): RequestTicket {
    this.cancel()
    const controller = new AbortController()
    this.active = controller
    const isCurrent = () => this.active === controller && !controller.signal.aborted
    const finish = () => {
      if (this.active === controller) this.active = undefined
    }
    return {
      signal: controller.signal,
      isCurrent,
      commit: (apply) => {
        if (!isCurrent()) return false
        apply()
        return true
      },
      finish,
      cancel: () => {
        controller.abort()
        finish()
      },
    }
  }

  cancel(): void {
    const controller = this.active
    this.active = undefined
    controller?.abort()
  }
}
