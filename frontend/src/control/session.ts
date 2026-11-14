import { ControlClient, ControlError, HttpError, RequestConfigurationError, RequestSequence } from '../transport/index.ts'
import type { ControlResult, FetchImplementation, SessionLoginCredentials } from '../transport/index.ts'
import { decodeAuthenticatedSession, decodeNull, decodeSession } from './contracts.ts'
import type { Instant, Operator, PasswordChange, Session } from './contracts.ts'

export type SessionPhase = 'unresolved' | 'loading' | 'anonymous' | 'authenticated' | 'changing' | 'reauthentication_required' | 'unknown'

export interface SessionSnapshot {
  readonly phase: SessionPhase
  readonly operator?: Readonly<Operator>
  readonly expires_at?: Instant
  readonly error?: ControlError
}

export interface SessionModelOptions {
  basePath: string
  fetch?: FetchImplementation
  onChange?: (snapshot: SessionSnapshot) => void
}

export type SessionRead = { applied: false } | { applied: true; snapshot: SessionSnapshot; meta: ControlResult<Session>['meta'] }

/** Owns only current session state. Passwords and browser cookie values are never persisted. */
export class SessionModel {
  readonly client: ControlClient
  private readonly reads = new RequestSequence()
  private readonly onChange?: SessionModelOptions['onChange']
  private session?: Session
  private changing = false
  private revision = 0
  private state: SessionSnapshot = Object.freeze({ phase: 'unresolved' })

  constructor(options: SessionModelOptions) {
    this.onChange = options.onChange
    this.client = new ControlClient({
      basePath: options.basePath, fetch: options.fetch,
      csrfToken: () => this.session?.authenticated ? this.session.csrf_token : undefined,
      sessionRevision: () => this.revision,
      onUnauthorized: (event) => {
        this.revision++
        this.reads.cancel()
        this.session = undefined
        this.publish('reauthentication_required', new HttpError(401, { requestId: event.requestId, requestKey: event.requestKey }))
      },
    })
  }

  get snapshot(): SessionSnapshot { return this.state }
  get generation(): number { return this.revision }

  /** Discard local authority after a credential change; no remote mutation is repeated. */
  invalidate(expectedRevision?: number): boolean {
    if (expectedRevision !== undefined && expectedRevision !== this.revision) return false
    this.revision++
    this.reads.cancel()
    this.session = undefined
    this.publish('reauthentication_required')
    return true
  }

  async refresh(signal?: AbortSignal): Promise<SessionRead> {
    if (this.changing) throw new RequestConfigurationError('session_change_pending')
    const previous = this.session
    const ticket = this.reads.start()
    const requestSignal = signal ? AbortSignal.any([ticket.signal, signal]) : ticket.signal
    this.publish('loading')
    try {
      const response = await this.client.json('/session', { signal: requestSignal, decodeResult: decodeSession })
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) {
        this.session = previous
        this.publish(previous ? previous.authenticated ? 'authenticated' : 'anonymous' : 'unresolved')
        return { applied: false }
      }
      this.session = response.result
      this.revision++
      this.publish(response.result.authenticated ? 'authenticated' : 'anonymous')
      return { applied: true, snapshot: this.state, meta: response.meta }
    } catch (error) {
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) {
        this.session = previous
        this.publish(previous ? previous.authenticated ? 'authenticated' : 'anonymous' : 'unresolved')
        return { applied: false }
      }
      this.session = undefined
      this.revision++
      this.publish(error instanceof HttpError && error.status === 401 ? 'reauthentication_required' : 'unresolved', safeError(error))
      throw error
    } finally {
      ticket.finish()
    }
  }

  async login(credentials: SessionLoginCredentials, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.change(async () => {
      const response = await this.client.loginSession(credentials, { signal, decodeResult: decodeAuthenticatedSession })
      this.session = response.result
      this.revision++
      this.publish('authenticated')
    })
  }

  async logout(signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.change(async () => {
      await this.client.json('/session', { method: 'DELETE', signal, decodeResult: decodeNull })
      this.session = { authenticated: false }
      this.revision++
      this.publish('anonymous')
    })
  }

  async changePassword(input: PasswordChange, signal?: AbortSignal): Promise<SessionSnapshot> {
    return this.change(async () => {
      if (!input || typeof input.current_password !== 'string' || typeof input.new_password !== 'string' || typeof input.confirmation !== 'string') {
        throw new RequestConfigurationError('invalid_password_change', { outcome: 'not_sent' })
      }
      await this.client.json('/password', { method: 'PUT', signal, body: {
        current_password: input.current_password, new_password: input.new_password, confirmation: input.confirmation,
      }, decodeResult: decodeNull })
      this.session = undefined
      this.revision++
      this.publish('reauthentication_required')
    }, true)
  }

  cancelRead(): void {
    this.reads.cancel()
    if (this.state.phase === 'loading') this.publish(this.session ? this.session.authenticated ? 'authenticated' : 'anonymous' : 'unresolved')
  }

  private async change(action: () => Promise<void>, preserveRejectedPassword = false): Promise<SessionSnapshot> {
    if (this.changing) throw new RequestConfigurationError('session_change_pending', { outcome: 'not_sent' })
    this.reads.cancel()
    const previous = this.session
    this.changing = true
    const ticket = ++this.revision
    this.publish('changing')
    try {
      await action()
      return this.state
    } catch (error) {
      // A concurrent explicit invalidation or current-session 401 owns the
      // newer state. A late rejection must not resurrect its earlier token.
      if (ticket !== this.revision) throw error
      const knownPasswordRejection = preserveRejectedPassword && previous?.authenticated && error instanceof HttpError && error.outcome === 'not_sent' &&
        (error.status === 400 || error.status === 429 || error.status === 403 && error.code === 'CURRENT_PASSWORD_INVALID')
      if (error instanceof RequestConfigurationError && error.outcome === 'not_sent' || knownPasswordRejection) {
        this.revision++
        this.session = previous
        this.publish(previous ? previous.authenticated ? 'authenticated' : 'anonymous' : 'unresolved', safeError(error))
      } else {
        this.revision++
        this.session = undefined
        this.publish(error instanceof HttpError && error.status === 401 ? 'reauthentication_required' : 'unknown', safeError(error))
      }
      throw error
    } finally {
      this.changing = false
    }
  }

  private publish(phase: SessionPhase, error?: ControlError): void {
    const operator = this.session?.authenticated ? Object.freeze({ ...this.session.operator }) : undefined
    this.state = Object.freeze({ phase, operator, expires_at: this.session?.authenticated ? this.session.expires_at : undefined, error })
    try { this.onChange?.(this.state) } catch { /* A view observer cannot change a protocol result. */ }
  }
}

function safeError(error: unknown): ControlError {
  return error instanceof ControlError ? error : new ControlError('invalid_response', 'invalid_session', 'The management session could not be verified.')
}
