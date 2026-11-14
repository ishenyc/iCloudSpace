import { HttpError, InvalidResponseError, RequestConfigurationError, TransportError } from './errors.ts'
import type {
  ControlClientOptions, ControlFailure, ControlResult, ErrorDetail, HttpMethod,
  JsonRequestOptions, RequestContext, RequestOptions, ResponseMeta, SubmissionOutcome,
  SessionLoginCredentials, SessionLoginOptions,
  ResourceReference,
} from './types.ts'

const methods = new Set<HttpMethod>(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
const outcomes = new Set<SubmissionOutcome>(['accepted', 'rejected', 'not_sent', 'unknown'])
const diagnostic = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/
const own = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key)
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)
const writeMethod = (method: HttpMethod) => method !== 'GET' && method !== 'HEAD'
const isOpaqueKey = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._~-]{0,511}$/.test(value)

interface PreparedRequest {
  url: string
  init: RequestInit
  context: RequestContext
  write: boolean
  sessionRevision?: number
}

/**
 * Deliberately has no retry, endpoint fallback, storage, or session singleton.
 * Resource paths and query values are kept separate so a caller cannot escape basePath.
 */
export class ControlClient {
  private readonly options: ControlClientOptions
  private readonly basePath: string

  constructor(options: ControlClientOptions) {
    this.basePath = validatePath(options.basePath, true).replace(/\/$/, '')
    this.options = options
  }

  async json<T>(path: string, options: JsonRequestOptions<T> = {}): Promise<ControlResult<T>> {
    return this.jsonRequest(path, options)
  }

  /** The sole anonymous write: create a session at the fixed canonical login endpoint. */
  async loginSession<T>(credentials: SessionLoginCredentials, options: SessionLoginOptions<T> = {}): Promise<ControlResult<T>> {
    if (!credentials || typeof credentials.username !== 'string' || typeof credentials.password !== 'string') {
      throw new RequestConfigurationError('invalid_login', { outcome: 'not_sent' })
    }
    return this.jsonRequest('/session', {
      method: 'POST', body: { username: credentials.username, password: credentials.password },
      signal: options.signal, decodeResult: options.decodeResult,
    }, true)
  }

  private async jsonRequest<T>(path: string, options: JsonRequestOptions<T>, login = false): Promise<ControlResult<T>> {
    const request = this.prepare(path, options, true, login)
    const response = await this.dispatch(request)
    const headerContext = this.responseContext(request, response)
    let envelope: unknown
    try {
      envelope = await this.readJson(response, request, headerContext)
    } catch (error) {
      this.notifyUnauthorized(response, request, headerContext)
      if (!response.ok && error instanceof InvalidResponseError) throw new HttpError(response.status, headerContext)
      throw error
    }
    const parsed = parseEnvelope(envelope)
    const context = parsed ? { ...headerContext, requestId: parsed.meta.request_id ?? headerContext.requestId } : headerContext
    this.notifyUnauthorized(response, request, context)
    if (parsed && 'error' in parsed) throw this.httpFailure(response, parsed.error, context)
    if (!response.ok) throw new HttpError(response.status, context)
    if (!parsed) throw new InvalidResponseError('invalid_envelope', context)
    let result: T
    try {
      result = options.decodeResult ? options.decodeResult(parsed.result) : parsed.result as T
    } catch {
      throw new InvalidResponseError('invalid_result', context)
    }
    return { result, meta: parsed.meta }
  }

  /** Callers consuming this response's body directly own body-read failure handling. */
  async raw(path: string, options: RequestOptions = {}): Promise<Response> {
    const request = this.prepare(path, options, false)
    return this.rawResponse(request)
  }

  /** Wraps stream failures without retaining the native exception or response URL. */
  async stream(path: string, options: RequestOptions = {}): Promise<ReadableStream<Uint8Array>> {
    const request = this.prepare(path, options, false)
    const response = await this.rawResponse(request)
    const context = this.responseContext(request, response)
    if (!response.body) throw new InvalidResponseError('missing_stream', context)
    const reader = response.body.getReader()
    let ended = false
    const release = () => {
      if (ended) return
      ended = true
      reader.releaseLock()
    }
    return new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        try {
          const chunk = await reader.read()
          if (chunk.done) {
            release()
            controller.close()
          } else {
            controller.enqueue(chunk.value)
          }
        } catch {
          release()
          controller.error(new TransportError(request.init.signal?.aborted ? 'aborted' : 'body_read', context))
        }
      },
      cancel: async () => {
        try {
          await reader.cancel()
        } catch {
          // Canceling consumption must never trigger a replacement request.
        } finally {
          release()
        }
      },
    })
  }

  private prepare(path: string, options: RequestOptions, json: boolean, login = false): PreparedRequest {
    // Invalid input must not be reflected into diagnostic metadata.
    const context: RequestContext = { requestKey: isOpaqueKey(options.requestKey) ? options.requestKey : undefined }
    const method = options.method ?? 'GET'
    const write = writeMethod(method)
    if (write) context.outcome = 'not_sent'
    if (!methods.has(method)) throw new RequestConfigurationError('invalid_method', context)
    if (options.requestKey !== undefined && !isOpaqueKey(options.requestKey)) throw new RequestConfigurationError('invalid_request_key', context)
    if (options.resource !== undefined) {
      if (!validResource(options.resource)) throw new RequestConfigurationError('invalid_resource', context)
      context.resource = { kind: options.resource.kind, id: options.resource.id }
    }
    if (options.signal?.aborted) throw new RequestConfigurationError('aborted_before_start', context)
    let url: string
    let headers: Headers
    let body: string | undefined
    try {
      const resource = validatePath(path, false)
      url = this.basePath + (resource ? '/' + resource : '')
      const search = options.search instanceof URLSearchParams ? new URLSearchParams(options.search) : new URLSearchParams()
      if (options.search && !(options.search instanceof URLSearchParams)) {
        for (const [name, value] of Object.entries(options.search)) {
          if (value !== null && value !== undefined) search.append(name, String(value))
        }
      }
      const query = search.toString()
      if (query) url += '?' + query
      headers = new Headers(options.headers)
      // Session authentication always belongs to the browser's same-origin cookie policy.
      headers.delete('Authorization')
      headers.delete('Proxy-Authorization')
      headers.delete('Cookie')
      if (json) headers.set('Accept', 'application/json')
      if (options.body !== undefined) {
        if (!write) throw new Error()
        body = JSON.stringify(options.body)
        if (body === undefined) throw new Error()
        headers.set('Content-Type', 'application/json')
      }
    } catch {
      throw new RequestConfigurationError('invalid_request', context)
    }
    // A caller-supplied header cannot override the current session token or attach it to a read.
    headers.delete('X-CSRF-Token')
    if (write && !(login && method === 'POST' && path === '/session')) {
      let token: string | undefined
      try {
        token = this.options.csrfToken?.()
        if (!token || !token.trim()) throw new Error()
        headers.set('X-CSRF-Token', token)
      } catch {
        throw new RequestConfigurationError('csrf_unavailable', context)
      }
    }
    let sessionRevision: number | undefined
    if (this.options.sessionRevision) {
      try { sessionRevision = this.options.sessionRevision() } catch { throw new RequestConfigurationError('invalid_session_revision', context) }
      if (!Number.isSafeInteger(sessionRevision) || sessionRevision < 0) throw new RequestConfigurationError('invalid_session_revision', context)
    }
    return {
      url,
      write,
      context,
      sessionRevision,
      init: { method, headers, body, signal: options.signal, mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store' },
    }
  }

  private async dispatch(request: PreparedRequest): Promise<Response> {
    // Recheck after synchronous token/body callbacks, before the fetch invocation boundary.
    if (request.init.signal?.aborted) throw new RequestConfigurationError('aborted_before_start', request.context)
    let fetch: ControlClientOptions['fetch']
    try { fetch = this.options.fetch ?? globalThis.fetch } catch { /* Report unavailable runtime support below. */ }
    if (typeof fetch !== 'function') throw new RequestConfigurationError('fetch_unavailable', request.context)
    if (request.write) request.context.outcome = 'unknown'
    try {
      return await fetch(request.url, request.init)
    } catch {
      throw new TransportError(request.init.signal?.aborted ? 'aborted' : 'network', request.context)
    }
  }

  private responseContext(request: PreparedRequest, response: Response): RequestContext {
    const requestId = response.headers.get('X-Request-ID')
    return { ...request.context, requestId: requestId && diagnostic.test(requestId) ? requestId : undefined }
  }

  private async readJson(response: Response, request: PreparedRequest, context: RequestContext): Promise<unknown> {
    const mediaType = response.headers.get('Content-Type')?.split(';', 1)[0].trim().toLowerCase()
    if (mediaType !== 'application/json') {
      try { await response.body?.cancel() } catch { /* Discard the invalid body without retaining its error. */ }
      throw new InvalidResponseError('expected_json', context)
    }
    let text: string
    try {
      text = await response.text()
    } catch {
      throw new TransportError(request.init.signal?.aborted ? 'aborted' : 'body_read', context)
    }
    try {
      return JSON.parse(text) as unknown
    } catch {
      throw new InvalidResponseError('invalid_json', context)
    }
  }

  private httpFailure(response: Response, error: ErrorDetail, context: RequestContext): HttpError {
    if (context.requestKey && error.submission_key && context.requestKey !== error.submission_key) {
      throw new InvalidResponseError('submission_key_mismatch', context)
    }
    if (context.resource && error.resource && (context.resource.kind !== error.resource.kind || context.resource.id !== error.resource.id)) {
      throw new InvalidResponseError('resource_mismatch', context)
    }
    return new HttpError(response.status, {
      ...context,
      submissionKey: error.submission_key,
      outcome: error.outcome ?? context.outcome,
      resource: error.resource ?? context.resource,
    }, { kind: error.kind, code: error.code })
  }

  private notifyUnauthorized(response: Response, request: PreparedRequest, context: RequestContext): void {
    if (response.status !== 401 || request.init.signal?.aborted) return
    try {
      if (this.options.sessionRevision && request.sessionRevision !== this.options.sessionRevision()) return
      this.options.onUnauthorized?.({ status: 401, requestId: context.requestId, requestKey: context.requestKey, signal: request.init.signal ?? undefined })
    } catch {
      // A UI callback cannot replace the request's actual protocol result.
    }
  }

  private async rawResponse(request: PreparedRequest): Promise<Response> {
    const response = await this.dispatch(request)
    const headerContext = this.responseContext(request, response)
    if (response.ok) return response
    let envelope: unknown
    try {
      envelope = await this.readJson(response, request, headerContext)
    } catch {
      this.notifyUnauthorized(response, request, headerContext)
      throw new HttpError(response.status, headerContext)
    }
    const parsed = parseEnvelope(envelope)
    const context = parsed ? { ...headerContext, requestId: parsed.meta.request_id ?? headerContext.requestId } : headerContext
    this.notifyUnauthorized(response, request, context)
    throw parsed && 'error' in parsed ? this.httpFailure(response, parsed.error, context) : new HttpError(response.status, context)
  }
}

function validatePath(value: string, base: boolean): string {
  // Repeated decode checks also reject an encoded delimiter that a proxy might decode twice.
  if (typeof value !== 'string' || /[\s\\?#\u0000-\u001f\u007f]/.test(value) || value.includes('//') || value.includes(':')) throw new RequestConfigurationError('invalid_path')
  if (base && (!value.startsWith('/') || value === '/')) throw new RequestConfigurationError('invalid_base_path')
  const path = value.replace(/^\//, '').replace(/\/$/, '')
  for (const segment of path.split('/')) {
    let decoded = segment
    for (let depth = 0; depth < 4; depth++) {
      if (decoded === '.' || decoded === '..' || /[\\/\s?#:\u0000-\u001f\u007f]/.test(decoded)) throw new RequestConfigurationError('invalid_path')
      let next: string
      try { next = decodeURIComponent(decoded) } catch { throw new RequestConfigurationError('invalid_path') }
      if (next === decoded) break
      if (depth === 3) throw new RequestConfigurationError('invalid_path')
      decoded = next
    }
  }
  return base ? '/' + path : path
}

function parseEnvelope(value: unknown): ControlResult<unknown> | ControlFailure | undefined {
  if (!record(value) || !record(value.meta)) return undefined
  if (value.meta.request_id !== undefined && (typeof value.meta.request_id !== 'string' || !diagnostic.test(value.meta.request_id))) return undefined
  const meta: ResponseMeta = value.meta.request_id === undefined ? {} : { request_id: value.meta.request_id as string }
  if (own(value, 'result') === own(value, 'error')) return undefined
  if (own(value, 'result')) return { result: value.result, meta }
  const error = value.error
  if (!record(error) || typeof error.kind !== 'string' || !diagnostic.test(error.kind) || typeof error.code !== 'string' || !diagnostic.test(error.code) || typeof error.message !== 'string') return undefined
  if (error.submission_key !== undefined && !isOpaqueKey(error.submission_key)) return undefined
  if (error.outcome !== undefined && !outcomes.has(error.outcome as SubmissionOutcome)) return undefined
  if (error.resource !== undefined && !validResource(error.resource)) return undefined
  return {
    error: {
      kind: error.kind,
      code: error.code,
      // Parse the field for protocol validity; never retain its untrusted content in a thrown error.
      message: '',
      submission_key: error.submission_key as string | undefined,
      outcome: error.outcome as SubmissionOutcome | undefined,
      resource: error.resource === undefined ? undefined : { kind: error.resource.kind, id: error.resource.id },
    },
    meta,
  }
}

function validResource(value: unknown): value is ResourceReference {
  return record(value) && (value.kind === 'account' || value.kind === 'address' || value.kind === 'address_group') && typeof value.id === 'string' &&
    /^[1-9][0-9]{0,18}$/.test(value.id) && (value.id.length < 19 || value.id <= '9223372036854775807') &&
    Object.keys(value).every((key) => key === 'kind' || key === 'id')
}
