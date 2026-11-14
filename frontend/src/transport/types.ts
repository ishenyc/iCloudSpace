export type SubmissionOutcome = 'accepted' | 'rejected' | 'not_sent' | 'unknown'

export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface ResponseMeta {
  request_id?: string
}

export interface ControlResult<T> {
  result: T
  meta: ResponseMeta
}

export interface ErrorDetail {
  kind: string
  code: string
  message: string
  submission_key?: string
  outcome?: SubmissionOutcome
  resource?: ResourceReference
}

export interface ResourceReference {
  kind: 'account' | 'address' | 'address_group'
  id: string
}

export interface ControlFailure {
  error: ErrorDetail
  meta: ResponseMeta
}

export interface RequestContext {
  requestKey?: string
  requestId?: string
  submissionKey?: string
  outcome?: SubmissionOutcome
  resource?: ResourceReference
}

export interface UnauthorizedEvent {
  status: 401
  requestId?: string
  requestKey?: string
  signal?: AbortSignal
}

export type FetchImplementation = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export type SearchParameters = URLSearchParams | Readonly<Record<string, string | number | boolean | null | undefined>>

export interface RequestOptions {
  method?: HttpMethod
  signal?: AbortSignal
  search?: SearchParameters
  headers?: HeadersInit
  body?: unknown
  /** Identifies an existing submission; this value never causes an automatic retry. */
  requestKey?: string
  /** Exact known command target. Creation never invents an ID for this field. */
  resource?: ResourceReference
}

export interface JsonRequestOptions<T> extends RequestOptions {
  decodeResult?: (value: unknown) => T
}

export interface SessionLoginCredentials {
  username: string
  password: string
}

export interface SessionLoginOptions<T> {
  signal?: AbortSignal
  decodeResult?: (value: unknown) => T
}

export interface ControlClientOptions {
  /** Same-origin path including the installed management entry and /api/control/v1. */
  basePath: string
  fetch?: FetchImplementation
  /** The caller owns token acquisition and lifetime. No cookie or storage reads occur here. */
  csrfToken?: () => string | undefined
  onUnauthorized?: (event: UnauthorizedEvent) => void
  /** A session owner may suppress a late 401 event from an earlier authenticated state. */
  sessionRevision?: () => number
}
