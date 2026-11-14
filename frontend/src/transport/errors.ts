import type { RequestContext } from './types.ts'

export type ControlErrorCategory = 'request' | 'http' | 'transport' | 'invalid_response'

/** Stores only protocol diagnostics, never the URL, response body, token, or fetch exception. */
export class ControlError extends Error {
  readonly category: ControlErrorCategory
  readonly code: string
  readonly requestKey?: string
  readonly requestId?: string
  readonly submissionKey?: string
  readonly outcome?: RequestContext['outcome']
  readonly resource?: RequestContext['resource']

  constructor(category: ControlErrorCategory, code: string, message: string, context: RequestContext = {}) {
    super(message)
    this.name = 'ControlError'
    this.category = category
    this.code = code
    this.requestKey = context.requestKey
    this.requestId = context.requestId
    this.submissionKey = context.submissionKey
    this.outcome = context.outcome
    this.resource = context.resource ? Object.freeze({ ...context.resource }) : undefined
  }
}

export class RequestConfigurationError extends ControlError {
  constructor(code: string, context: RequestContext = {}) {
    super('request', code, 'The request could not be started.', context)
    this.name = 'RequestConfigurationError'
  }
}

export class HttpError extends ControlError {
  readonly status: number
  readonly kind?: string

  constructor(status: number, context: RequestContext = {}, detail?: { kind: string; code: string }) {
    super('http', detail?.code ?? 'http_error', 'The server rejected the request.', context)
    this.name = 'HttpError'
    this.status = status
    this.kind = detail?.kind
  }
}

export class TransportError extends ControlError {
  readonly reason: 'aborted' | 'network' | 'body_read'

  constructor(reason: TransportError['reason'], context: RequestContext = {}) {
    super('transport', reason, reason === 'aborted' ? 'The request was canceled.' : 'The connection did not complete.', context)
    this.name = 'TransportError'
    this.reason = reason
  }
}

export class InvalidResponseError extends ControlError {
  constructor(code: string, context: RequestContext = {}) {
    super('invalid_response', code, 'The server response could not be verified.', context)
    this.name = 'InvalidResponseError'
  }
}

const controlMessages: Readonly<Record<string, string>> = {
  SESSION_REQUIRED: '管理会话已失效，请重新登录。',
  SESSION_REAUTHENTICATION_REQUIRED: '请重新登录以恢复管理会话。',
  CREDENTIALS_INVALID: '登录凭据不正确，请核对用户名和密码。',
  CREDENTIALS_CHANGED: '登录凭据已更新，请重新登录。',
  CSRF_INVALID: '页面的安全凭据已失效，请刷新会话后再操作。',
  ORIGIN_REJECTED: '请求来源未通过校验，请从当前管理站点打开页面。',
  LOGIN_THROTTLED: '登录尝试过于频繁，请稍候再登录。',
  CURRENT_PASSWORD_INVALID: '当前密码不正确，请重新核对。',
  PASSWORD_POLICY: '新密码需为 12–72 字节，两次输入必须一致。',
  AUTH_INPUT_INVALID: '登录信息格式不正确，请核对输入。',
  INSTALLATION_READ_ONLY: '当前安装处于只读状态，请等待维护结束后再修改。',
  ACCOUNT_INPUT_INVALID: '主号配置或筛选条件不正确，请核对输入。',
  ACCOUNT_NOT_FOUND: '主号已不存在，请返回列表刷新。',
  ACCOUNT_REVISION_CONFLICT: '主号设置已变化，请重新读取后再修改。',
  ACCOUNT_IDENTITY_IN_USE: '该主号已有隐私邮箱，当前邮箱身份不能直接修改。',
  ACCOUNT_SOURCE_CHANGE_REQUIRED: '收件来源将发生变化，请核对并明确确认。',
  ACCOUNT_CREDENTIALS_UNAVAILABLE: '无法读取主号凭据，请检查当前安装的密钥与数据是否匹配。',
  ACCOUNT_HAS_DEPENDENT_STATE: '主号仍有关联数据，请使用主号清理入口处理。',
  ACCOUNT_SOURCE_CHANGE_UNAVAILABLE: '当前无法开始切换收件来源，尚未执行变更。',
  SOURCE_CREDENTIAL_READ_UNAVAILABLE: '主号凭据暂不可读，请保留当前状态并检查维护信息。',
  ADDRESS_INPUT_INVALID: '邮箱信息、筛选条件或选择范围不正确，请核对。',
  ADDRESS_NOT_FOUND: '邮箱或分组已不存在，请刷新列表。',
  ADDRESS_REVISION_CONFLICT: '邮箱或分组已变化，请重新读取后再修改。',
  ADDRESS_INELIGIBLE: '邮箱当前状态不支持此操作，请查看详情中的状态说明。',
  ADDRESS_LOCAL_CAPACITY: '主号的本地邮箱容量已满，请先核对已启用和待处理邮箱。',
  DIRECTORY_INCOMPLETE: '未能取得完整的 Apple 目录，本次不据此归档邮箱。请查看同步诊断。',
  ADDRESS_PROVIDER_UNAVAILABLE: '邮箱服务未能完成操作，请查看原请求结果和同步诊断。',
  PROVIDER_INPUT_INVALID: 'Apple 验证信息不正确，请核对验证方式和输入。',
  PROVIDER_REQUEST_NOT_FOUND: '主号或原认证请求已不可用，请重新读取主号状态。',
  PROVIDER_SCOPE_CHANGED: '主号身份或 Apple 会话已变化，请重新读取当前状态。',
  PROVIDER_OWNER_CHANGED: '当前登录身份已变化，请重新登录后查询原请求。',
  PROVIDER_CHALLENGE_EXPIRED: '本次 Apple 验证已过期，请从当前主号重新开始登录。',
  PROVIDER_ATTEMPTS_EXHAUSTED: '本次验证尝试次数已用完，请按 Apple 提示稍后处理。',
  PROVIDER_LOGIN_REQUIRED: '需要先登录 Apple，才能继续此操作。',
  HME_LOGIN_REQUIRED: '需要先登录 Apple，才能管理隐私邮箱。',
  CREDENTIAL_INPUT_INVALID: '凭据操作参数或确认内容不正确，请重新核对。',
  CREDENTIAL_SCOPE_CHANGED: '凭据范围已变化，请重新读取后再修改。',
  CREDENTIAL_MATERIAL_UNAVAILABLE: '该凭据已不可领取，可能已确认、轮换或撤销；请查看当前状态。',
  CREDENTIAL_ROTATION_THROTTLED: '凭据轮换过于频繁，请稍候再操作。',
  MAIL_DRAFT_BUSY: '邮件准备暂时繁忙，本次尚未提交。',
  MAIL_INPUT_INVALID: '收件人、正文或附件信息不正确，请核对。',
  MAIL_SEND_INELIGIBLE: '此邮箱当前不能发信，请核对启用状态和 Apple 登录。',
  MAIL_REQUEST_CONFLICT: '本次内容与记录中的原请求不同，请查询原请求并核对。',
  MAIL_REQUEST_NOT_FOUND: '原邮件请求已不可用，请保留请求编号并核对当前状态。',
  MAIL_BOOTSTRAP_PERMISSION_REQUIRED: '需要先明确允许本次邮件准备操作。',
  MAIL_REFERENCE_PENDING: '邮件准备尚未完成，请刷新同一封邮件的准备状态。',
  MAIL_PROVIDER_UNAVAILABLE: '未能核实邮件服务返回的结果，请查询原请求。',
  MAIL_INPUT_BUDGET: '邮件正文或附件超过限制，请减小内容后再准备。',
  MAIL_NOT_FOUND: '没有找到可读取的邮件，请刷新当前邮件列表。',
  MAIL_CREDENTIALS_INVALID: '邮箱凭据已失效或不允许此用途，请重新核对凭据。',
  SYNC_UNAVAILABLE: '当前没有可用的同步结果，请查看主号同步状态和诊断。',
  LOCAL_CLEANUP_INPUT_INVALID: '清理对象或确认内容不正确，请重新核对。',
  LOCAL_CLEANUP_CONFLICT: '清理范围已变化，请刷新数据并查询原操作。',
  LOCAL_CLEANUP_NOT_FOUND: '未找到匹配的清理对象或原操作，请核对当前状态。',
  ENDPOINT_NOT_FOUND: '当前页面使用的接口不存在，请刷新页面并核对安装版本。',
}

const unknownMessages: Readonly<Record<string, string>> = {
  AUTH_COMMIT_UNKNOWN: '登录或密码变更结果尚未确认，请检查当前会话，必要时主动重新登录。',
  ACCOUNT_COMMIT_UNKNOWN: '主号变更结果尚未确认，请查询候选主号，不要重复提交。',
  ADDRESS_COMMIT_UNKNOWN: '邮箱变更结果尚未确认，请查询原对象，不要重复提交。',
  CREDENTIAL_COMMIT_UNKNOWN: '凭据变更结果尚未确认，请查询原操作或未领取凭据，不要重复操作。',
  PROVIDER_REQUEST_UNKNOWN: 'Apple 认证操作结果尚未确认，请查询原请求，不要重复提交。',
  MAIL_REQUEST_UNKNOWN: '邮件准备或发信结果尚未确认，请查询原请求，不要再次提交。',
  HME_OPERATION_UNSETTLED: '隐私邮箱操作结果尚未确认，请查询原请求，不要重复操作。',
  LOCAL_CLEANUP_UNCONFIRMED: '清理结果尚未确认，请查询原操作，不要重新发起清理。',
  LOCAL_CLEANUP_COMMIT_UNKNOWN: '清理结果尚未确认，请查询原操作，不要重复清理。',
}

/** Uses controlled codes only; server text, URLs and private values are never reflected. */
export function controlErrorMessage(error: ControlError): string {
  if (unknownMessages[error.code]) return unknownMessages[error.code]
  const known = controlMessages[error.code]
  if (error.outcome === 'unknown') return `${known ? known + ' ' : ''}本次操作结果尚未确认，请查询原请求，不要重复提交。`
  if (known) return known
  if (error.category === 'request') return '请求尚未发出，请核对输入和当前页面。'
  if (error.category === 'transport') return error.code === 'aborted'
    ? '请求已取消，请先核对当前结果。'
    : '连接未能完成，请查询原请求或刷新当前状态后再操作。'
  if (error.category === 'invalid_response') return '未能核实服务器响应，请检查当前结果，变更操作不要重复提交。'
  if (error instanceof HttpError) {
    if (error.status === 401) return '管理会话已失效，请重新登录。'
    if (error.status === 403) return '此操作未通过安全校验，请刷新当前会话并核对权限。'
    if (error.status === 404) return '请求的对象已不可用，请刷新当前列表。'
    if (error.status === 409) return '当前数据已变化，请重新读取并核对原操作。'
    if (error.status === 413) return '请求内容超过限制，请减小内容。'
    if (error.status === 429) return '操作过于频繁，请稍候再处理。'
    if (error.status >= 500) return '服务暂不可用，请核对当前状态；未确认的操作请查询原请求。'
  }
  return '请求未能完成，请核对输入和当前状态。'
}
