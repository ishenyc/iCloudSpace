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
  HME_DIRECTORY_READ_FAILED: '读取 Apple 隐私邮箱目录失败，本次未变更本地邮箱。可稍后再同步。',
  HME_DIRECTORY_READ_TIMEOUT: '读取 Apple 隐私邮箱目录超时，本次未变更本地邮箱。可稍后再同步。',
  HME_DIRECTORY_RATE_LIMITED: 'Apple 暂时限制了目录读取，请稍后再同步。本次未变更本地邮箱。',
  HME_DIRECTORY_SESSION_CHECKPOINT: 'Apple 会话保存结果待核对，本次未变更本地邮箱。请查看主号的 Apple 会话状态。',
  PROVIDER_TRUST_CHOICE_REQUIRED: '请刷新页面，在验证码通过后选择是否信任此登录环境。',
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
  ALIAS_EXISTS: '此隐私邮箱已经登记，请从邮箱列表查看。',
  ALIAS_LIMIT_REACHED: '已达到邮箱数量上限，请核对主号容量。',
  CREATION_INPUT_INVALID: '创建计划的数量或时间无效，请核对设置。',
  CREATION_RESOURCE_NOT_FOUND: '找不到原创建计划或尝试，请刷新主号详情。',
  CREATION_REVIEW_REQUIRED: '上次创建仍需核对，请查看原尝试。',
  CREATION_REVISION_CHANGED: '创建计划已变化，请重新读取后修改。',
  CREATION_SOURCE_INELIGIBLE: '此主号当前无法创建邮箱，请核对主号类型和启用状态。',
  CREDENTIAL_EXPORT_INPUT_INVALID: '导出范围无效，请重新选择邮箱。',
  CREDENTIAL_EXPORT_SELECTION_INELIGIBLE: '所选邮箱中有无法导出的凭据，请刷新列表并核对选择。',
  HME_CREATION_NOT_STARTED: '创建请求尚未开始，请核对主号和转发设置。',
  HME_FORWARDING_INITIALIZED: '转发设置已初始化，可以重新发起一次创建。',
  HME_OPERATION_REJECTED: 'Apple 未接受这次邮箱操作，请核对邮箱状态。',
  DATABASE_UNAVAILABLE: '暂时无法读取数据库，请稍后刷新。',
  EVENT_QUERY_INVALID: '日志筛选条件无效，请核对时间和筛选范围。',
  MAIL_CONTENT_UNAVAILABLE: '此邮件的正文暂不可用，请查看邮件详情。',
  MAIL_ORIGINAL_UNAVAILABLE: '此邮件的完整原文暂不可用，请稍后再查看。',
  MAIL_SCOPE_DENIED: '当前凭据没有访问此邮件的权限。',
  MAIL_ALREADY_CONSUMED: '这封邮件已被领取，请查看之后的邮件。',
  MAIL_REFERENCE_CHANGED: '邮件准备记录已变化，请查询原发送记录。',
  MAIL_PREPARATION_RETIRED: '这条准备记录已停用，请查看原邮件的发送结果。',
  SYNCHRONIZATION_INPUT_INVALID: '同步请求的范围无效，请重新选择主号。',
  SYNCHRONIZATION_SOURCE_DISABLED: '主号已停用，请先启用主号。',
  SYNCHRONIZATION_SOURCE_NOT_FOUND: '找不到要同步的主号，请刷新列表。',
  SYNCHRONIZATION_COORDINATOR_UNAVAILABLE: '同步服务暂不可用，请稍后查看主号同步进度。',
  SYNCHRONIZATION_UNAVAILABLE: '暂时无法读取同步状态，请稍后刷新。',
  ENDPOINT_NOT_FOUND: '当前页面使用的接口不存在，请刷新页面并核对安装版本。',
}

const unknownMessages: Readonly<Record<string, string>> = {
  CREATION_RESULT_UNKNOWN: '本次创建结果尚未确认，请查询原尝试。',
  MAIL_CLAIM_UNKNOWN: '邮件领取结果尚未确认，请核对原领取记录。',
  MAIL_AUTHORIZATION_UNKNOWN: '邮件访问权限仍待确认，请核对原请求。',
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
  if (Object.hasOwn(unknownMessages, error.code)) return unknownMessages[error.code]
  const known = Object.hasOwn(controlMessages, error.code) ? controlMessages[error.code] : undefined
  if (error.outcome === 'unknown') return `${known ? known + ' ' : ''}本次操作结果尚未确认，请查询原请求，不要重复提交。`
  if (known) return known
  if (error.category === 'request') return '请求尚未发出，请核对输入和当前页面。'
  if (error.category === 'transport') return error.code === 'aborted'
    ? '请求已取消，请先核对当前结果。'
    : '连接中断，请检查网络并核对操作结果。'
  if (error.category === 'invalid_response') return '无法核实返回结果。请先核对当前状态，修改操作不要重复提交。'
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
