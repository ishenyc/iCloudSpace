// Codes in persisted sync results predate the HTTP error envelope.
const reasons: Readonly<Record<string, string>> = {
  login_required: '请先登录 Apple 账户，再同步隐私邮箱目录。',
  authentication_required: 'Apple 登录已失效，请重新登录后继续。',
  session_binding: '已保存的 Apple 会话与当前主号不匹配，请核对账户并重新登录。',
  mail_auth: '收件服务器拒绝了登录，请核对 IMAP 用户名和应用专用密码。',
  mail_connect: '无法连接收件服务器，请核对 IMAP 地址、端口和网络连接。',
  mail_dns: '找不到收件服务器，请核对 IMAP 主机名和 DNS 设置。',
  mail_tls: '无法建立安全的收件连接，请核对 IMAP 端口和服务器证书。',
  mail_timeout: '收件服务器响应超时，请稍后查看邮件同步进度。',
  mail_command: '收件服务器未接受读取命令，请核对邮箱权限。',
  mail_protocol: '收件服务器返回了无法识别的响应，请核对 IMAP 配置。',
  directory_checkpoint_failed: '隐私邮箱目录的同步进度未能保存，请先核对本轮结果。',
  read_only: '当前安装处于只读状态，请等维护结束后继续。',
  source_changed: '主号配置已变化，请重新读取主号设置。',
  unresolved_attempt: '上次创建邮箱的结果仍待确认，请先查询原尝试。',
  capacity_reached: '隐私邮箱容量已满，请核对当前主号的可用容量。',
  rate_limited: 'Apple 暂时限制了请求次数，请稍后再试。',
  apple_rejected: 'Apple 未接受本次请求，请核对账户状态和当前操作。',
  challenge_method_unavailable: 'Apple 暂未提供可用的验证方式，请重新读取验证选项。',
  second_factor_required: '请在主号的 Apple 登录窗口完成两步验证。',
}
export function diagnosticMessage(code: string, fallback: string): string {
  const key = code.toLowerCase().replace(/^imap_/, 'mail_')
  if (Object.hasOwn(reasons, key)) return reasons[key]
  if (key.startsWith('directory_')) {
    const reason = key.slice('directory_'.length)
    if (Object.hasOwn(reasons, reason)) return reasons[reason]
    if (reason === 'timeout') return 'Apple 隐私邮箱目录响应超时，请稍后再同步。'
    if (['dns', 'connect', 'transport', 'tls'].includes(reason)) return '无法连接 Apple 隐私邮箱目录，请检查网络后再同步。'
  }
  return fallback
}
