import type { HMEOperationResult } from './hme-contracts.ts'

/** Presentation never turns a terminal preflight failure into an unknown send. */
export function hmeResultHint(result: HMEOperationResult): string {
  const code = result.warning?.code, operation = result.operation
  if (code === 'HME_LOGIN_REQUIRED') return 'Apple 会话尚未通过认证，本次未生成或预约地址。请先完成认证，再明确发起新的创建。'
  if (code === 'INSTALLATION_READ_ONLY') return '安装当前只读，本次未生成或预约地址。'
  if (operation.error_code === 'forwarding_initialized_retry_explicit') return '转发目标初始化已确认。本次没有生成邮箱；如需新建，请明确提交一次新的创建。'
  if (operation.error_code === 'forwarding_initialization_unknown') return '转发目标初始化结果待确认，请查询原请求；不会自动初始化或再次创建。'
  if (operation.error_code === 'forwarding_target_unverified') return 'Apple 当前选中的转发目标与本主号不一致，或目标尚未核实。本次未生成或预约地址，请核对 Apple 转发设置。'
  if (operation.error_code === 'forwarding_preflight_failed') return '创建前的目录或会话检查失败，本次未生成或预约地址。请先检查真实错误，再明确发起新的创建。'
  if (operation.error_code === 'source_changed') return '主号配置已变化，本次未生成或预约地址。请重新读取主号后再创建。'
  if (operation.state === 'failed') return 'Apple 已明确拒绝原操作' + (operation.error_code ? '（' + operation.error_code + '）' : '') + '。原结果已保留。'
  return '原操作尚未确认，请查询原请求。'
}
