import { diagnosticMessage } from '../lib/diagnostic-message.ts'
import type { RuntimeEvent } from './event-contracts.ts'

const labels: Record<string, string> = {
  round_queued: '本轮已排队', round_succeeded: '本轮完成', round_degraded: '本轮完成，目录存在警告', round_failed: '本轮最终失败',
  round_cancelled: '本轮已取消', round_superseded: '本轮已被替代', round_unknown: '本轮结果待核对',
  attempt_failed: '本次尝试失败', attempt_unknown: '本次尝试结果待核对', attempt_completed: '本次尝试完成',
  segment_pending: '继续下一批邮件', directory_degraded: '目录同步存在警告', admission_failed: '等待同步资源',
  creation_claimed: '开始自动创建', creation_confirmed: '自动创建完成', creation_not_created: '本次未创建',
  creation_rate_cooldown: '远端限流，进入冷却', creation_paused: '自动创建已暂停',
}
const terminalStages = new Set(['round_succeeded', 'round_degraded', 'round_failed', 'round_cancelled', 'round_superseded', 'round_unknown', 'creation_confirmed', 'creation_not_created'])

/** Runtime projections carry the executor phase and an explicit event stage.
 * Coordinator event rows already carry the event name as their phase. */
export function runtimeStage(event: RuntimeEvent): string {
  return Object.hasOwn(labels, event.fields.stage) ? event.fields.stage : event.phase
}
export function terminalRuntimeEvent(event: RuntimeEvent): boolean { return terminalStages.has(runtimeStage(event)) }
export function runtimeStageLabel(event: RuntimeEvent): string | undefined {
  const stage = runtimeStage(event), label = labels[stage]
  return stage === 'round_succeeded' && event.fields.recovered === 'true' ? label + '（重试后恢复）' : label
}
export function runtimeMessage(event: RuntimeEvent): string {
  const label = runtimeStageLabel(event)
  if (event.error_code) return (label ? label + '。' : '') + diagnosticMessage(event.error_code, '当前步骤遇到问题，请展开诊断详情。')
  return label || event.message
}
