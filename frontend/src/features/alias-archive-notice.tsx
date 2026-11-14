import { Link } from 'react-router-dom'
import { Alert } from '../components/ui'
import { formatAliasTime } from './aliases/model'
import { archivedAccountPath, archiveSyncChange } from './alias-archive'

export function AliasArchiveNotice({ archivedAt, reason }: { archivedAt: string; reason?: 'remote_missing' | 'historical' }) {
  return <Alert tone="warning"><div className="stack" style={{ gap: 4 }}><strong>此邮箱已归档</strong><span>{reason === 'historical' ? '此地址保留原有归档事实，当前已停用；历史邮件仍可查看。' : 'Apple 完整目录已无此地址，已归档并停用；历史邮件保留。'}</span><span className="text-muted">归档时间：{formatAliasTime(archivedAt, true)}</span></div></Alert>
}

export function AliasArchiveSyncNotice({ accountId, summary }: { accountId: string; summary: { archived: number; rediscovered: number } | null }) {
  const changes = archiveSyncChange(summary)
  if (!changes) return null
  return <Alert tone="warning"><div className="stack" style={{ gap: 6 }}>{changes.archived > 0 && <span>本次归档 {changes.archived} 个邮箱。Apple 完整目录已无这些地址，已停用；历史邮件保留。</span>}{changes.rediscovered > 0 && <span>目录重新发现 {changes.rediscovered} 个邮箱，已解除归档并保持停用；请核对后再决定是否启用。</span>}<Link className="text-link" to={archivedAccountPath(accountId, changes.archived > 0)}>{changes.archived > 0 ? '查看此主号已归档邮箱' : '查看此主号未归档邮箱'}</Link></div></Alert>
}
