import type { AddressMetadata } from '../control/address-contracts.ts'
export type ArchiveFilter = '' | 'false' | 'true'
export type AliasView = 'current' | 'archived'

export function aliasViewArchiveFilter(view: AliasView): ArchiveFilter {
  return view === 'archived' ? 'true' : 'false'
}

export function aliasViewPath(view: AliasView, params = new URLSearchParams()) {
  const query = new URLSearchParams(params)
  query.delete('archived')
  const path = view === 'archived' ? '/aliases/archived' : '/aliases'
  return query.size ? `${path}?${query}` : path
}

// Sidebar folders are destinations in the current mailbox space. Filtering an
// archive by group remains available in that page's own filter controls.
export function aliasGroupPath(groupId: string, params = new URLSearchParams()) {
  const query = new URLSearchParams(params)
  query.delete('manageGroups')
  query.delete('page')
  groupId ? query.set('groupId', groupId) : query.delete('groupId')
  return aliasViewPath('current', query)
}

// Existing directory notices and bookmarks may still carry the former filter.
// Navigation keeps their source/group scope without issuing a business request.
export function legacyAliasArchivePath(params: URLSearchParams) {
  return params.has('archived') ? aliasViewPath(params.get('archived') === 'true' ? 'archived' : 'current', params) : null
}

export function archiveFilter(value: string | null): ArchiveFilter {
  return value === 'true' || value === 'false' ? value : ''
}

export function archiveQuery(value: ArchiveFilter): 'all' | 'archived' | 'unarchived' {
  return value === '' ? 'all' : value === 'true' ? 'archived' : 'unarchived'
}

export function withArchiveFilter(params: URLSearchParams, value: ArchiveFilter) {
  const next = new URLSearchParams(params)
  if (value) next.set('archived', value)
  else next.delete('archived')
  return next
}

export function archivedAccountPath(accountId: string, archived = true) {
  return aliasViewPath(archived ? 'archived' : 'current', new URLSearchParams({ sourceId: accountId }))
}

// Lifecycle/grants are facts; retained fields and URL/error formats grant nothing.
export function aliasAccess(alias: AddressMetadata) {
  const archived = alias.lifecycle === 'archived', pending = alias.lifecycle === 'pending', deleting = alias.lifecycle === 'deletion_pending'
  const confirmed = alias.lifecycle === 'confirmed', material = alias.credential_profile !== 'unavailable'
  return {
    archived,
    pending,
    deleting,
    canReveal: confirmed && material,
    canRotate: confirmed && material,
    canToggle: confirmed,
    canDelete: confirmed || archived,
    canSend: confirmed && alias.enabled && (alias.source_kind === 'apple_direct' || alias.source_kind === 'apple_forwarded'),
    canExport: confirmed && material,
    canExportMailbox: confirmed && alias.credential_profile === 'mailbox',
    canReceive: !pending,
  }
}

export function confirmedAliasDeletion(address: string, confirmation: string) {
  return confirmation.trim() === address
}

export function archiveSyncChange(summary: { archived: number; rediscovered: number } | null) {
  if (!summary) return null
  return summary.archived > 0 || summary.rediscovered > 0 ? { archived: summary.archived, rediscovered: summary.rediscovered } : null
}
