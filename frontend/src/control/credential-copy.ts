import type { CredentialBundle } from './credential-contracts.ts'

export type CredentialCopyFormat = 'otp' | 'imap'
export interface CredentialCopyLinks { otp: string; recent: string; raw: string }

/** URL order, explicit flags, CRLF separators and no trailing newline match
 * the original copy contract. Only same-origin public paths are accepted. */
export function credentialCopyURL(path: string, origin: string): string {
  const base = new URL(origin), target = new URL(path, base.origin)
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || !path.startsWith('/') || path.startsWith('//') || target.origin !== base.origin || target.hash || !['/api/v1/otp', '/api/v1/mail/recent', '/api/v1/mail/recent/'].includes(target.pathname)) throw new Error('接入链接无效')
  return target.href
}

export function credentialCopyText(rows: readonly { address: string; bundle?: CredentialBundle; links?: CredentialCopyLinks }[], format: CredentialCopyFormat, origin: string): string {
  const field = (value: string | undefined) => {
    const text = value
    if (!text || /[\r\n]/.test(text)) throw new Error('复制凭据不完整')
    return text
  }
  return rows.map(row => format === 'otp'
    ? `${field(row.address)}----${credentialCopyURL(field(row.links?.otp), origin)}`
    : `${field(row.address)}----${field(row.bundle?.imap.password)}----${field(row.bundle?.oauth.client_id)}----${field(row.bundle?.oauth.refresh_token)}`).join('\r\n')
}
