import { ContractError } from './contracts.ts'

export interface InstallationBootstrap {
  readonly version: 1
  readonly ui_path: string
  readonly control_path: string
  readonly public_mail_path: '/api/mail/v1'
  readonly previous_control_path?: string
}

function entry(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value === '/' || value.endsWith('/') || /[?#%{}\\\s\p{Cc}]/u.test(value) || value.includes('//') || value.split('/').some((part) => part === '.' || part === '..') || value === '/api' || value.startsWith('/api/') || value === '/healthz') throw new ContractError('installation_bootstrap')
  return value
}

export function decodeInstallationBootstrap(value: unknown): Readonly<InstallationBootstrap> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('installation_bootstrap')
  const data = value as Record<string, unknown>, ui_path = entry(data.ui_path)
  if (data.version !== 1 || data.control_path !== ui_path + '/api/control/v1' || data.public_mail_path !== '/api/mail/v1') throw new ContractError('installation_bootstrap')
  let previous: string | undefined
  if (data.previous_control_path !== undefined) {
    if (typeof data.previous_control_path !== 'string' || !data.previous_control_path.endsWith('/api/control/v1')) throw new ContractError('installation_bootstrap')
    const oldEntry = entry(data.previous_control_path.slice(0, -'/api/control/v1'.length))
    if (oldEntry === ui_path) throw new ContractError('installation_bootstrap')
    previous = data.previous_control_path
  }
  return Object.freeze({ version: 1, ui_path, control_path: data.control_path as string, public_mail_path: '/api/mail/v1', ...(previous ? { previous_control_path: previous } : {}) })
}

/** The server supplies this data block at the retained installed entry. */
export function readInstallationBootstrap(document: Pick<Document, 'getElementById'>): Readonly<InstallationBootstrap> {
  const node = document.getElementById('space-runtime')
  if (!node || node.tagName !== 'SCRIPT' || node.getAttribute('type') !== 'application/json' || typeof node.textContent !== 'string') throw new ContractError('installation_bootstrap')
  try { return decodeInstallationBootstrap(JSON.parse(node.textContent)) } catch { throw new ContractError('installation_bootstrap') }
}
