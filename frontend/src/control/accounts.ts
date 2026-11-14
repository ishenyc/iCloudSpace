import { ControlClient, ControlError, RequestConfigurationError, RequestSequence } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import {
  ContractError, decodeAccount, decodeAccountChange, decodeAccountDeleted, decodeAccountKind,
  decodeAccountPage, decodeAccountReveal, decodeCredentials, decodeEndpoint, decodeIdentifier,
} from './contracts.ts'
import type {
  Account, AccountChange, AccountCreate, AccountDelete, AccountDeleted, AccountExport,
  AccountFilter, AccountListQuery, AccountPage, AccountPatch, AccountReveal, AppleIdentityInput,
} from './contracts.ts'

/** Explicit account operations. No credential reveal, export, or mutation runs during a list read. */
export class AccountsModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  list(query: AccountListQuery = {}, signal?: AbortSignal): Promise<ControlResult<AccountPage>> {
    const search = input(() => {
      const filter = filterBody(query)
      if (query.page !== undefined && (!Number.isSafeInteger(query.page) || query.page < 1)) throw new ContractError('page')
      if (query.page_size !== undefined && (!Number.isSafeInteger(query.page_size) || query.page_size < 1 || query.page_size > 1000)) throw new ContractError('page_size')
      return { ...filter, page: query.page, page_size: query.page_size }
    })
    return this.client.json('/accounts', { search, signal, decodeResult: decodeAccountPage })
  }

  get(id: string, signal?: AbortSignal): Promise<ControlResult<Account>> {
    const sourceID = input(() => decodeIdentifier(id))
    return this.client.json('/accounts/' + sourceID, { signal, decodeResult: (value) => {
      const account = decodeAccount(value)
      if (account.id !== sourceID) throw new ContractError('id')
      return account
    } })
  }

  create(value: AccountCreate, signal?: AbortSignal): Promise<ControlResult<Account>> {
    const body = input(() => {
      const data = object(value)
      const kind = decodeAccountKind(data.kind)
      const apple = data.apple === undefined ? undefined : appleInput(data.apple)
      if ((kind === 'custom') === (apple !== undefined)) throw new ContractError('apple')
      return {
        kind, display_name: text(data.display_name), address_namespace: text(data.address_namespace),
        endpoint: decodeEndpoint(data.endpoint), address_suffix: text(data.address_suffix), enabled: boolean(data.enabled),
        credentials: decodeCredentials(data.credentials), ...(apple ? { apple } : {}),
      }
    })
    return this.client.json('/accounts', { method: 'POST', body, signal, decodeResult: decodeAccount })
  }

  patch(id: string, value: AccountPatch, signal?: AbortSignal): Promise<ControlResult<AccountChange>> {
    const sourceID = input(() => decodeIdentifier(id))
    const body = input(() => {
      const data = object(value)
      const patch: AccountPatch = { expected_revision: decodeIdentifier(data.expected_revision, 'expected_revision') }
      if (data.require_source_change !== undefined) patch.require_source_change = boolean(data.require_source_change)
      if (data.kind !== undefined) patch.kind = decodeAccountKind(data.kind)
      if (data.display_name !== undefined) patch.display_name = text(data.display_name)
      if (data.address_namespace !== undefined) patch.address_namespace = text(data.address_namespace)
      if (data.address_suffix !== undefined) patch.address_suffix = text(data.address_suffix)
      if (data.endpoint !== undefined) patch.endpoint = decodeEndpoint(data.endpoint)
      if (data.enabled !== undefined) patch.enabled = boolean(data.enabled)
      if (data.credentials !== undefined) patch.credentials = decodeCredentials(data.credentials)
      if (data.apple !== undefined) patch.apple = appleInput(data.apple)
      if (patch.kind === 'custom' && patch.apple) throw new ContractError('apple')
      return patch
    })
    return this.client.json('/accounts/' + sourceID, { method: 'PATCH', body, signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const change = decodeAccountChange(value)
      if (change.source.id !== sourceID) throw new ContractError('id')
      return change
    } })
  }

  reveal(id: string, signal?: AbortSignal): Promise<ControlResult<AccountReveal>> {
    const sourceID = input(() => decodeIdentifier(id))
    return this.client.json('/accounts/' + sourceID + '/reveal', { method: 'POST', body: {}, signal, decodeResult: (value) => {
      const reveal = decodeAccountReveal(value)
      if (reveal.source.id !== sourceID) throw new ContractError('id')
      return reveal
    } })
  }

  delete(id: string, value: AccountDelete, signal?: AbortSignal): Promise<ControlResult<AccountDeleted>> {
    const sourceID = input(() => decodeIdentifier(id))
    const body = input(() => {
      const data = object(value)
      const operation_key = text(data.operation_key)
      if (!/^[A-Za-z0-9][A-Za-z0-9._~-]{0,511}$/.test(operation_key)) throw new ContractError('operation_key')
      return { expected_revision: decodeIdentifier(data.expected_revision, 'expected_revision'), operation_key }
    })
    return this.client.json('/accounts/' + sourceID, { method: 'DELETE', body, signal, requestKey: body.operation_key, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const deleted = decodeAccountDeleted(value)
      if (deleted.source_id !== sourceID || deleted.operation_key !== body.operation_key) throw new ContractError('deletion')
      return deleted
    } })
  }

  /** The caller invokes this only after the operator explicitly chooses a sensitive export. */
  export(value: AccountExport, signal?: AbortSignal): Promise<ReadableStream<Uint8Array>> {
    const body = input(() => {
      const data = object(value)
      if (data.format !== 'csv' && data.format !== 'jsonl') throw new ContractError('format')
      return { format: data.format, filter: filterBody(object(data.filter)) }
    })
    return this.client.stream('/accounts/export', { method: 'POST', body, signal })
  }

  /** Reads the server's actual candidate ID. It never recreates or repeats the original command. */
  async queryUnknownResource(error: unknown, signal?: AbortSignal): Promise<ControlResult<Account> | undefined> {
    if (!(error instanceof ControlError) || error.outcome !== 'unknown' || error.resource?.kind !== 'account') return undefined
    return this.get(error.resource.id, signal)
  }
}

export interface AccountListSnapshot {
  readonly phase: 'idle' | 'loading' | 'ready' | 'error'
  readonly page?: AccountPage
  readonly error?: ControlError
}

export type AccountListRead = { applied: false } | { applied: true; response: ControlResult<AccountPage> }

/** Owns only the replaceable metadata read; mutation and sensitive results are never cached here. */
export class AccountListModel {
  private readonly reads = new RequestSequence()
  private state: AccountListSnapshot = Object.freeze({ phase: 'idle' })
  private readonly accounts: AccountsModel
  private readonly onChange?: (state: AccountListSnapshot) => void
  constructor(accounts: AccountsModel, onChange?: (state: AccountListSnapshot) => void) { this.accounts = accounts; this.onChange = onChange }
  get snapshot(): AccountListSnapshot { return this.state }

  async load(query: AccountListQuery = {}, signal?: AbortSignal): Promise<AccountListRead> {
    const ticket = this.reads.start()
    const requestSignal = signal ? AbortSignal.any([ticket.signal, signal]) : ticket.signal
    const previous: AccountListSnapshot = this.state.phase === 'loading'
      ? this.state.page ? { phase: 'ready', page: this.state.page } : { phase: 'idle' }
      : this.state
    this.publish({ phase: 'loading', page: previous.page })
    try {
      const response = await this.accounts.list(query, requestSignal)
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) { this.publish(previous); return { applied: false } }
      this.publish({ phase: 'ready', page: response.result })
      return { applied: true, response }
    } catch (error) {
      if (!ticket.isCurrent()) return { applied: false }
      if (requestSignal.aborted) { this.publish(previous); return { applied: false } }
      this.publish({ phase: 'error', page: previous.page, error: error instanceof ControlError ? error : new ControlError('invalid_response', 'invalid_accounts', 'The account list could not be verified.') })
      throw error
    } finally { ticket.finish() }
  }

  cancel(): void {
    this.reads.cancel()
    if (this.state.phase === 'loading') this.publish({ phase: this.state.page ? 'ready' : 'idle', page: this.state.page })
  }

  private publish(state: AccountListSnapshot): void {
    this.state = Object.freeze(state)
    try { this.onChange?.(this.state) } catch { /* A view observer cannot change the read result. */ }
  }
}

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_account_input', { outcome: 'not_sent' }) }
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ContractError('input')
  return value as Record<string, unknown>
}
function text(value: unknown): string { if (typeof value !== 'string') throw new ContractError('input'); return value }
function boolean(value: unknown): boolean { if (typeof value !== 'boolean') throw new ContractError('input'); return value }
function appleInput(value: unknown): AppleIdentityInput {
  const apple = object(value)
  return { apple_id: text(apple.apple_id), region: text(apple.region) }
}
function filterBody(value: AccountFilter | Record<string, unknown>): AccountFilter {
  const filter: AccountFilter = {}
  if (value.query !== undefined) filter.query = text(value.query)
  if (value.kind !== undefined) filter.kind = decodeAccountKind(value.kind)
  if (value.enabled !== undefined) filter.enabled = boolean(value.enabled)
  return filter
}
