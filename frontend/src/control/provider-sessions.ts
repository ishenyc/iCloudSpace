import { ControlClient, ControlError, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError, decodeIdentifier } from './contracts.ts'
import { decodeProviderAuthResult, decodeProviderSessionStatus, providerAction, providerChallengeToken, providerChoice, providerObject, providerRequestKey, providerText } from './provider-session-contracts.ts'
import type { ProviderAction, ProviderActionInput, ProviderAuthResult, ProviderLogin, ProviderQuery, ProviderRequest, ProviderRestore, ProviderSessionStatus } from './provider-session-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_provider_input', { outcome: 'not_sent' }) }
}
function code(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{6}$/.test(value)) throw new ContractError('provider_code')
  return value
}
function loginPassword(value: unknown): string {
  const password = providerText(value, 4096, true)
  for (let index = 0; index < password.length; index++) {
    const unit = password.charCodeAt(index)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = password.charCodeAt(++index)
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new ContractError('provider_password')
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new ContractError('provider_password')
  }
  return password
}
function result(value: unknown, source: string, key: string, action: ProviderAction, token?: string): ProviderAuthResult {
  const decoded = decodeProviderAuthResult(value)
  if (decoded.request_key !== key || decoded.receipt === null || decoded.receipt.action !== action || decoded.session === null || decoded.session.source_id !== source || token !== undefined && decoded.challenge_token !== token) throw new ContractError('provider_request_scope')
  return decoded
}
function exactJSON(document: unknown): Record<string, unknown> {
  const value = { ...providerObject(document) }
  if (value.version !== 1) throw new ContractError('provider_document')
  // Restore never trusts a previous validation claim. Raw document strings use
  // the server's lossless reader instead of any JS numeric round trip.
  delete value.validated_at_unix_nano
  const text = JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item === 'number' && !Number.isSafeInteger(item)) throw new ContractError('provider_document_precision')
    return item
  })
  if (new TextEncoder().encode(text).byteLength > 1 << 20) throw new ContractError('provider_document')
  return JSON.parse(text) as Record<string, unknown>
}

/** Stateless protocol calls. Passwords, codes, capsules and challenge tokens
 * remain caller-owned ephemeral values; no storage, logging or retry exists. */
export class ProviderSessionsModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  status(sourceID: string, signal?: AbortSignal): Promise<ControlResult<ProviderSessionStatus>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    return this.client.json(this.base(sourceID), { signal, resource: { kind: 'account', id: sourceID }, decodeResult: (value) => {
      const decoded = decodeProviderSessionStatus(value)
      if (decoded.source_id !== sourceID) throw new ContractError('provider_source')
      return decoded
    } })
  }
  async login(sourceID: string, value: ProviderLogin, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => ({ request_key: providerRequestKey(value.request_key, true), password: loginPassword(value.password) }))
    try { return await this.write(sourceID, 'login', body, 'login', signal) } finally { body.password = '' }
  }
  async action(sourceID: string, value: ProviderActionInput, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => {
      const data = providerObject(value)
      const action = providerChoice(data.action, ['load_challenge', 'send_device_code', 'verify_device_code', 'send_sms', 'verify_sms', 'verify_security_key', 'trust_browser', 'decline_trust', 'exchange_token', 'validate_session'] as const)
      const request: Record<string, unknown> & { request_key: string; challenge_token: string } = { request_key: providerRequestKey(data.request_key, true), challenge_token: providerChallengeToken(data.challenge_token), action }
      if (action === 'trust_browser') {
        if (data.confirm_browser_trust !== true) throw new ContractError('provider_trust_choice')
        request.confirm_browser_trust = true
      }
      if (action === 'verify_device_code' || action === 'verify_sms') request.code = code(data.code)
      if (action === 'send_sms' || action === 'verify_sms') { request.phone_id = providerText(data.phone_id, 64, true); request.mode = providerChoice(data.mode, ['sms', 'voice'] as const) }
      if (action === 'verify_security_key') {
        const assertion = providerObject(data.assertion)
        request.assertion = { challenge_id: providerText(assertion.challenge_id, 64, true), credential_id: providerText(assertion.credential_id, 4096, true),
          client_data_json: providerText(assertion.client_data_json, 32768, true), authenticator_data: providerText(assertion.authenticator_data, 16384, true),
          signature: providerText(assertion.signature, 16384, true), ...(assertion.user_handle === undefined ? {} : { user_handle: providerText(assertion.user_handle, 128) }) }
      }
      return request
    })
    const expectedAction = body.action as ProviderAction, token = body.challenge_token
    try { return await this.write(sourceID, 'actions', body, expectedAction, signal, token) } finally { delete body.code; delete body.assertion; body.challenge_token = '' }
  }
  query(sourceID: string, value: ProviderQuery, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const query = input(() => ({ request_key: providerRequestKey(value.request_key), action: providerAction(value.action), challenge_token: value.challenge_token === undefined ? undefined : providerChallengeToken(value.challenge_token) }))
    // POST is the explicit local receipt read. Old keys remain body data and do
    // not acquire the narrower new-mutation transport-key restriction.
    return this.client.json(this.base(sourceID) + '/query', { method: 'POST', body: { request_key: query.request_key, ...(query.challenge_token === undefined ? {} : { challenge_token: query.challenge_token }) }, signal,
      resource: { kind: 'account', id: sourceID }, decodeResult: (value) => result(value, sourceID, query.request_key, query.action, query.challenge_token) })
  }
  async restore(sourceID: string, value: ProviderRestore, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const body = input(() => {
      if (Object.hasOwn(providerObject(value), 'document_json')) throw new ContractError('provider_document')
      const request_key = providerRequestKey(value.request_key, true)
      return typeof value.document === 'string' ? { request_key, document_json: providerText(value.document, 1 << 20, true) } : { request_key, document: exactJSON(value.document) }
    })
    try { return await this.write(sourceID, 'restore', body, 'restore_session', signal) } finally { if ('document' in body) body.document = {}; if ('document_json' in body) body.document_json = '' }
  }
  validate(sourceID: string, value: ProviderRequest, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    return this.local(sourceID, 'validate', value, 'validate_session', signal)
  }
  clear(sourceID: string, value: ProviderRequest, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    return this.local(sourceID, 'clear', value, 'clear_authentication', signal)
  }
  async queryUnknown(error: unknown, sourceID: string, value: ProviderQuery, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult> | undefined> {
    sourceID = input(() => decodeIdentifier(sourceID))
    const key = input(() => providerRequestKey(value.request_key))
    if (!(error instanceof ControlError) || error.outcome !== 'unknown' || error.resource?.kind !== 'account' || error.resource.id !== sourceID ||
      error.requestKey !== key && error.submissionKey !== key || error.requestKey !== undefined && error.requestKey !== key || error.submissionKey !== undefined && error.submissionKey !== key) return undefined
    return this.query(sourceID, value, signal)
  }
  private base(source: string): string { return '/accounts/' + source + '/provider-session' }
  private local(source: string, path: string, value: ProviderRequest, action: ProviderAction, signal?: AbortSignal): Promise<ControlResult<ProviderAuthResult>> {
    source = input(() => decodeIdentifier(source))
    return this.write(source, path, input(() => ({ request_key: providerRequestKey(value.request_key, true) })), action, signal)
  }
  private write(source: string, path: string, body: { request_key: string }, action: ProviderAction, signal?: AbortSignal, token?: string): Promise<ControlResult<ProviderAuthResult>> {
    const key = body.request_key
    return this.client.json(this.base(source) + '/' + path, { method: 'POST', body, signal, requestKey: key, resource: { kind: 'account', id: source }, decodeResult: (value) => result(value, source, key, action, token) })
  }
}
