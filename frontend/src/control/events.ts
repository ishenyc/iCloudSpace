import { ControlClient, RequestConfigurationError } from '../transport/index.ts'
import type { ControlResult } from '../transport/index.ts'
import { ContractError } from './contracts.ts'
import { auditRecordsSearch, decodeAuditRecordsPage, decodeRuntimeEventsPage, runtimeEventsSearch } from './event-contracts.ts'
import type { AuditRecordsPage, AuditRecordsQuery, RuntimeEventsPage, RuntimeEventsQuery } from './event-contracts.ts'

function input<T>(read: () => T): T {
  try { return read() } catch { throw new RequestConfigurationError('invalid_events_input', { outcome: 'not_sent' }) }
}

/** One explicit session-authenticated read per call. Stream namespaces and live
 * generations remain caller-visible; no retry, polling or SSE is started. */
export class EventsModel {
  private readonly client: ControlClient
  constructor(client: ControlClient) { this.client = client }

  runtime(query: RuntimeEventsQuery = {}, signal?: AbortSignal): Promise<ControlResult<RuntimeEventsPage>> {
    const search = input(() => runtimeEventsSearch(query))
    return this.client.json('/runtime-events', { search: { ...search }, signal,
      resource: search.source_id === undefined ? undefined : { kind: 'account', id: search.source_id }, decodeResult: (value) => {
        const decoded = decodeRuntimeEventsPage(value)
        if (decoded.stream !== search.stream || decoded.limit !== search.limit || decoded.before_id !== (search.before_id ?? null) || decoded.after_id !== (search.after_id ?? null) ||
          decoded.items.some((item) => search.source_id !== undefined && item.source_id !== search.source_id || search.level !== undefined && item.level !== search.level ||
            search.round_key !== undefined && item.round_key !== search.round_key)) throw new ContractError('event_scope')
        return decoded
      } })
  }
  audits(query: AuditRecordsQuery = {}, signal?: AbortSignal): Promise<ControlResult<AuditRecordsPage>> {
    const search = input(() => auditRecordsSearch(query))
    return this.client.json('/audit-records', { search: { ...search }, signal,
      resource: search.source_id === undefined ? undefined : { kind: 'account', id: search.source_id }, decodeResult: (value) => {
        const decoded = decodeAuditRecordsPage(value)
        if (decoded.page !== search.page || decoded.page_size !== search.page_size || decoded.items.some((item) =>
          search.source_id !== undefined && item.source_id !== search.source_id || search.action !== undefined && item.action !== search.action ||
          search.outcome !== undefined && item.outcome !== search.outcome)) throw new ContractError('audit_scope')
        return decoded
      } })
  }
}
