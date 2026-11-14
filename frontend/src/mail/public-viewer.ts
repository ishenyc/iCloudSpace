import { decodeIdentifier } from '../control/contracts.ts'
import { HttpError, RequestConfigurationError } from '../transport/errors.ts'
import type { FetchImplementation } from '../transport/types.ts'
import { PublicMailClient } from './public-client.ts'
import type { MailDownload, MailMessage, MailPage, MailPageQuery } from './contracts.ts'

export interface PublicViewerBootstrap { version: 1; address_id: string; public_mail_path: '/api/mail/v1' }
export function decodePublicViewerBootstrap(value: unknown): PublicViewerBootstrap {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new RequestConfigurationError('public_viewer_configuration')
  const input = value as Record<string, unknown>
  if (Object.keys(input).sort().join(',') !== 'address_id,public_mail_path,version' || input.version !== 1 || input.public_mail_path !== '/api/mail/v1') throw new RequestConfigurationError('public_viewer_configuration')
  try { return { version: 1, address_id: decodeIdentifier(input.address_id), public_mail_path: '/api/mail/v1' } }
  catch { throw new RequestConfigurationError('public_viewer_configuration') }
}

/** Fragment is erased even when configuration or credentials are invalid.
 * No credential is returned as ordinary bootstrap data or retained in a URL. */
export function openPublicViewer(rawBootstrap: string, location: Pick<Location, 'pathname' | 'search' | 'hash'>,
  history: Pick<History, 'replaceState'>, fetch?: FetchImplementation): PublicViewerModel {
  const fragment = location.hash
  try { history.replaceState(null, '', location.pathname + location.search) }
  catch { throw new RequestConfigurationError('public_viewer_fragment_cleanup') }
  let bootstrap: PublicViewerBootstrap, token: string
  try {
    bootstrap = decodePublicViewerBootstrap(JSON.parse(rawBootstrap))
    if (location.search !== '' || location.pathname !== '/viewer/addresses/' + bootstrap.address_id || !fragment.startsWith('#access_token=')) throw new Error()
    const encoded = fragment.slice('#access_token='.length)
    if (encoded.includes('&') || /%(?![0-9a-f]{2})/i.test(encoded)) throw new Error()
    token = decodeURIComponent(encoded.replace(/\+/g, ' '))
    if (!/^[\x21-\x7e]{1,4096}$/.test(token)) throw new Error()
  } catch { throw new RequestConfigurationError('public_viewer_access_unavailable') }
  return new PublicViewerModel(bootstrap.address_id, token, fetch)
}

export interface PublicViewerSelection { message: MailMessage | null; unavailable: number[] }

/** The viewer exposes only raw_read operations. Its client and credential stay
 * private; there is no derive/consume/refresh/Seen or management-session port. */
export class PublicViewerModel {
  readonly addressID: string
  #client: PublicMailClient
  constructor(addressID: string, token: string, fetch?: FetchImplementation) {
    this.addressID = decodeIdentifier(addressID)
    this.#client = new PublicMailClient({ credential: { scheme: 'Bearer', token }, fetch })
  }
  toJSON(): { address_id: string } { return { address_id: this.addressID } }
  async candidates(page: MailPageQuery = {}, signal?: AbortSignal): Promise<MailPage> {
    return (await this.#client.rawCandidates(this.addressID, { ...page, limit: 20 }, signal)).result
  }
  async message(uid: number, signal?: AbortSignal): Promise<MailMessage> { return (await this.#client.rawMessage(this.addressID, uid, signal)).result }
  raw(uid: number, signal?: AbortSignal): Promise<MailDownload> { return this.#client.raw(this.addressID, uid, { signal }) }
  attachment(uid: number, part: string, signal?: AbortSignal): Promise<MailDownload> { return this.#client.attachment(this.addressID, uid, part, signal) }
  async latest(page: MailPage, signal?: AbortSignal): Promise<PublicViewerSelection> {
    // One explicit metadata page is the admission budget. A page with no valid
    // body and more=true offers an explicit earlier-page action, never a false
    // global empty conclusion or an unbounded background traversal.
    if (page.items.length > 20) throw new RequestConfigurationError('public_viewer_candidate_budget')
    const unavailable: number[] = []
    for (const item of page.items) {
      if (item.uid === null) continue
      if (item.raw_state !== 'available') { unavailable.push(item.uid); continue }
      try { return { message: await this.message(item.uid, signal), unavailable } }
      catch (error) {
        if (!(error instanceof HttpError) || !((error.status === 404 && error.code === 'MAIL_NOT_FOUND') || (error.status === 410 && error.code === 'MAIL_ORIGINAL_UNAVAILABLE') || (error.status === 422 && error.code === 'MAIL_CONTENT_UNAVAILABLE'))) throw error
        unavailable.push(item.uid)
      }
    }
    return { message: null, unavailable }
  }
}
