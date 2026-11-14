import { AccountsModel } from './accounts.ts'
import { AddressesModel } from './addresses.ts'
import { CreationModel } from './creation.ts'
import { CredentialExportsModel } from './credential-exports.ts'
import { CredentialsModel } from './credentials.ts'
import { EventsModel } from './events.ts'
import { HMEModel } from './hme.ts'
import { MailoutModel } from './mailout.ts'
import { LocalCleanupModel } from './local-cleanup.ts'
import { ProviderSessionsModel } from './provider-sessions.ts'
import { SessionModel } from './session.ts'
import { SynchronizationModel } from './synchronization.ts'
import { ManagementMailClient } from '../mail/management-client.ts'
import type { SessionModelOptions } from './session.ts'

/** One installation and one session own every management request. */
export function createControl(options: SessionModelOptions) {
  const sessionModel = new SessionModel(options)
  const client = sessionModel.client
  return Object.freeze({
    basePath: options.basePath,
    sessionModel,
    accounts: new AccountsModel(client),
    addresses: new AddressesModel(client),
    credentials: new CredentialsModel(client, { sessionRevision: () => sessionModel.generation, onSessionRevoked: revision => { sessionModel.invalidate(revision) } }),
    credentialExports: new CredentialExportsModel(client),
    hme: new HMEModel(client),
    providerSessions: new ProviderSessionsModel(client),
    creation: new CreationModel(client),
    synchronization: new SynchronizationModel(client),
    events: new EventsModel(client),
    mailout: new MailoutModel(client),
    localCleanup: new LocalCleanupModel(client),
    mail: new ManagementMailClient(client),
  })
}

export type ControlServices = ReturnType<typeof createControl>
