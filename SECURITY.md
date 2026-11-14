# Security policy

Security fixes target the latest published release. Upgrade after reviewing its release notes and taking a matched backup of the database, content store and encryption key.

## Reporting a vulnerability

Use **Security → Report a vulnerability** on this repository when private reporting is available. Do not put credentials, cookies, mailbox contents, real account addresses or exploit details in a public issue. If private reporting is unavailable, open an issue titled “Private security contact requested” without sensitive details so the maintainer can arrange a private channel.

Include the affected release, a minimal description, impact and reproduction steps using invented data. Keep the report private while a fix is being prepared.

## Deployment responsibilities

- Run the administration UI over HTTPS outside localhost and keep the service behind an appropriate firewall or reverse proxy.
- Keep runtime files outside the checkout. Database connection files, the 32-byte master key, application passwords, sessions and backups are private.
- Back up the database, content directory and master key together. Losing the key can make encrypted data unrecoverable.
- Treat mailbox links and mailbox credentials as access-bearing secrets. Avoid recording query strings in proxy access logs.
- The legacy `recent` endpoint consumes mail on an explicit GET. Do not prefetch or automatically retry that request.
- If a send result is `unknown`, query the original operation. Repeating a submission may send the message twice.

iCloudSpace is an independent project. Changes to upstream services can affect authentication, synchronization and delivery.
