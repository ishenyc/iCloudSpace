# Contributing

Bug reports and focused pull requests are welcome. Use invented addresses and remove credentials, cookies and mail contents from examples. Describe the observed result, expected result and affected release.

## Build checks

Use the Node version in `.nvmrc`, the Go version declared in `backend/go.mod`, and Docker Compose v2 for container builds.

```sh
npm --prefix frontend ci
npm --prefix frontend run check
npm --prefix frontend run build
(cd backend && go vet ./... && go build ./...)
python3 scripts/check-public-tree.py
docker build --target application -t icloudspace:check .
```

For UI development, point `ICLOUDSPACE_API_TARGET` at an installation you control. The default is `http://127.0.0.1:8080`. Development requests can change that installation; use a separate instance with disposable accounts.

## Pull requests

Keep changes focused, describe compatibility or data-migration effects, and include the checks you ran. Changes to mail submission, credential rotation and consumption must preserve operation identifiers and explicit unknown outcomes. Append schema migrations; do not edit migrations already distributed in a release.

Do not commit runtime configuration, database files, local investigation notes, test datasets or account exports. Keep required third-party notices intact. Contributions are provided under the project's MIT license.

When adding or removing a public file, review the publication boundary and update `scripts/public-files.json`. When changing dependencies, update the corresponding third-party license notices as part of the same pull request.

## Releases

CI validates builds and the public file boundary. Dependency update pull requests are reviewed before merging. The first public release is 1.5.0. Release tags use `vMAJOR.MINOR.PATCH` and must match `VERSION` and the frontend package version; the release workflow builds versioned Linux archives and checksums from that tag. Breaking configuration or API changes require a major version and upgrade instructions. Include user-visible changes and migration requirements in the release notes.

An archive contains the application, administration commands and web assets. It does not contain a database or runtime secrets. Follow the [upgrade guide](docs/upgrading.md) when replacing a running installation.
