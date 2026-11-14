#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RELEASE_TAG:?set a vMAJOR.MINOR.PATCH release tag}"
: "${TARGET_ARCH:?set amd64 or arm64}"
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
[[ "$TARGET_ARCH" == amd64 || "$TARGET_ARCH" == arm64 ]] || exit 2
[[ "$RELEASE_TAG" == "v$(cat VERSION)" ]] || { printf '%s\n' 'Release tag must match VERSION.' >&2; exit 2; }
python3 scripts/check-public-tree.py
release_name="icloudspace-${RELEASE_TAG}-linux-${TARGET_ARCH}"
stage_dir=$(mktemp -d)
trap 'rm -rf "$stage_dir"' EXIT
mkdir -p "$stage_dir/$release_name/bin" release
for command in icloudspace icloudspace-install icloudspace-operator icloudspace-health icloudspace-smtp-egress; do
  (cd backend && CGO_ENABLED=0 GOOS=linux GOARCH="$TARGET_ARCH" go build -trimpath -buildvcs=false -ldflags='-s -w' -o "$stage_dir/$release_name/bin/$command" "./cmd/$command")
done
cp -R frontend/dist "$stage_dir/$release_name/web"
cp LICENSE THIRD_PARTY_NOTICES.md "$stage_dir/$release_name/"
cat > "$stage_dir/$release_name/README.txt" <<EOF
iCloudSpace $RELEASE_TAG — Linux $TARGET_ARCH binary bundle

This archive contains the application, offline administration commands
and web assets. It does not contain a configured installation,
Docker build sources, database, certificates or runtime secrets.

For the supported Docker installation, download the SOURCE CODE at the same
release tag from the repository and follow its README and installation guide.
Do not run the source-install commands from this binary bundle.

Binary operators must supply a private process configuration, initialized
PostgreSQL database, content directory, master key and valid IMAPS certificate.
The server never creates or upgrades an installation implicitly.

Keep bin/ and web/ from the same release. Frontend licenses are in
web/assets/third-party-licenses.txt; Go and component notices are included here.
EOF
python3 - "$stage_dir" "$release_name" <<'PY'
import gzip
import os
from pathlib import Path
import tarfile
import tempfile
import sys

stage, name = Path(sys.argv[1]), sys.argv[2]
epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
if epoch < 0 or epoch > 4294967295:
    raise ValueError('SOURCE_DATE_EPOCH must fit an unsigned 32-bit timestamp')
destination = Path('release') / (name + '.tar.gz')

def normalize(member):
    if any(part == '.DS_Store' or part.startswith('._') for part in Path(member.name).parts):
        return None
    if not (member.isfile() or member.isdir()):
        raise ValueError('Release bundles may contain only regular files and directories')
    member.uid = member.gid = 0
    member.uname = member.gname = 'root'
    member.mtime = epoch
    member.pax_headers = {}
    member.mode = 0o755 if member.isdir() or '/bin/' in member.name else 0o644
    return member

temporary = None
try:
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='bundle-', delete=False) as raw:
        temporary = Path(raw.name)
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                archive.add(stage / name, arcname=name, filter=normalize)
    os.replace(temporary, destination)
finally:
    if temporary is not None:
        temporary.unlink(missing_ok=True)
PY
(cd release && shasum -a 256 "$release_name.tar.gz" > "$release_name.sha256")
