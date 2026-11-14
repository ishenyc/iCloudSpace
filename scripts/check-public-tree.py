#!/usr/bin/env python3
"""Check the reviewed publication boundary without printing file contents."""
import json
import pathlib
import re
import subprocess
import sys
import struct
import zlib

root = pathlib.Path(__file__).resolve().parents[1]
allowed = set(json.loads((root / 'scripts/public-files.json').read_text()))
generated = {'node_modules', 'dist', '.git', '.cache', '__pycache__', 'release', 'bin'}
if (root / '.git').exists():
    result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root, check=True, capture_output=True)
    paths = set(result.stdout.decode().split('\0')) - {''}
else:
    paths = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and not any(x in generated for x in p.relative_to(root).parts) and not p.name.endswith(('.tsbuildinfo', '.pyc'))}
errors = []
dimensions = {}
for name in sorted(paths):
    path = root / name
    if name not in allowed:
        errors.append(name + ': not in reviewed public file list')
        continue
    if path.is_symlink():
        errors.append(name + ': symlink')
        continue
    if path.suffix == '.png':
        raw = path.read_bytes()
        offset, chunks = 8, []
        try:
            if raw[:8] != b'\x89PNG\r\n\x1a\n':
                raise ValueError('signature')
            while offset < len(raw):
                length = struct.unpack('>I', raw[offset:offset + 4])[0]
                kind = raw[offset + 4:offset + 8]
                payload = raw[offset + 8:offset + 8 + length]
                checksum = struct.unpack('>I', raw[offset + 8 + length:offset + 12 + length])[0]
                if len(payload) != length or zlib.crc32(kind + payload) & 0xffffffff != checksum:
                    raise ValueError('checksum')
                if kind not in {b'IHDR', b'PLTE', b'IDAT', b'IEND', b'tRNS'}:
                    raise ValueError('unreviewed image metadata')
                chunks.append(kind)
                if kind == b'IHDR':
                    dimensions[name] = struct.unpack('>II', payload[:8])
                offset += 12 + length
                if kind == b'IEND':
                    break
            if offset != len(raw) or chunks[0] != b'IHDR' or chunks[-1] != b'IEND' or b'IDAT' not in chunks:
                raise ValueError('structure')
        except (ValueError, IndexError, struct.error):
            errors.append(name + ': invalid PNG or unreviewed metadata')
        continue
    try:
        content = path.read_text()
    except (UnicodeError, OSError):
        errors.append(name + ': unreadable text')
        continue
    checks = {
        'host home path': r'/' + r'Users/|/' + r'home/[^ /]+/',
        'private key': r'-----BEGIN ' + r'(?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'access token': r'gh[pousr]_' + r'[A-Za-z0-9]{30,}|github_pat_' + r'[A-Za-z0-9_]{40,}',
        'database credential': r'postgres(?:ql)?://' + r'[^\s/:]+:[^\s$<{]+@',
        'internal version narrative': r'\b(?:second|third)[ -]' + r'version\b|[第][二三][版]',
        'historical source annotation': r'//\s*Source:\s*iCloudSpace\s+' + r'[0-9a-f]{7,40}\b',
    }
    for label, pattern in checks.items():
        if re.search(pattern, content):
            errors.append(name + ': ' + label)
for name in sorted(allowed - paths):
    errors.append(name + ': missing reviewed file')
for name, size in dimensions.items():
    if name.endswith('-dark.png') and dimensions.get(name[:-9] + '-light.png') != size:
        errors.append(name + ': theme image dimensions do not match')
try:
    version = (root / 'VERSION').read_text().strip()
    package = json.loads((root / 'frontend/package.json').read_text())
    lock = json.loads((root / 'frontend/package-lock.json').read_text())
    app = (root / 'frontend/src/lib/version.ts').read_text().strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) or any(value != version for value in [package['version'], lock['version'], lock['packages']['']['version']]) or app != "export const APP_VERSION = '" + version + "'":
        errors.append('Public version declarations do not match VERSION.')
    if package.get('author') != 'iShenyc' or package.get('license') != 'MIT':
        errors.append('Public package identity or license is incorrect.')
except (OSError, KeyError, ValueError):
    errors.append('Public version or package identity could not be verified.')
if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print(f'Public file boundary passed: {len(paths)} files.')
