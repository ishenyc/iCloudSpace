#!/usr/bin/env python3
"""Prepare a new private installation. No database or service is started."""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import uuid


def private_write(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "wb") as output:
        output.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True, type=Path,
                        help="new absolute private directory outside this checkout")
    parser.add_argument("--project", default="icloudspace-" + secrets.token_hex(4),
                        help="unique lowercase Compose project name")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--imaps-port", type=int, default=1993)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    supplied = args.runtime_dir
    if not supplied.is_absolute() or supplied.is_symlink() or supplied.exists():
        parser.error("runtime-dir must be a new absolute directory; existing paths are never replaced")
    runtime = supplied.resolve()
    if runtime == repository or repository in runtime.parents:
        parser.error("runtime-dir must be outside the repository")
    if any(char in str(runtime) for char in "\x00\r\n'$\\"):
        parser.error("runtime-dir cannot contain quotes, dollar signs, backslashes or control characters")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", args.project):
        parser.error("project must be 1–63 lowercase letters, digits, underscores or hyphens")
    if not all(1024 <= value <= 65535 for value in (args.http_port, args.imaps_port)) or args.http_port == args.imaps_port:
        parser.error("choose distinct unprivileged ports between 1024 and 65535")
    openssl = shutil.which("openssl")
    if not openssl:
        parser.error("OpenSSL is required to generate the local IMAPS certificate")
    docker = shutil.which(os.environ.get("DOCKER", "docker"))
    if not docker:
        parser.error("Docker is required; set DOCKER to its executable path if needed")
    try:
        for resource in ("ps", "volume"):
            arguments = [docker, "ps", "-a"] if resource == "ps" else [docker, "volume", "ls"]
            result = subprocess.run(arguments + ["--filter", "label=com.docker.compose.project=" + args.project,
                                                 "--format", "{{.ID}}" if resource == "ps" else "{{.Name}}"],
                                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            if result.stdout.strip():
                parser.error("this Compose project already owns containers or volumes; choose a new project name")
        expected_volumes = {args.project + "_" + name for name in
                            ("database", "configuration", "content", "database-secrets")}
        for resource, expected in (("volume", expected_volumes),
                                   ("network", {args.project + "_default"})):
            result = subprocess.run([docker, resource, "ls", "--format", "{{.Name}}"],
                                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
            if expected.intersection(result.stdout.splitlines()):
                parser.error("an expected installation volume or network already exists; choose a new project name")
    except (OSError, subprocess.SubprocessError):
        parser.error("Docker must be running before preparing a new installation")
    if not runtime.parent.is_dir():
        parser.error("create the parent of runtime-dir first")
    previous_umask = os.umask(0o077)
    try:
        runtime.mkdir(mode=0o700)
        seed = runtime / "seed"
        seed.mkdir(mode=0o700)
        db_password = secrets.token_hex(32)
        private_write(seed / "postgres-password", db_password)
        private_write(seed / "database.dsn", "postgres://icloudspace:" + db_password + "@postgres:5432/icloudspace?sslmode=disable\n")
        private_write(seed / "master.key", secrets.token_bytes(32))
        private_write(seed / "admin-password", secrets.token_urlsafe(24))
        process = json.loads((repository / "deployment/process.example.json").read_text())
        process["installation_id"] = str(uuid.uuid4())
        private_write(seed / "process.json", json.dumps(process, indent=2) + "\n")
        install = json.loads((repository / "deployment/install.example.json").read_text())
        private_write(seed / "initialize.json", json.dumps(install, indent=2) + "\n")
        private_write(seed / "openssl.cnf", "[req]\ndistinguished_name=subject\nx509_extensions=extensions\nprompt=no\n[subject]\nCN=localhost\n[extensions]\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "365",
                        "-config", str(seed / "openssl.cnf"), "-keyout", str(seed / "tls.key"),
                        "-out", str(seed / "tls.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for name in ("tls.key", "tls.crt"):
            (seed / name).chmod(0o600)
        private_write(runtime / "deployment.env", "\n".join([
            "SPACE_PROJECT_NAME=" + args.project,
            "SPACE_RUNTIME_DIRECTORY='" + str(runtime) + "'",
            "SPACE_APP_IMAGE=icloudspace:" + args.project,
            "SPACE_HTTP_PORT=" + str(args.http_port),
            "SPACE_IMAPS_PORT=" + str(args.imaps_port), "",
        ]))
        private_write(runtime / "installation.json", json.dumps({
            "version": 1, "project": args.project, "installation_id": process["installation_id"],
            "http_port": args.http_port, "imaps_port": args.imaps_port,
            "initial_enable_operation": "initial-enable-" + str(uuid.uuid4()),
        }, indent=2) + "\n")
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Preparation failed. The partially created private directory was retained; inspect it before starting again with a new directory.", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)
    print("Prepared a private installation. No service has been started.")
    print("Compose project: " + args.project)
    print("Environment file: " + str(runtime / "deployment.env"))
    print("Administrator login: admin. Password is stored only in seed/admin-password.")
    print("Follow docs/installation.md to build, provision and initialize this installation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
