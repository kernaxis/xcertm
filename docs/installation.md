# Installation and updates

XCertM distributes static Linux binaries for amd64, 386, ARMv7 and ARM64 through
[GitHub releases](https://github.com/kernaxis/xcertm/releases). Synology DSM uses
the corresponding Linux binary; the DS1522+ uses amd64. ARMv5/ARMv6, macOS and
Windows are not supported by the installer or self-updater.

## System installation

On Linux or DSM, run:

```sh
curl -fsSL https://raw.githubusercontent.com/kernaxis/xcertm/main/install.sh | sudo sh
/usr/local/bin/xcertm --version
```

The script detects Linux/DSM and the CPU architecture, selects the latest stable
release, downloads its archive and `SHA256SUMS`, verifies the archive, then checks
the binary's version before installing it. It never invokes `sudo` itself.
It requires a POSIX shell, curl with HTTPS support, tar with `-O` support,
sha256sum, mktemp, GNU/BusyBox-compatible `stat -c`, and standard shell utilities.
It requires neither Go, Python nor jq. Missing tools produce an error.

Installation defaults to `/usr/local/bin/xcertm` when run as root. The script
refuses to overwrite an existing binary or symlink; use `xcertm update` for an
existing installation. It rejects unsafe installation paths and unsupported
architectures before publishing a binary.

License, third-party notices and the dependency inventory are retained under
`/usr/local/share/doc/xcertm/<version>`. This is separate from DSM's persistent
certificate store at `/usr/local/share/xcertm`. Installation does not create a
configuration, certificate store, scheduled task or service.

For an inspected local copy of the script:

```sh
curl -fsSL https://raw.githubusercontent.com/kernaxis/xcertm/main/install.sh -o install.sh
# Inspect install.sh before executing it.
sudo sh ./install.sh
```

## User installation and explicit versions

Without root, the default destination is `$HOME/.local/bin/xcertm`. Add that
directory to `PATH` if necessary:

```sh
curl -fsSL https://raw.githubusercontent.com/kernaxis/xcertm/main/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

To install a particular stable release or choose an absolute binary directory:

```sh
curl -fsSL https://raw.githubusercontent.com/kernaxis/xcertm/main/install.sh |
  sudo sh -s -- --version v0.1.0 --bin-dir /opt/xcertm/bin
```

For any binary directory `<prefix>/bin`, notices are stored in
`<prefix>/share/doc/xcertm/<version>`. More generally, `share/doc/xcertm` is placed
under the binary directory's parent. Neither installation nor update silently
follows symlinks in documentation paths.

Installing as a user does not grant deployment privileges. DSM deployment
requires root. Linux filesystem deployment can run as a user with sufficient
permissions on both the chosen store and destination.

## Update an installed binary

```sh
sudo xcertm update
```

The command checks the latest published stable GitHub release. When a newer
version is available, it displays both versions and the resolved executable path:

```text
This will install xcertm v0.2.0 over v0.1.0.
Binary: /usr/local/bin/xcertm
Continue? [y/N]
```

Only `y` or `yes` confirms installation; an empty answer or refusal cancels with
exit code 0. Confirmation is read from the controlling terminal, never piped
stdin. Without a terminal, installation requires `--yes`. The command never
automatically escalates privileges.

```sh
xcertm update --check
sudo xcertm update --yes
```

`--check` does not create files or acquire an installation lock; it exits 0 when
the check succeeds, whether or not an update is available. It cannot be combined
with `--yes`. A matching version prints `You are up to date (vX.Y.Z).` A version
newer than the stable release is left installed. Development/unrecognized builds
are explicitly identified before an optional replacement. An rc build can update
to a later stable version, but the updater never selects an rc release.

Updates replace the executable actually running, resolving symlinks rather than
searching `PATH`. The binary must be owned by the executing user and must not be
group/world writable. For a system installation, run the command with `sudo`.
The updater preserves the binary's owner, group and ordinary permission bits.
HTTP/download/verification/installation failures exit 1 with a diagnostic.

## Integrity and recovery

Both paths use normal HTTPS certificate verification, require a matching
SHA-256 checksum from the same release, and verify the staged binary's reported
version. The Go updater also bounds downloads and decompression. Network
requests have explicit timeouts. Checksums detect damaged or inconsistent
downloads; they are not an independent signature. Trust rests on GitHub, the
repository's release maintainers and the machine's TLS trust store.

The replacement is staged beside the binary and published with a single rename
on the same filesystem. The updater serializes updates with an advisory lock;
the lock file remains, but the operating system releases the lock on process
exit. The installer uses a temporary directory lock. Ordinary exits clean up
staging; a forced kill or power loss can leave temporary files. Inspect an
installer lock before removing it and retrying. An installation directory
mounted `noexec` cannot run the staged binary and is rejected by the version check.

The old binary remains in place until replacement. Configuration, keys,
generations and recovery journals are never migrated or deleted. Versioned
license directories can remain after an interrupted update. There is no
transaction across binary and documentation and no automatic rollback after
replacement. Already running processes continue using their existing executable.
If the updater reports that rename succeeded but directory sync failed, check
`xcertm --version` before retrying.

Updates require outbound HTTPS to GitHub's API and release/download hosts, plus
the download hosts reached through GitHub redirects. A missing stable release,
draft-only repository, API rate limit or blocked download is reported as an error.
Release workflows create drafts; a maintainer must publish a stable release for
automatic discovery. See [release documentation](ci-cd.md).
