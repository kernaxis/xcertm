# Building and contributing

XCertM is a Go project with one module and one CLI binary. Use the preferred
toolchain declared in [go.mod](../go.mod), currently **Go 1.26.11**. The selected
`golang.org/x/crypto` release requires Go 1.26 or newer. Initial dependency and
toolchain downloads need network access.

## Build from source

Run these commands from the repository root:

```sh
go build -o xcertm ./cmd/xcertm
./xcertm --help
./xcertm --version
./xcertm version
```

Local builds report `xcertm version dev` unless you inject a version:

```sh
go build -ldflags '-X main.version=v0.1.1' -o xcertm ./cmd/xcertm
```

No additional build framework is required. To install a published binary instead,
use the [installation guide](installation.md).

## Checks

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/xcertm
```

Tests use local HTTP servers, temporary certificates/files, subprocess crash
recovery, release fixtures and simulated DSM scripts. They do not contact public
ACME/DNS services or modify a real DSM store. Race tests require CGO and a
supported native toolchain. The installer is exercised by Go tests with local
release fixtures; it can also be checked with `sh -n install.sh` and ShellCheck.

The Makefile provides equivalent convenience targets plus linting and packaging.
See [CI and releases](ci-cd.md) for pinned tools, `make ci`, security scans,
cross-compilation and draft release preparation. Distributable builds belong to
the Release workflow; ordinary CI has no separate binary packaging job.

## Architecture and command behavior

- [Components and invariants](architecture/README.md)
- [Configuration and command reference](architecture/configuration.md)
- [Deployment and recovery](architecture/deployment.md)
- [Installer and updater](installation.md)

Commands exit with 0 on success and 1 on error. Lifecycle progress and diagnostics
go to stderr; stdout is reserved for the final result or `--json` output. Logs
must not expose credentials, private keys or DNS proof values.

Dependencies compiled into a release must remain compatible with MIT
distribution and retain their license/notice requirements. See
[third-party notices](../THIRD_PARTY_NOTICES.md) and the license packaging section
of the [release guide](ci-cd.md#binary-archives).
