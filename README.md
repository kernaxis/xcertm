# XCertM

XCertM is an MIT-licensed Go CLI for issuing, renewing, and deploying TLS
certificates with Let's Encrypt. It supports Cloudflare and OVH DNS-01,
including wildcard certificates and mixed apex/wildcard SANs.

Certificates can be deployed to several independent **local** destinations:
filesystem directories on Linux and certificate entries on Synology DSM.
Accounts, immutable generations, private keys, and recovery progress are stored
as private files. YAML is optional; there is no database or required daemon.
XCertM does not depend on Lego or a Synolego installation.

**Early development:** automated tests cover local ACME/provider servers and
simulated DSM layouts. Real Let's Encrypt/provider integration and actual NAS
compatibility have not yet been validated. Remote deployment and certificate
imports are not supported.

## Build

Use Go **1.26 or newer**, as required by the selected `golang.org/x/crypto`
release. `go.mod` selects Go 1.26.10 as the preferred build toolchain. No
additional build framework is needed.

```sh
go build ./cmd/xcertm
./xcertm --help
./xcertm --version
./xcertm version
```

Both version commands default to `xcertm version dev`. Release metadata can be
injected with `go build -ldflags '-X main.version=v0.1.0' ./cmd/xcertm`.
Commands exit with 0 on success and 1 on error, with a diagnostic on stderr.
Lifecycle progress also goes to stderr, keeping stdout available for the final
result or `--json`. Progress identifies ACME/DNS/deployment stages without
printing credentials, keys, or challenge values.

## First certificate without configuration

Supply a scoped Cloudflare token through `CLOUDFLARE_API_TOKEN` in the process
environment. Start with Let's Encrypt staging; its certificates are not publicly
trusted. The commands below use a private store owned by the executing user.

```sh
install -d -m 0700 "$HOME/.local/share/xcertm"
./xcertm issue --staging --state-dir "$HOME/.local/share/xcertm" \
  --certificate web --email admin@example.com --accept-tos \
  --dns cloudflare --zone example.com \
  --domain example.com --domain '*.example.com'

./xcertm list --state-dir "$HOME/.local/share/xcertm"
./xcertm show web --state-dir "$HOME/.local/share/xcertm"
```

Use domains you control. Omitting `--staging` selects production; staging and
production accounts and generations are distinguished in the same store.
Secrets can be referenced through environment variables or private files.
Cloudflare also accepts `api_token` directly in private YAML (mode `0600` or
`0400`); it is never copied into the persistent store or public inspection.
Literal secrets are not required as flag values.

## Configuration and deployment

Use the optional [example YAML](examples/xcertm.yaml) for named DNS providers,
certificates, and multiple destinations. Explicit flags override YAML values.

```sh
./xcertm issue --config xcertm.yaml --certificate web --deploy
./xcertm renew --config xcertm.yaml --all --deploy
./xcertm deploy --config xcertm.yaml --certificate web --destination web-local
```

`issue` reuses an existing valid generation with matching names. `renew` issues
when due (by default, the final third of its lifetime). `--force` explicitly
requests a fresh generation. `deploy` never issues a certificate. Without YAML,
later commands can reuse the last stored non-secret request for that certificate.

The default store is `/var/lib/xcertm` on Linux and `/usr/local/share/xcertm` on
DSM, overridden by YAML `state_dir` and then `--state-dir`. The store must be
private (`0700`) and owned by the executing user. Destination directories must
already exist. Filesystem deployment produces `privkey.pem` and `fullchain.pem`
without reloading a service. DSM deployment runs locally on the NAS with the
required privileges and uses existing DSM reload scripts.
With a DSM destination containing only `type: dsm`, XCertM creates a dedicated
entry and reuses its generated ID. `certificate_id` selects an existing entry;
`default: true` selects the current default. Automatic creation does not change
the default or assign services.

`list` and `show <id>` inspect stored certificates without DNS credentials or
network access; `--json` produces structured public metadata. They never expose
keys, activate services, or create a missing store.

See the [configuration and command reference](docs/architecture/configuration.md)
and [deployment and recovery](docs/architecture/deployment.md) before publishing
to an existing service. Back up the complete private store securely; recovery
depends on retained keys and journals. Do not remove pending state to bypass a
conflict.

## Development

```sh
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/xcertm
```

Tests use local HTTP servers, temporary certificates/files, subprocess crash
recovery, and simulated DSM scripts. They do not contact public services or
modify a real DSM store. Initial module downloads require network access.

GitHub Actions is configured for CI, scheduled security checks, CodeQL, and
draft releases for Linux amd64, 386, ARMv7 and ARM64. Releases run the checks
before packaging binaries, license notices and checksums. See
[CI and releases](docs/ci-cd.md) for manual release/tag behavior and local Make
targets.

See [architecture](docs/architecture/README.md) for component boundaries and
invariants. Complete dependency license texts, notices and redistribution
requirements are retained in [third-party notices](THIRD_PARTY_NOTICES.md).
