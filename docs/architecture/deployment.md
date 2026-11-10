# Local deployment and recovery

The internal deployment API consumes an already validated `domain.Generation`.
It does not issue certificates, contact ACME/DNS, import user certificates, or
revalidate current lifetime, authority trust, or the desired DNS names. The
lifecycle application owns issuance/renewal policy. The CLI exposes these adapters
through `deploy` and the `issue`/`renew --deploy` option; see the
[command reference](configuration.md).

## Components and API

- `deploy.Session` coordinates one destination and holds its locks until `Close`.
- `filesystem.Open` and `dsm.Open` provide concrete plans and plan validation.
- `state` handles atomic writes, synchronization, snapshots, locks, private
  journals, and replay. It calls back for semantic validation and activation;
  it has no platform-specific knowledge or dependency on either adapter.

Given a generation produced by the application, the filesystem API is:

```go
session, err := filesystem.Open(stateRoot, filesystem.Config{
    DestinationID: "web-server",
    Directory: "/etc/example/tls",
})
if err != nil {
    return err
}
defer session.Close()
result, err := session.Deploy(ctx, operationID, generation)
```

For DSM, omit both selectors to create and retain a dedicated entry:

```go
session, err := dsm.Open(stateRoot, dsm.Config{
    DestinationID: "nas-main",
})
```

Alternatively select an existing certificate ID or `UseDefault`, exclusively:

```go
session, err := dsm.Open(stateRoot, dsm.Config{
    DestinationID: "nas-main",
    UseDefault: true,
})
```

`Deploy` requires a non-blank operation ID. Retrying the same operation and
generation reconciles the recorded operation; reusing its ID with different
material is rejected. A different pending operation must be recovered first.
`session.Recover(ctx)` needs no generation argument: it uses durable staged
material, not new flags or certificate input. It also verifies an already
completed receipt without repeating service activation. No journal yields an
empty result. A successful result identifies operation, destination, managed
certificate, and generation; `Completed` is true only after successful completion
verification. Errors preserve the latest receipt or pending operation.

One session is used serially. Separate destinations can have independent results
and sessions; resources that overlap are serialized. There is no transaction
across destinations. A failed deployment never requests a new certificate.

## Filesystem target

The destination directory must already exist. Output defaults are `privkey.pem`
(unencrypted PKCS#8 PEM) and `fullchain.pem` (leaf followed by the supplied chain).
Names can be configured as distinct direct child filenames; reserved `.xcertm*`
names and path traversal are rejected. New files have mode `0600` and the
executing user's UID/GID. A first deployment refuses existing managed output
files; an adoption/overwrite workflow is not implemented. Unrelated files are
left untouched. Subsequent deployments require the previous observed contents
and metadata to remain unchanged. There is no service activation.

## DSM target

The default local root is `/`; `Config.Root` permits a mounted/test layout.
The process needs permission to update the store, preserve file ownership, and
execute DSM reload profiles; this normally requires root on the NAS.
The archive is `usr/syno/etc/certificate/_archive`. Explicit IDs must already
exist in `INFO` and have a directory. `UseDefault` resolves `DEFAULT`
when starting a new operation. The concrete ID and configuration snapshots are
pinned for its recovery. A changed `DEFAULT` cannot redirect pending work.

With neither selector, the adapter initializes an automatically managed entry
under the session's archive/destination locks before read-only file planning.
Like `mktemp -d _archive/XXXXXX`, it reserves a private directory with an exclusive
mkdir and six random alphanumeric characters. It uses Go's cryptographic random
source and filesystem calls, without an external `mktemp` dependency.

Before publishing the new `INFO` entry, a private `dsm-entry.json` record retains
the ID, directory identities, initial operation/generation fingerprint, and exact
before/after index images. The new entry has `user_deletable: true`, an empty
service list, and description `XCertM: <certificate-id> (<destination-id>)`.
Unknown metadata and all existing entries are preserved; `INFO` ownership and
permissions are preserved during atomic replacement. `DEFAULT` is not modified.

The `.xcertm-dsm-create` marker identifies the owning destination/store during
incomplete registration. Other selectors/stores cannot bypass it. Retrying
accepts only the recorded old or new `INFO` image with the original metadata;
unrelated changes stop recovery. Once registered, the mapping is retained and
future generations reuse the ID. Removing its directory/index entry or losing
the mapping is an error, not a request to allocate a new ID.

Registration precedes certificate files, so an interruption can leave an empty
unassigned entry until deployment resumes. A crash before the mapping is saved
can leave an unregistered empty directory; it is retained and never adopted as
another certificate. Resume initial preparation with `Deploy` and the original
operation/generation; `Recover` alone needs a published file journal. No
certificate generation or key is discarded to recover this metadata step.

The adapter updates `privkey.pem`, `cert.pem`, `chain.pem`, and `fullchain.pem`
in the archive entry and each assigned service directory. With no chain,
the managed `chain.pem` is removed. It preserves existing UID/GID and ordinary
permissions; new files are `0600`. Unsafe private-key permissions are refused
(including world access, execute bits, or group write). An existing `0640`
service key keeps its owner/group and read permission. Updating an existing
entry leaves `INFO`, descriptions, unknown metadata, `DEFAULT` and assignments
unchanged. Automatic registration adds only the new entry to `INFO`.

Service certificate directories are resolved in this order:

1. `usr/local/etc/certificate/<subscriber>/<service>`
2. `usr/syno/etc/certificate/<subscriber>/<service>`

Activation follows Synolego's local mechanics: the first available subscriber
script is searched in `usr/libexec/certificate.d`,
`usr/local/libexec/certificate.d`, `usr/syno/share/certificate.d`, and
`usr/local/share/certificate.d`, and called with the service argument. If present,
`usr/libexec/security-profile/tls-profile/<subscriber>.sh` is then called without
arguments; `system/default` uses `dsm.sh`. Programs are invoked directly without
shell interpolation, with a 30-second context timeout per service. Script output
is discarded. Missing activation scripts are an error for an assigned service.
With no assigned services, only the archive is published.

A service is checkpointed only after its files and activation succeed. Completed
services are not activated again during recovery. An interruption after successful
activation but before its checkpoint can repeat that activation; scripts must
tolerate repetition. Arbitrary user hooks are not supported.

DSM shares `.synolego.lock` with the referenced Synolego implementation and
refuses `.synolego-pending`: recover those operations with Synolego. XCertM state
is not a migration of Synolego's journals. Changing assignments and remote DSM
APIs are outside this implementation.

## Persistence and recovery

The state root must have an existing parent; it and its state subdirectories
must be owned by the executing user with mode `0700`. Its private versioned JSON
is operational state, separate from user YAML configuration. Each stable
destination ID maps to its own `deployments/<SHA-256-of-ID>` directory, with:

- `current.json`: the pending operation or latest completed receipt (`0600`).
- `operation-*`: staged immutable contents (`0700`, files `0600`).
- `.lock`: a retained destination lock file.

The receipt also retains the generation's explicit source/reference and its
original validation instant, independently of ACME. Reusing a recorded generation
identity with different material or provenance is rejected.

The resource has a retained lock file and a `.xcertm-pending` marker pointing to
the owning store/operation. This prevents another state root or destination from
overwriting unfinished work after process loss. A marker without its journal, or
with a different operation identity, requires manual recovery. Do not remove
markers to bypass unresolved state.

Before publication, all contents and the journal are synchronized durably. Replay
preflights all files and staged blobs. Every destination must match its recorded
old or new contents and UID/GID/mode; a checkpointed group must remain new.
Directory device/inode/owner/mode changes and changes to guarded DSM configuration
stop recovery. Checks are repeated between file writes and before activation.
Recovery moves forward toward the pinned generation; there is no automatic
rollback. A complete receipt is retained to detect later drift before another
deployment. Completed DSM configuration snapshots do not prevent starting a new
operation after intentional assignment/index changes, provided the recorded
files and directories still match.

Generations/staged keys are not automatically pruned, including old completed
stages and preparation orphans. This deliberately preserves material needed to
diagnose or recover operations. Retention/garbage collection is future work.
Changing a destination's directory, selector, or filename layout is rejected
when an existing receipt uses another binding; migration is not implemented.

## Guarantees and limits

Local deployment currently supports Linux filesystems with working file/directory
synchronization, atomic single-file rename, ownership, and advisory `flock`.
Other platforms can build the CLI, but deployment reports unsupported capability.
Existing symlinks, non-regular output files, and symlinked parent directories
are rejected. Files/directories with extended attributes, ACLs, or security labels
are refused because this implementation cannot preserve them. It does not
silently replace them with different access-control metadata.

Each output file is prepared completely before replacement and synchronized,
including when its desired contents were already present. Multiple files are
never claimed to switch atomically together. A concurrent reader or interrupted
operation can observe mixed generations. Readers need their own coordination.
Filesystem success does not prove that a TLS endpoint serves the certificate.

Locks coordinate participating programs only. These checks require controlled
directories and are not an atomic compare-and-swap against an uncoordinated or
hostile writer. Power-loss durability depends on the filesystem/storage honoring
synchronization. Unsupported synchronization fails explicitly.

## Validation status

Tests use real local files and private temporary directories, failure injection
at every file/group/activation boundary, a subprocess exiting without cleanup,
and actual simulated DSM scripts. They cover per-destination partial results,
cross-store locks and markers, drift, corrupted staging/journals, changed DSM
configuration, preserved permissions, missing scripts, and selective activation
retries. No test accesses a real NAS.
Automatic-entry tests cover six-character IDs, metadata/default preservation,
generation reuse, assignment updates, every registration boundary, index/directory
conflicts, generation pinning and subprocess termination during registration.

Hardware/version compatibility, actual script idempotence, PKCS#8 acceptance,
and filesystem durability still require validation on the intended DSM versions
before claiming production compatibility.
