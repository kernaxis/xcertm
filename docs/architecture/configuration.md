# Configuration and commands

YAML is optional. Use `--config PATH` explicitly; XCertM does not discover or
rewrite configuration files. The [example](../../examples/xcertm.yaml) contains
both DNS providers and filesystem/DSM destinations. All destinations are local
to the executing host, including when one NAS deploys both to DSM and to files
consumed by another local application.

## Selection and precedence

Commands accept global flags before or after their name. Effective values come
from built-in defaults, then YAML, then explicitly supplied flags. A supplied
list replaces its configured counterpart. YAML-relative paths (including secret
files and destination directories) are based on the YAML file's directory;
flag-relative paths are based on the current working directory.

`--certificate ID` selects one managed certificate. `--all` selects every profile
in the supplied YAML, or stored certificate/pending-operation IDs when there are
no configured profiles. They are mutually exclusive. Selection is sorted for
predictable execution; destinations belonging to several selected certificates
are rejected before starting the batch. Independent failures are reported with
a nonzero overall exit code.

Without a matching YAML profile, commands reuse the last pending or obtained
request in the selected ACME environment. This stores non-secret recovery inputs,
not a database-managed configuration registry. YAML profiles remain authoritative
when present. Stored credential references can be overridden with flags; literal
credential values are never persisted in requests.

## YAML reference

Unknown fields, duplicate mapping keys, multiple documents, files larger than
1 MiB, and unsupported versions are rejected. Format version is `1`.
Only selected certificate requests are semantically validated, so an unrelated
profile's credentials need not be present.

| Section | Settings |
| --- | --- |
| `state_dir` | Optional persistent root override. |
| `acme` | `environment`: `production` (default) or `staging`; `email`; `accept_tos` for account registration. |
| `dns_providers.<id>` | `type`: `cloudflare` or `ovh`; optional `zone`; credential references below. OVH `endpoint` defaults to `ovh-eu`, with `ovh-ca` and `ovh-us` also accepted. |
| `destinations.<id>` | `type`: `filesystem` or `dsm`, with the fields below. IDs remain stable across generations. |
| `certificates.<id>` | Required `domains` and `dns_provider`; optional `destinations` and `renew_before`. |
| `resolvers` | Optional list of resolver IPs, optionally with ports; otherwise the system's Go DNS resolver is used. |

Filesystem settings are `directory` (existing absolute or YAML-relative path),
optional `key_file` (default `privkey.pem`), and `certificate_file` (default
`fullchain.pem`). Output names must be distinct direct child filenames. The
first deployment refuses preexisting managed files. No service is reloaded.

DSM has three selection modes:

- Neither selector: create a dedicated entry on first deployment and reuse its
  stored six-character ID on later generations.
- `certificate_id`: update this existing entry.
- `default: true`: update the existing default entry.

`certificate_id` and `default: true` are mutually exclusive. Minimal automatic
configuration is:

```yaml
destinations:
  nas-test:
    type: dsm
```

The created entry is labeled `XCertM: <certificate-id> (<destination-id>)` and
initially has no assigned services. Creation does not change DSM's default or
existing assignments. Assign services through DSM when appropriate; subsequent
generations use those assignments. Existing entry descriptions are preserved.
Local deployment normally requires root for archive updates, ownership and
reload scripts. Keep the store: its ID mapping is necessary for reuse/recovery.

`renew_before` accepts a positive Go duration or days, such as `480h` or `20d`.
For renewal of an existing certificate it must be smaller than its lifetime.
The default window is the final third of the certificate's actual lifetime.

## Credentials

| Provider | YAML environment reference | Default environment variable |
| --- | --- | --- |
| Cloudflare | `api_token_env` | `CLOUDFLARE_API_TOKEN` |
| OVH | `application_key_env` | `OVH_APPLICATION_KEY` |
| OVH | `application_secret_env` | `OVH_APPLICATION_SECRET` |
| OVH | `consumer_key_env` | `OVH_CONSUMER_KEY` |

Replace the `_env` suffix with `_file` to reference a private regular file.
Choose one source per credential. Files must have mode `0400` or `0600` and
must not be symlinks. Surrounding whitespace is trimmed; embedded newlines and
empty credentials are rejected. Secret values are resolved only when DNS work
is required; inspection, reuse of an already issued generation, and deployment
need no DNS credentials. Pending DNS cleanup does require them.

Cloudflare also accepts an inline token in YAML:

```yaml
dns_providers:
  cloudflare:
    type: cloudflare
    zone: example.com
    api_token: "YOUR_CLOUDFLARE_TOKEN"
```

Use exactly one of `api_token`, `api_token_env`, or `api_token_file`. YAML
containing an inline token must itself have mode `0600` or `0400` (`chmod 600
xcertm.yaml`). The token is used only in memory: it is excluded from persistent
request/generation snapshots and `list`/`show`. Continue passing this YAML to
issuance/renewal commands and DNS-cleanup retries; the store cannot restore its
literal token when the YAML is omitted. Explicit credential-reference flags
override the configured inline token. Changing the inline token's value does
not change a pending order's identity.

For Cloudflare use a token scoped to the intended zone with Zone Read and DNS
Edit permissions. An explicit `zone` avoids probing parent suffixes, but the
adapter still resolves its ID through the zones API. OVH AK/AS/CK access must
allow reading/listing TXT records, creating and deleting individual records,
and refreshing the intended zone. With an explicit zone it need not list all
zones. The public `/auth/time` endpoint is used for signed-request timestamps.
No provider SDK or external DNS library is needed.

## Network prerequisites

Building with an empty module cache needs HTTPS access to `proxy.golang.org` and
`sum.golang.org` (or the configured Go proxy/checksum services). Automated tests
use loopback HTTP servers and require no public network once modules are cached.

Runtime issuance needs outbound HTTPS (TCP 443) to the selected Let's Encrypt
directory, `acme-v02.api.letsencrypt.org` or
`acme-staging-v02.api.letsencrypt.org`, and the selected provider:
`api.cloudflare.com`, `eu.api.ovh.com`, `ca.api.ovh.com`, or
`api.us.ovhcloud.com`. The host needs working CA trust roots and an accurate clock.
Provider credentials must cover the requested zone.

Propagation checks need UDP/TCP DNS access to the system or configured resolvers
(normally port 53). No inbound HTTP port is needed for DNS-01. Local deployment
and store inspection need no network; DNS cleanup after issuance still does.

## Store selection and permissions

| Executing environment | Default root |
| --- | --- |
| Linux | `/var/lib/xcertm` |
| Synology DSM | `/usr/local/share/xcertm` |

`--state-dir` overrides YAML `state_dir`, which overrides this default. DSM host
detection checks for both `/etc.defaults/VERSION` and `/etc/synoinfo.conf`;
it does not depend on the selected destination. Every command resolves the same
root. Overrides are useful for unprivileged users, containers, and persistent
DSM volumes; ensure the chosen path survives upgrades in your installation.

The root's parent must exist. XCertM creates its root/subdirectories with mode
`0700`; existing ones must be private and owned by the executing user. Store
files containing keys and journals have mode `0600`. The root contains accounts,
certificate generations, pending issuance, deployment requests and deployment
journals, not just published output files. Back up the complete store securely.
No keys or recovery records are automatically pruned.

## Lifecycle commands

```sh
xcertm issue --config xcertm.yaml --certificate web --deploy
xcertm renew --config xcertm.yaml --all --deploy
xcertm deploy --config xcertm.yaml --certificate web --destination nas-main
```

- `issue` obtains/stores a generation, or reuses an existing valid one with the
  same SAN set. `--deploy` also publishes it. No destination is needed to issue
  without deployment.
- `renew` checks the renewal window before issuing. An absent generation is
  issued. `--deploy` also publishes a generation that is not yet due.
- `--force` explicitly requests a new issuance for `issue` or `renew`, with a
  fresh key. Recovery of an unfinished deployment takes priority even with this flag.
- `deploy` uses the latest stored generation in the selected environment and
  does not contact ACME or DNS. It can resume an older pinned deployment first;
  output identifies the generation actually used by each destination.

Production is the default. `--staging` or `--environment staging` selects Let's
Encrypt staging, whose certificates are not publicly trusted. `list`/`show`
show both environments unless explicitly filtered. Do not publish a staging
certificate to a production service by mistake.

Example without YAML, using OVH environment credentials:

```sh
xcertm issue --staging --certificate web --email admin@example.com --accept-tos \
  --dns ovh --ovh-endpoint ovh-eu --zone example.com \
  --domain example.com --domain '*.example.com' \
  --destination web-local --type filesystem --directory /etc/example/tls --deploy

xcertm renew --staging --certificate web --deploy
xcertm deploy --staging --certificate web --destination web-local
```

For automatic DSM creation use `--destination nas-main --type dsm`. Add
`--dsm-default` or `--dsm-certificate-id ABC123` to select an existing entry
instead. Explicit destination settings require exactly
one selected destination; YAML defines multiple different destinations conveniently.

| Flags | Purpose |
| --- | --- |
| `--config`, `--state-dir`, `--environment`, `--staging` | Configuration, store and CA selection. |
| `--certificate`, `--all` | Select managed certificate requests. |
| `--email`, `--accept-tos`, repeatable `--domain` | Account registration and SANs. Quote wildcard names. |
| `--dns`, `--zone`, `--ovh-endpoint` | Named YAML provider or explicit `cloudflare`/`ovh` and optional zone/region. |
| `--cloudflare-token-env` / `--cloudflare-token-file` | Cloudflare credential reference override. |
| `--ovh-application-key-env`, `--ovh-application-secret-env`, `--ovh-consumer-key-env` | OVH credential reference overrides; each also has a `-file` variant. |
| Repeatable `--destination`, `--type`, `--directory`, `--key-file`, `--certificate-file` | Filesystem destination selection/settings. |
| `--dsm-default`, `--dsm-certificate-id` | Existing local DSM entry selection; omit both to create a dedicated managed entry. |
| `--deploy`, `--force`, `--renew-before` | Issuance/renewal and optional publication policy. |
| Repeatable `--resolver`, `--propagation-timeout` | DNS lookup selection; default propagation deadline `2m`. |
| `--timeout` | Whole lifecycle command deadline, default `10m`. |
| `--json` | Public results as JSON on stdout. Progress and diagnostics stay on stderr; errors exit nonzero. |

Run `xcertm <command> --help` for the flags accepted by that command. Secrets
should enter the process environment through your secret manager or a private
file, or a private YAML file using the inline Cloudflare setting above.

Lifecycle commands report progress on stderr by default: selected store and
resolver, ACME operation/recovery, TXT publication, propagation, generation
storage, DNS cleanup, and deployment. During propagation, changed observations
are reported immediately, with a reminder at least every 15 seconds between
completed polls. Timeout diagnostics identify the owner name, missing TXT counts,
or the lookup failure and resolver when the system supplies it. Logs omit token
values, private keys, and TXT proof values. stdout contains the final summary or
JSON; `2>&1` combines both streams when desired.

### DNS propagation troubleshooting

The default recursive resolver may have cached a negative answer before the TXT
was created. Compare the same query against the NAS resolver and a public one:

```sh
nslookup -type=TXT _acme-challenge.example.com
nslookup -type=TXT _acme-challenge.example.com 1.1.1.1
```

If only the public resolver returns the expected TXT, retry the same pending
issuance with `--resolver 1.1.1.1 --propagation-timeout 5m`, without `--force` or
deleting the store. A recursive-resolver difference can reflect caching or local
DNS policy; it does not by itself prove universal DNS visibility. To retain the
resolver selection, add a top-level YAML setting:

```yaml
resolvers:
  - 1.1.1.1
```

The selected resolver must be reachable from the executing host over DNS.

## Recovery

Repeat an interrupted request with the same certificate ID, environment, account,
SANs, and DNS parameters. Stored inputs are reused when flags/YAML do not replace
them. Changing these inputs while issuance is pending is rejected. For DNS
cleanup after issuance, the stored generation is reused without reissuing.
HTTP 429 retry deadlines are persisted; retry after the indicated time.

An interrupted deployment retains its original destination parameters and key
material. Use `deploy` with that certificate/destination to reconcile it; another
issuance is blocked while known deployment work remains unfinished. If an
`issue --deploy` invocation recovers pending deployments, it reports `recovered`
and returns without issuing; run `renew` again when ready to evaluate renewal.
A different generation can require another `deploy` after pinned work completes.

Automatic DSM entry creation has a separate durable mapping and registration
record. Retry with the same store, destination, certificate and generation;
an interrupted `INFO` update is reconciled before certificate publication. Do
not delete the mapping or `.xcertm-dsm-create` marker to force a new entry.
If DSM's index or the reserved directory changed during incomplete registration,
recovery stops in conflict. A removed managed entry is not silently replaced.

Drift/conflicts are reported for manual resolution, never silently overwritten.
See [deployment and recovery](deployment.md) for file guarantees and limits.

## Read-only inspection

```sh
xcertm list
xcertm show web
xcertm list --state-dir /custom/private/xcertm --json
xcertm show web --state-dir /custom/private/xcertm --environment staging --json
```

`list` summarizes the latest stored generation per managed ID and environment,
SANs, expiry and recorded destination results. A profile that has never obtained
a certificate is not an inventory entry. `show <id>` includes every stored
generation, validity, issuer, public-key algorithm, SHA-256 fingerprint,
provenance, pending issuance and destination observations.

Neither command needs YAML, DNS credentials, or network access. They do not
recover operations, activate services, create a missing store, or expose keys or
credential values. Deployment information is the last recorded observation,
not a live assertion about files or a service's TLS endpoint.

An absent store yields an empty `list` (`[]` with `--json`); unknown IDs make
`show` fail. Unreadable or corrupt state is an error. There are no certificate
`add`, `update`, or `delete` commands and no database.
