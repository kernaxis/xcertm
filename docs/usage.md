# Getting started

Install XCertM on the NAS or server that will use the certificate, following the
[installation guide](installation.md). You need a domain you control and API
credentials for its DNS provider. You do not need to open an incoming HTTP port.

The examples below name the certificate `web`. Replace the sample email,
domains and credentials with your own. Commands use `sudo` so the same setup
works for DSM and for system directories on Linux.

## Synology DSM

Create a private file named `xcertm.yaml` before adding your credentials:

```sh
touch xcertm.yaml
chmod 600 xcertm.yaml
```

Open it in your text editor and use the configuration below. This example uses
Cloudflare and asks DSM to create a separate certificate entry for XCertM:

```yaml
version: 1

acme:
  email: you@example.com
  accept_tos: true

dns_providers:
  dns:
    type: cloudflare
    zone: example.com
    api_token: "YOUR_CLOUDFLARE_TOKEN"

destinations:
  local:
    type: dsm

certificates:
  web:
    domains: [nas.example.com]
    dns_provider: dns
    destinations: [local]
```

Use a Cloudflare token with **Zone Read** and **DNS Edit** permissions for your
zone. Keep the file private. `accept_tos: true` accepts
the certificate authority's terms when registering your account. XCertM reads
this file only when you pass `--config ./xcertm.yaml`.

Continue with [requesting your certificate](#request-your-certificate).

After deploying the trusted certificate, open **Control Panel → Security →
Certificate → Settings** in DSM and assign it to the services that should use
it. The new entry is named `XCertM: web (local)`. It does not automatically
replace your default certificate or take over existing service assignments.
Later deployments reuse this entry and update its assigned services.

## Linux

Use the Cloudflare configuration above, but replace the entire `destinations`
section with:

```yaml
destinations:
  local:
    type: filesystem
    directory: /etc/xcertm/web
```

Create the destination before deploying:

```sh
sudo mkdir -p /etc/xcertm/web
```

Use a fresh directory: XCertM refuses to overwrite preexisting certificate files
on the first deployment. After deployment it contains:

| File | Use |
| --- | --- |
| `fullchain.pem` | Certificate and issuer chain |
| `privkey.pem` | Private key; keep it private |

Configure your application to read these files and reload it after each
deployment. With these `sudo` commands, the files are readable only by root;
check how your application loads certificates. Do not change the generated
files or their permissions between deployments. XCertM does not reload Linux
services; see the [deployment guide](architecture/deployment.md#filesystem-target)
for details.

## Using OVH

Use the same DSM or Linux configuration, replacing the entire `dns_providers`
section with:

```yaml
dns_providers:
  dns:
    type: ovh
    endpoint: ovh-eu
    zone: example.com
    application_key_file: ./ovh-application-key
    application_secret_file: ./ovh-application-secret
    consumer_key_file: ./ovh-consumer-key
```

Create these three files beside `xcertm.yaml`, then fill each with the matching
OVH credential using your text editor:

```sh
touch ovh-application-key ovh-application-secret ovh-consumer-key
chmod 600 ovh-application-key ovh-application-secret ovh-consumer-key
```

The credentials must permit reading, adding and removing TXT records and
refreshing your DNS zone. For OVH Canada or US, use `ovh-ca` or `ovh-us`.
See the [credential reference](architecture/configuration.md#credentials)
for permissions and environment-variable alternatives.

## Request your certificate

First, request a test certificate without deploying it:

```sh
sudo xcertm issue --config ./xcertm.yaml --certificate web --staging
```

This uses Let's Encrypt's test environment. Its certificates are **not trusted
by browsers**. When the test succeeds, request and deploy a trusted certificate:

```sh
sudo xcertm issue --config ./xcertm.yaml --certificate web --deploy
```

The sample configuration uses production by default. If you copy another
configuration, ensure its `acme.environment` is not set to `staging` before
deploying to a live service. There is no need to delete the earlier test
certificate or change the `web` name.

For a wildcard or several domain names, change `domains`, for example:

```yaml
domains: [example.com, "*.example.com"]
```

If a command is interrupted, repeat it with the same configuration and flags.
Keep XCertM's saved files so it can resume. For a DNS propagation timeout, see
[DNS troubleshooting](architecture/configuration.md#dns-propagation-troubleshooting).

## Renew and inspect

```sh
sudo xcertm renew --config ./xcertm.yaml --all --deploy
sudo xcertm list
sudo xcertm show web
```

`renew` requests a replacement when needed. `list` shows expiry dates and where
certificates were deployed; `show` displays more details. Both test and trusted
certificates can appear, labeled `staging` and `production` respectively.

To check for renewal every day, schedule this command as root with **DSM Task
Scheduler** or **cron**, replacing the paths with your actual locations:

```sh
/usr/local/bin/xcertm renew --config /absolute/path/to/xcertm.yaml --all --deploy
```

Use the scheduler's output/error notifications to notice failed runs. For Linux,
arrange your application's reload separately. Keep using the same configuration
and saved-data location for manual and scheduled commands.

XCertM keeps certificates, private keys and progress in `/usr/local/share/xcertm`
on DSM and `/var/lib/xcertm` on Linux. Back up that directory securely along with
your configuration and credential files. Do not delete it between runs. See
[storage settings](architecture/configuration.md#store-selection-and-permissions)
if you need another location.

## Without a configuration file

All certificate operations also accept command-line options. For example, with
a private Cloudflare token file and an existing destination directory:

```sh
sudo xcertm issue --staging --certificate web \
  --email you@example.com --accept-tos \
  --dns cloudflare --zone example.com --cloudflare-token-file ./cloudflare-token \
  --domain example.com --domain '*.example.com' \
  --destination local --type filesystem --directory /etc/xcertm/web
```

The token file must have mode `0600` or `0400`. This example obtains a test
certificate without deploying it. The [command reference](architecture/configuration.md)
describes all flags and how to deploy or renew without YAML.
