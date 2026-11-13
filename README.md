# XCertM

[![CI](https://github.com/kernaxis/xcertm/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/kernaxis/xcertm/actions/workflows/ci.yml)
[![Security](https://github.com/kernaxis/xcertm/actions/workflows/security.yml/badge.svg?branch=main)](https://github.com/kernaxis/xcertm/actions/workflows/security.yml)
[![Latest release](https://img.shields.io/github/v/release/kernaxis/xcertm)](https://github.com/kernaxis/xcertm/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Get, renew and install Let's Encrypt certificates on your **Synology NAS** or
**Linux server**.

XCertM supports **Cloudflare** and **OVH**, including wildcard certificates such
as `*.example.com`. One certificate can be installed in several locations on
the same machine.

## Install

Open a terminal on the NAS or Linux server where you want to use your certificates:

```sh
curl -fsSL https://raw.githubusercontent.com/kernaxis/xcertm/main/install.sh | sudo sh
```

The installer selects the right binary for your machine. For manual installation
or installation without root, see the [installation guide](docs/installation.md).

## Get your first certificate

You need a domain managed through Cloudflare or OVH and credentials allowing
XCertM to update its DNS records.

Create `xcertm.yaml` using the [getting started guide](docs/usage.md):

- [Synology DSM](docs/usage.md#synology-dsm): install certificates in DSM.
- [Linux](docs/usage.md#linux): save certificate files for your application.
- [OVH](docs/usage.md#using-ovh): use OVH instead of Cloudflare.

Start with a **test certificate**, which browsers will not trust:

```sh
sudo xcertm issue --config ./xcertm.yaml --certificate web --staging
```

Once that succeeds, request and install a **trusted certificate**:

```sh
sudo xcertm issue --config ./xcertm.yaml --certificate web --deploy
```

On DSM, assign the new certificate to your services in **Control Panel →
Security → Certificate → Settings**. On Linux, configure your application to
use the generated files and reload it yourself.

## Everyday commands

| What you want to do | Command |
| --- | --- |
| Renew certificates when needed and install them | `sudo xcertm renew --config ./xcertm.yaml --all --deploy` |
| List your certificates | `sudo xcertm list` |
| See details for a certificate | `sudo xcertm show web` |
| Deploy a stored certificate where needed | `sudo xcertm deploy --config ./xcertm.yaml --certificate web` |

Schedule the renewal command with DSM Task Scheduler or cron to check regularly.
XCertM does not run in the background. See the [usage guide](docs/usage.md#renew-and-inspect)
for scheduling and where your certificates are kept.

## Update XCertM

```sh
sudo xcertm update
```

XCertM shows the new version and asks for confirmation. If you already have the
latest version, it tells you. This command requires **v0.1.1 or later**; see the
[update guide](docs/installation.md#update-an-installed-binary) for details.

## Learn more

- [Getting started and daily use](docs/usage.md)
- [Configuration and all command options](docs/architecture/configuration.md)
- [Installation and updates](docs/installation.md)
- [Building and contributing](docs/development.md)

XCertM is in early development. Test your setup before using it for a live service.
Released under the [MIT license](LICENSE), with [third-party notices](THIRD_PARTY_NOTICES.md).
