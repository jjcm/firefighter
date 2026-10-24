# Deployment

The public deployment uses [https://45.76.243.18/](https://45.76.243.18/) for the
notice board, [FAQ](https://45.76.243.18/faq), [signed notices](https://45.76.243.18/api/v1/notices), and
[source health](https://45.76.243.18/api/v1/status). The status endpoint is the
source of truth for upstream availability. The hosted deployment and default hub
configuration use Ubuntu notices, CISA KEV, and NVD. Paid X intake is currently
disabled to stop API spend; the integration remains available as an opt-in source.

The hub collects public advisory data once. Clients receive signed notices,
then use their own inventory, model credentials, and local root runner to assess
and repair their servers. The hub has no action, shell, policy-update, approval,
or remote-remediation endpoint. The notice feed does not upload client inventory,
command output, credentials, or private incident records to the hub.

## Components and paths

| Component | Deployment choice |
| --- | --- |
| Public endpoint | `https://45.76.243.18/` |
| TLS termination | nginx, ports 80 and 443; public links use IPv4 |
| IP certificate | Certbot short-lived profile, lineage `firefighter-ip` |
| Certificate files | `/etc/letsencrypt/live/firefighter-ip/fullchain.pem` and `privkey.pem` |
| Hub listener | `127.0.0.1:8090`, accessible through nginx |
| Hub service account | `firefighter-hub`, without root remediation privileges |
| Hub executable | `/usr/local/bin/firefighter-hub` |
| Hub configuration | `/etc/firefighter-hub/config.json` |
| Hub environment | `/etc/firefighter-hub/firefighter-hub.env`, root-owned `0600` |
| Hub state and signing key | `/var/lib/firefighter-hub`, directory `0700`, files `0600` |
| Website assets | `/opt/firefighter/web` |
| Public bootstrap | `/opt/firefighter/install.sh`, served at `/` for curl and explicitly at `/install.sh` |
| Public publisher key | `/opt/firefighter/downloads/firefighter-hub.pub`, the only allowed download path |
| ACME challenge webroot | `/var/lib/letsencrypt` |
| Administrator access | SSH alias `firefighter`, user `j`, with passwordless sudo; existing `firefighter-host` / `firefighter-admin` access remains available |

Root SSH login is disabled in this deployment. On the local Mac, `ssh firefighter`
connects as `j` using a dedicated key. This account has passwordless sudo. The
local SSH entries are:

```sshconfig
Host firefighter
    HostName 45.76.243.18
    User j
    IdentityFile ~/.ssh/firefighter_j_ed25519
    IdentitiesOnly yes

Host firefighter-host
    HostName 45.76.243.18
    User firefighter-admin
    IdentityFile ~/.ssh/firefighter_vps_ed25519
    IdentitiesOnly yes
```

The Mac's `/etc/hosts` also contains this local hostname mapping:

```text
45.76.243.18 firefighter
```

These paths name local private keys; neither key nor its contents belongs in this
repository, the website, or the download directory. For another deployment,
replace the IP address, administrator account, and local identity path. The local
`firefighter` alias does not configure public DNS for `firefighter.sh`.

## Build and install the hub

From a reviewed checkout:

```sh
make check
make linux
```

The build produces responder, hub, and Grok Bot bridge binaries for both Linux
amd64 and arm64. The current hub uses amd64. `make build` instead produces all
three binaries for the machine running the build.

On the hub, create the service account once and prepare its directories:

```sh
sudo useradd --system --home-dir /var/lib/firefighter-hub \
  --shell /usr/sbin/nologin firefighter-hub
sudo install -d -o root -g firefighter-hub -m 0750 /etc/firefighter-hub
sudo install -d -o firefighter-hub -g firefighter-hub -m 0700 /var/lib/firefighter-hub
sudo install -d -o root -g root -m 0755 \
  /opt/firefighter/web /opt/firefighter/downloads \
  /var/lib/letsencrypt/.well-known/acme-challenge
sudo install -m 0755 dist/firefighter-hub-linux-amd64 /usr/local/bin/firefighter-hub
sudo install -o root -g firefighter-hub -m 0640 \
  configs/hub.example.json /etc/firefighter-hub/config.json
sudo cp -R web/. /opt/firefighter/web/
sudo install -m 0644 deploy/bootstrap.sh /opt/firefighter/install.sh
sudo install -m 0644 deploy/firefighter-hub.service /etc/systemd/system/firefighter-hub.service
```

Skip account creation when the account already exists. Preserve existing
configuration, credentials, and state on subsequent deployments. The responder
installer is separate; a public notice hub does not need the root responder
service to distribute notices.

Edit the hub configuration for the chosen sources and retention limits. Place
upstream credentials in the private environment file, using environment variable
names referenced by that configuration. The file may contain `X_BEARER_TOKEN`
and an optional `NVD_API_KEY`; never place their values in public JSON or assets.
systemd reads the environment file before running the unprivileged service.

Initialize the signing identity once:

```sh
sudo -u firefighter-hub /usr/local/bin/firefighter-hub init-key \
  --config /etc/firefighter-hub/config.json
sudo -u firefighter-hub /usr/local/bin/firefighter-hub check \
  --config /etc/firefighter-hub/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now firefighter-hub
```

`init-key` refuses to overwrite an existing key. Back up the private signing key
and hub state together. Replacing the signing identity requires intentionally
redistributing and verifying a new public pin on every client.

## HTTPS and nginx

The supplied [nginx configuration](../deploy/nginx.conf) matches this deployment.
It proxies the site and APIs to the loopback hub, overwrites `X-Real-IP` and
`X-Forwarded-For` with nginx's observed client address, and exposes only the exact
`/downloads/firefighter-hub.pub` public-key path. Other `/downloads/` paths return
404; prebuilt Firefighter executables are not distributed. At exact `/`, curl
User-Agents receive `/opt/firefighter/install.sh` as plain text while browsers
receive the website. Both responses use `Cache-Control: no-store` and
`Vary: User-Agent` to prevent caches mixing the two representations. The explicit
`/install.sh` route serves the same installer regardless of User-Agent; neither
route exposes the deployment directory. The hub maps `/faq` and `/faq/` to the public `faq.html` asset. These web
routes do not change the signed notice schema or add an API for running commands.
The address overwrite is required because the hub trusts the local proxy's header
for rate limiting.

For an initial installation, enable the HTTP server and ACME challenge location
before obtaining a certificate. Do not enable an HTTPS block referring to
certificate files that do not yet exist. The deployment uses Certbot 5.5 with
these issuance options and its configured ACME account:

```sh
sudo certbot certonly \
  --preferred-profile shortlived \
  --webroot --webroot-path /var/lib/letsencrypt \
  --ip-address 45.76.243.18 \
  --cert-name firefighter-ip \
  --deploy-hook 'systemctl reload nginx'
```

After certificate issuance, install the complete nginx configuration, enable it,
validate it, and reload nginx:

```sh
sudo install -m 0644 deploy/nginx.conf /etc/nginx/sites-available/firefighter
sudo ln -s /etc/nginx/sites-available/firefighter /etc/nginx/sites-enabled/firefighter
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl enable --now certbot.timer
```

Skip the symlink command when it already exists. Review existing nginx sites
before changing listeners. The certificate is short-lived, so automatic renewal
and the nginx reload hook are part of normal operation. Verify timer activity and
renewal logs; do not disable TLS verification on clients if renewal fails.

```sh
sudo systemctl status certbot.timer
sudo journalctl -u certbot.service --since '1 day ago'
sudo certbot certificates
```

The deployment uses a publicly trusted IP certificate. A private installation
can instead distribute a CA bundle and configure the client's absolute `ca_file`
path. Hostname/IP matching remains enabled, and the Ed25519 publisher pin remains
required independently of TLS.

### Domain certificate (pending DNS)

`firefighter.sh` is the intended domain, but its certificate is not issued yet.
Cloudflare shows the registrar status as Active, with nameservers
`aria.ns.cloudflare.com` and `ridge.ns.cloudflare.com`. The apex A record points
to `45.76.243.18` with proxying enabled, and SSL/TLS mode is Full (Strict).
Direct queries to those Cloudflare nameservers return edge addresses
`172.67.163.131` and `104.21.49.139`, as expected for a proxied record. Public DNS
should resolve to Cloudflare's edge addresses, which may change, rather than the
origin IP.

At approximately 13:58 UTC (20:58 Bangkok time) on October 24, 2026, direct queries
from both the Mac and hub to authoritative `.sh` nameservers still returned
`NXDOMAIN`. The remaining blocker is registry publication of the delegation,
despite the active registration and configured Cloudflare zone. The existing IP
URL and its `firefighter-ip` certificate remain in service.

The hub's HTTP domain route for `/.well-known/acme-challenge/` has been prepared
and verified against `/var/lib/letsencrypt`. Once the delegation is published and
public DNS resolves the domain, verify that this challenge path is reachable
through Cloudflare on port 80. Local hosts-file entries do not satisfy the
certificate authority's DNS checks. Use the existing ACME account to issue a
separate domain certificate:

```sh
sudo certbot certonly --non-interactive --webroot -w /var/lib/letsencrypt \
  -d firefighter.sh --cert-name firefighter-domain \
  --deploy-hook 'nginx -t && systemctl reload nginx'
```

The final [domain nginx configuration](../deploy/nginx-domain.conf) is prepared
locally. Only after `/etc/letsencrypt/live/firefighter-domain/fullchain.pem` and
`privkey.pem` exist, install and enable it:

```sh
sudo install -m 0644 deploy/nginx-domain.conf /etc/nginx/sites-available/firefighter-domain
sudo ln -s /etc/nginx/sites-available/firefighter-domain /etc/nginx/sites-enabled/firefighter-domain
sudo nginx -t
sudo systemctl reload nginx
sudo certbot renew --cert-name firefighter-domain --dry-run
```

Skip the symlink command if it already exists. Keep the original IP vhost and
certificate lineage enabled so existing clients continue to work. The existing
`certbot.timer` will renew both certificates; the domain deploy hook validates and
reloads nginx after successful renewal. A dry run does not run deploy hooks unless
`--run-deploy-hooks` is also supplied. No hub restart or client configuration change
is required. See the [Certbot renewal documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

## Optional X intake (currently disabled)

The deployed hub has no X source in its active `sources` array, so it schedules no
X API requests. The existing credential and source cursor are retained privately;
previously collected notices remain in signed history. The live notice board only
shows currently configured sources.

To re-enable paid X intake later, explicitly add an X source to the hub configuration
and restart the hub. On the current VPS, its previous source entry is saved in the
root-only `/etc/firefighter-hub/x-source.disabled.json` file. Keep the credential in
the private hub environment file. Review the query and provider pricing before
re-enabling. No client configuration change is required.

## Publish the installer and public key

The public installer retrieves a pinned source revision from the public GitHub
repository and compiles it on each client. Do not publish Firefighter binaries,
configuration templates, environment files, or checksum manifests to the website.
The installer obtains its build and service files from the reviewed source commit.

Publish the implementation commit first. Then update `FF_SOURCE_REV` in
`deploy/bootstrap.sh` to that exact 40-character commit ID, commit the pin change,
and publish the updated bootstrap. This two-commit workflow ensures the referenced
implementation already exists in GitHub. Do not replace the pin with a moving
branch name. The bootstrap checks that the fetched checkout matches its pin.

```sh
sudo -u firefighter-hub /usr/local/bin/firefighter-hub public-key \
  --config /etc/firefighter-hub/config.json \
  | sudo tee /opt/firefighter/downloads/firefighter-hub.pub >/dev/null
sudo install -m 0644 deploy/bootstrap.sh /opt/firefighter/install.sh
```

The `public-key` command prints only the public Ed25519 key. Clients should compare
it with an independently verified operator value before pinning it. The source
configuration template must contain that verified publisher pin. Existing client
configuration, including the pin, is preserved on upgrades. Keep real environment
files, source checkouts, and hub state outside public paths.

The nginx configuration serves the installer at exact `/` for curl and at
`/install.sh` for any client. Only `/downloads/firefighter-hub.pub` is downloadable
under `/downloads/`; its old general downloads location is disabled. The Go compiler bootstrap downloads official compiler
archives from `go.dev` and checks them against HTTPS release metadata. This is a
build prerequisite, not a prebuilt Firefighter release.

## Install a client

From an interactive terminal on a Linux server with a running systemd manager,
the domain quickstart is:

```sh
curl -fsSL https://firefighter.sh | sudo bash
```

The domain is still pending registry DNS publication and certificate issuance.
Until it is ready, use `curl -fsSL https://45.76.243.18 | sudo bash`.
`/install.sh` remains the explicit fallback when using a different User-Agent;
opening `/` in a browser shows the website.

The first installation displays an exact risk-acknowledgment sentence. The operator
must type it through `/dev/tty`; no terminal or a different sentence causes an
exit before writes. After successful startup, a root-owned, mode `0600` record at
`/etc/firefighter/install-risk-acknowledgment` skips that prompt on later upgrades.
This is installation consent, not a runtime approval step.

New setup asks for the provider, model, and an API key with echo disabled:

| Provider | Default model | Backend | Environment variable |
| --- | --- | --- | --- |
| OpenRouter (default) | `deepseek/deepseek-v4.1-flash-1017` | `api` | `OPENROUTER_API_KEY` |
| OpenAI | `gpt-6.1-sol` | `api` | `OPENAI_API_KEY` |
| Anthropic | `claude-sonnet-5-5` | `anthropic` | `ANTHROPIC_API_KEY` |

The model can be overridden. OpenRouter uses `https://openrouter.ai/api/v1` with
schema-constrained output (`json_mode: false`) and requires upstream support for
the requested parameters. OpenAI uses `https://api.openai.com/v1` with strict
structured output. Anthropic uses `https://api.anthropic.com/v1` and its native Messages API,
with `json_mode` disabled. [Planner details](../internal/planner/README.md) describe
provider output validation. Upgrades preserve existing configuration, including
an existing `json_mode: true`; they do not silently change a provider's mode.

The installer can install missing `git`, `curl`, and `python3` using apt, dnf, yum,
pacman, or zypper. It uses an installed Go version meeting `go.mod` or downloads a
checksum-verified official host toolchain into its private temporary workspace.
Architectures without an automatic toolchain download need a compatible Go
compiler installed first. The Firefighter executables are compiled locally.

The build workspace is a private directory under `/var/tmp`. Source, the optional
Go toolchain, build caches, and compiler scratch files all stay there; both
`TMPDIR` and `GOTMPDIR` point into the workspace. This avoids filling a small
RAM-backed `/tmp`. After risk acknowledgment, the installer checks for at least
2 GiB free on `/var/tmp` before downloads or provider setup. If that filesystem
is too small, free space or give `/var/tmp` a larger disk-backed filesystem before
retrying. Builds use one package worker to limit memory pressure. The temporary
workspace is cleaned up on success or failure.

The new configuration uses the central signed feed. Existing model settings and
credentials are preserved. After compilation, the final interactive step offers
Discord, Telegram, Slack, Grok Bot, or an explicit local-only choice. Destination
URLs and tokens are read with echo disabled and stored in the private environment
file. Telegram can pair a private chat using a one-time code. The compiled client
sends a test directly to the chosen provider before installation starts the service.
Failed delivery offers retry or another choice. Configured destinations and explicit
local-only selections are preserved on upgrades; an unattended upgrade does not
invent a destination.

After messaging setup and offline `doctor` validation pass, the installer enables
the responder at boot, starts or restarts it, and checks that it is active. There
are no model API calls during setup; model access and balance are checked by the
running service. Messaging tests do make provider requests. Grok Bot acceptance
starts a reporting routine, whose completion must be checked in the Bot chat.
Clients deliver messages directly over HTTPS without using the notice hub. The
optional older Grok Bot bridge remains available; see [notification setup](../README.md#choose-notifications).

For an existing configuration that polls upstream sources directly, replace the complete `sources`
array and configure the model API as needed. This fragment follows the public
bootstrap defaults; substitute the independently verified publisher key:

```json
{
  "sources": [
    {
      "name": "firefighter-central",
      "type": "broadcast",
      "url": "https://45.76.243.18",
      "public_key": "YOUR_VERIFIED_BASE64_ED25519_PUBLIC_KEY",
      "interval_seconds": 15
    }
  ],
  "llm": {
    "backend": "api",
    "base_url": "https://openrouter.ai/api/v1",
    "model": "deepseek/deepseek-v4.1-flash-1017",
    "api_key_env": "OPENROUTER_API_KEY",
    "timeout_seconds": 180,
    "json_mode": false
  }
}
```

This is a configuration fragment, not a full replacement for the responder's
execution and state settings. The shown provider/model is the selected deployment
configuration; the provider remains configurable. Put the corresponding model
credential in `/etc/firefighter/firefighter.env`, with mode `0600`. Each client
uses its own model access and makes local decisions. Shared-feed clients need no
X or NVD key for intake and do not poll those upstream feeds directly.

`json_mode: false` requests schema-constrained responses. At the official
OpenRouter endpoint the client also sends `provider.require_parameters: true`.
Operators may explicitly set `json_mode: true` for JSON-object responses when a
provider lacks schema support; that mode does not enforce the decision's shape.
Both modes retain the same strict local decision validation, command limits, and
mandatory mutation verification, with no automatic downgrade or output repair. The
responder runs as root without approval prompts. The unprivileged public hub has
no API for changing those settings or submitting executable actions.

## Verify and operate

On the hub:

```sh
sudo systemctl status firefighter-hub nginx
sudo journalctl -u firefighter-hub -f
curl --fail https://45.76.243.18/healthz
curl --fail https://45.76.243.18/api/v1/status
curl --fail --head https://45.76.243.18/faq
curl --fail --head https://45.76.243.18/install.sh
```

Also verify that curl receives identical installer bytes at `/` and `/install.sh`,
a browser User-Agent receives HTML at `/`, and both root responses include
`Cache-Control: no-store` and `Vary: User-Agent`.

`/healthz` checks process liveness. Inspect source `state`, `last_success`, and
`error_code` in `/api/v1/status` to assess actual intake. X may be degraded because
credentials, paid access, or query permissions are unavailable; the other sources
can continue. A client's successful signed poll does not prove every upstream
source is healthy. Current per-source health is presented by the hub and board.

On a client server, use `firefighter doctor`, `firefighter status`, and the
`firefighter` systemd journal with its configured environment. Keep routine host
reviews enabled: a central notice is not required for the local model to detect
existing exposure or suspicious evidence. Signed retention gaps are explicitly
queued as local coverage-gap incidents before the client resumes retained history.

Monitor hub state size, retained notice count, disk space, and upstream rate-limit
health. Retention bounds public history, while the responder's audit has its own
retention/archival requirements. Source polling and client feed requests do not
need additional active hub instances; running duplicate ingesters can duplicate
paid upstream usage. Keep backups of hub state and signing identity outside the
public webroot. See [the broadcast protocol](broadcast.md) for cursor and recovery
semantics and [the trust model](threat-model.md) for responder limitations.
