# Deployment

The public deployment uses [https://45.76.243.18/](https://45.76.243.18/) for the
notice board, [FAQ](https://45.76.243.18/faq), [signed notices](https://45.76.243.18/api/v1/notices), and
[source health](https://45.76.243.18/api/v1/status). The status endpoint is the
source of truth for upstream availability. The hosted deployment and default hub
configuration use Ubuntu notices, CISA KEV, and NVD. Paid X intake is currently
disabled to stop API spend; the integration remains available as an opt-in source.

The hub collects public advisory data once. Subscribers receive signed notices,
then use their own inventory, model credentials, and local root runner to assess
and repair their servers. The hub has no action, shell, policy-update, approval,
or remote-remediation endpoint. Subscription does not upload client inventory,
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
| Public bootstrap | `/opt/firefighter/install.sh`, served only at `/install.sh` |
| Public downloads | `/opt/firefighter/downloads`, served directly by nginx |
| ACME challenge webroot | `/var/lib/letsencrypt` |
| Administrator access | SSH alias `firefighter-host`, user `firefighter-admin` |

Root SSH login is disabled in this deployment. Administrator access uses a
dedicated SSH key and sudo. An equivalent local SSH entry is:

```sshconfig
Host firefighter-host
    HostName 45.76.243.18
    User firefighter-admin
    IdentityFile ~/.ssh/firefighter_vps_ed25519
    IdentitiesOnly yes
```

That path names a local private key; neither the key nor its contents belongs in
this repository, the website, or the download directory. For another deployment,
replace the IP address, administrator account, and local identity path.

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
`X-Forwarded-For` with nginx's observed client address, and serves downloads
directly from `/opt/firefighter/downloads`. The exact `/install.sh` route serves
only `/opt/firefighter/install.sh` as plain text; it does not expose the deployment
directory. The hub maps `/faq` and `/faq/` to the public `faq.html` asset. These web
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

## Publish downloads and the public key

Only public release artifacts belong in the download directory. Publish both
responder architectures, the bootstrap configuration, environment template,
service, and public key before generating their checksum manifest:

```sh
sudo install -m 0644 dist/firefighter-linux-amd64 dist/firefighter-linux-arm64 \
  /opt/firefighter/downloads/
sudo install -m 0644 deploy/firefighter-config.json \
  /opt/firefighter/downloads/firefighter-config.json
sudo install -m 0644 deploy/firefighter-bootstrap.env.example \
  /opt/firefighter/downloads/firefighter.env.example
sudo install -m 0644 deploy/firefighter.service \
  /opt/firefighter/downloads/firefighter.service
sudo -u firefighter-hub /usr/local/bin/firefighter-hub public-key \
  --config /etc/firefighter-hub/config.json \
  | sudo tee /opt/firefighter/downloads/firefighter-hub.pub >/dev/null
(cd /opt/firefighter/downloads && sha256sum \
  firefighter-linux-amd64 firefighter-linux-arm64 firefighter-config.json \
  firefighter.env.example firefighter.service firefighter-hub.pub) \
  | sudo tee /opt/firefighter/downloads/SHA256SUMS >/dev/null
sudo install -m 0644 deploy/bootstrap.sh /opt/firefighter/install.sh
```

The `public-key` command prints only the public Ed25519 key. The public download
lets clients obtain that key, but they should compare it with an independently
verified operator value before pinning it. Ensure the public configuration and
bootstrap's embedded publisher pin both match that verified key; the installer
rejects a mismatched template and preserves existing client pins. The bootstrap verifies downloaded
artifacts against `SHA256SUMS`; a manifest fetched from the same server does not
independently authenticate a release. Publish only reviewed configuration without
credentials, and keep real environment files outside these public paths.

## Configure a subscribing Ubuntu server

From an interactive Ubuntu terminal:

```sh
curl -fsSL https://45.76.243.18/install.sh | sudo bash
```

On the first installation, type this exact sentence when prompted:

```text
I understand the risks and that this might delete my entire server.
```

The prompt reads `/dev/tty`, not the piped script. No terminal or a different
sentence causes an exit before writes. A successful installation stores a
root-owned, mode `0600` acknowledgment at
`/etc/firefighter/install-risk-acknowledgment`; a valid record skips this prompt on
later upgrades. This does not add runtime approvals to the autonomous responder.

The bootstrap selects amd64 or arm64, preserves existing configuration and
secrets, and does not start or restart the daemon. Its new-install configuration already
subscribes to the central signed feed and uses OpenRouter's
`deepseek/deepseek-v4.1-flash-1017` with `OPENROUTER_API_KEY`. Review the installed
publisher pin, then configure credentials and run the service using the
[Ubuntu setup instructions](../README.md#run-on-ubuntu). The binary bootstrap does
not install the Grok Bot bridge; the source installer includes it.
After upgrading a configured, running responder, restart it separately at an
appropriate point to load the new binary.

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
      "interval_seconds": 30
    }
  ],
  "llm": {
    "backend": "api",
    "base_url": "https://openrouter.ai/api/v1",
    "model": "deepseek/deepseek-v4.1-flash-1017",
    "api_key_env": "OPENROUTER_API_KEY",
    "timeout_seconds": 180,
    "json_mode": true
  }
}
```

This is a configuration fragment, not a full replacement for the responder's
execution and state settings. The shown provider/model is the selected deployment
configuration; the provider remains configurable. Put the corresponding model
credential in `/etc/firefighter/firefighter.env`, with mode `0600`. Each client
uses its own model access and makes local decisions. Shared-feed clients need no
X or NVD key for intake and do not poll those upstream feeds directly.

`json_mode` requests JSON-object responses while retaining the same strict local
decision validation, command limits, and mandatory mutation verification. The
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

`/healthz` checks process liveness. Inspect source `state`, `last_success`, and
`error_code` in `/api/v1/status` to assess actual intake. X may be degraded because
credentials, paid access, or query permissions are unavailable; the other sources
can continue. A client's successful signed poll does not prove every upstream
source is healthy. Current per-source health is presented by the hub and board.

On a subscribing server, use `firefighter doctor`, `firefighter status`, and the
`firefighter` systemd journal with its configured environment. Keep routine host
reviews enabled: a central notice is not required for the local model to detect
existing exposure or suspicious evidence. Signed retention gaps are explicitly
queued as local coverage-gap incidents before the client resumes retained history.

Monitor hub state size, retained notice count, disk space, and upstream rate-limit
health. Retention bounds public history, while the responder's audit has its own
retention/archival requirements. Source polling and client subscriptions do not
need additional active hub instances; running duplicate ingesters can duplicate
paid upstream usage. Keep backups of hub state and signing identity outside the
public webroot. See [the broadcast protocol](broadcast.md) for cursor and recovery
semantics and [the trust model](threat-model.md) for responder limitations.
