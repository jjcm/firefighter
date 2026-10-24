# Public site

The static site in `web/` is served by the hub on `/`. It has no build step, package dependencies, third-party scripts, remote fonts, analytics, or secrets. Deploy `index.html`, `faq.html`, `styles.css`, `app.js`, and `assets/` together. The hub maps `/faq` and `/faq/` to `faq.html`; `/faq.html` also works. The hub and static assets must share an HTTPS origin.

## Design

The design follows option D from the [Firefighter Diffui project](https://diffui.ai/app/canvas/93a6765f-2c38-473f-88af-84fb52283487): warm black, off-white type, fire-orange accents, a shared-intake diagram, live disclosure board, process, and installation instructions. [Build instructions](https://diffui.ai/api/agent-build/0e7ed540-80fc-4299-8cc9-745a41925e27/instructions) are the implementation reference. The flame mark was generated through the same Diffui build. Generated reference images and local QA fixtures belong in ignored `.diffui/`, not the public directory.

## Live data and trust

The page polls `GET /api/v1/status` and `GET /api/v1/recent?limit=60` every 30 seconds while visible. The display endpoint includes notices only from currently configured sources; disabling a source preserves signed history but removes it from this active display. It returns plain JSON `{version:1, kind:"recent_notices", notices:[...], server_time:"..."}` containing the most recent 60 notices by publication date. The browser also sorts publication dates descending, with sequence numbers breaking ties, so historical backfill cannot dominate the board merely because it was imported last. Missing publication dates sort last; fallback observation times are labeled “Seen.” Dates before 1970 are treated as unavailable, and older calendar years remain visible. Local search, source filtering, detail expansion, and pagination operate on this recent selection. Feed failures keep previously loaded notices clearly marked as stale; unavailable source coverage never appears healthy.

The browser uses an unsigned endpoint **for display only**. It does not authenticate signatures or claim a trusted key. Host agents consume the separate signed cursor feed at `/api/v1/notices` and verify signatures against independently pinned Ed25519 keys. All notice fields are untrusted text rendered with `textContent`; source URLs must use HTTP(S) without embedded credentials. The page does not execute notices, accept remote instructions, send commands to agents, or publish host inventory, incidents, logs, keys, or private network details. The architecture drawing is explicitly illustrative, not fleet telemetry.

API responses are limited to 3 MiB and an eight-second deadline. Missing X credentials appear as “Credential not configured” from actual hub status. No sample notices or invented security statistics are shipped.

## Downloads and setup

The public quickstart begins with:

```sh
curl -fsSL https://45.76.243.18/install.sh | sudo bash
```

The first installation reads this exact acknowledgment from `/dev/tty`: `I understand the risks and that this might delete my entire server.` No terminal or a mismatched sentence aborts before writes. Successful installation records the acknowledgment in root-owned mode `0600` at `/etc/firefighter/install-risk-acknowledgment`; later upgrades with a valid record do not repeat it. The acknowledgment is an installation step, and the running responder still requires no approvals.

The bootstrap detects Ubuntu amd64/arm64, verifies downloaded artifact checksums internally, and installs the responder without starting or restarting it. It preserves existing configuration and secrets. New installations use the central signed feed and OpenRouter model `deepseek/deepseek-v4.1-flash-1017`, with `OPENROUTER_API_KEY` configured locally. The site's Configure and Run steps remain necessary; upgrades of a running service need a separate restart. Grok Bot's bridge is available through the source installer and is not included in this binary bootstrap.

The quickstart expects these same-origin files, provided by the deployment process:

- `/install.sh`, served from the reviewed `deploy/bootstrap.sh`
- `/downloads/firefighter-linux-amd64` and `/downloads/firefighter-linux-arm64`
- `/downloads/SHA256SUMS`
- `/downloads/firefighter-config.json`
- `/downloads/firefighter.service`
- `/downloads/firefighter.env.example`
- `/downloads/firefighter-hub.pub`

On HTTPS, copyable commands use the current origin. On a local HTTP preview they retain `YOUR_NOTICE_HUB`. The public key download is a distribution convenience, not independent proof of authenticity. Verify it over a separate trusted channel before pinning. Checksums fetched from the same origin detect mismatched artifacts but do not independently authenticate a release.

The [FAQ](https://45.76.243.18/faq) describes autonomous operation, costs, and limitations. The installer is a separate download initiated by an operator; executable instructions never enter the signed notice protocol.

The repository links currently require GitHub access. The site makes no public-source availability claim. Configure a compatible model API and credential environment variable on each host; local observations may leave the host for that API, with best-effort redaction.

## Hosting and checks

Use a restrictive Content Security Policy such as `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`, plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. Do not place configuration, credentials, hub state, or audit files under the static directory. Keep public downloads intentionally scoped.

nginx serves the exact `/install.sh` route from `/opt/firefighter/install.sh`, copied from `deploy/bootstrap.sh`. It does not expose the deployment directory or add shell files to the hub's static extension allowlist. Other API paths retain their existing strict routing and notice schema.

Local preview: `python3 -m http.server 4173 --bind 127.0.0.1 --directory web`. The feed honestly shows unavailable unless an API is supplied on that origin. JavaScript syntax was checked with `node --check web/app.js`; desktop and 390-pixel mobile layouts were inspected in Chrome. A separate, unshipped local fixture verified search, source filters, pagination, tab switching, degraded X status, literal hostile HTML text, and rejection of `javascript:` source links. The mobile page had no horizontal document overflow. A follow-up fixture confirmed publication ordering overrides ingestion order, sequence breaks publication-time ties, historical years remain visible, and zero dates never produce source-success tooltips.
