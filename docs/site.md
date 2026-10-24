# Public site

The static site in `web/` is served by the hub on `/`. It has no build step, package dependencies, third-party scripts, remote fonts, analytics, or secrets. Deploy `index.html`, `faq.html`, `styles.css`, `app.js`, and `assets/` together. The hub maps `/faq` and `/faq/` to `faq.html`; `/faq.html` also works. The hub and static assets must share an HTTPS origin.

## Design

The design follows option D from the [Firefighter Diffui project](https://diffui.ai/app/canvas/93a6765f-2c38-473f-88af-84fb52283487): warm black, off-white type, fire-orange accents, the supplied fire illustration, process, a single-command installation section, and a live disclosure board with compact source health above the footer. [Build instructions](https://diffui.ai/api/agent-build/0e7ed540-80fc-4299-8cc9-745a41925e27/instructions) are the implementation reference. The flame mark was generated through the same Diffui build. Generated reference images and local QA fixtures belong in ignored `.diffui/`, not the public directory.

## Live data and trust

The page polls `GET /api/v1/status` and `GET /api/v1/recent?limit=60` every 30 seconds while visible. The display endpoint includes notices only from currently configured sources; disabling a source preserves signed history but removes it from this active display. It returns plain JSON `{version:1, kind:"recent_notices", notices:[...], server_time:"..."}` containing the most recent 60 notices by publication date. The browser also sorts publication dates descending, with sequence numbers breaking ties, so historical backfill cannot dominate the board merely because it was imported last. Missing publication dates sort last; fallback observation times are labeled “Seen.” Dates before 1970 are treated as unavailable, and older calendar years remain visible. Local search, source filtering, detail expansion, and pagination operate on this recent selection. Feed failures keep previously loaded notices clearly marked as stale; unavailable source coverage never appears healthy.

The browser uses an unsigned endpoint **for display only**. It does not authenticate signatures or claim a trusted key. Host agents consume the separate signed cursor feed at `/api/v1/notices` and verify signatures against independently pinned Ed25519 keys. All notice fields are untrusted text rendered with `textContent`; source URLs must use HTTP(S) without embedded credentials. The page does not execute notices, accept remote instructions, send commands to agents, or publish host inventory, incidents, logs, keys, or private network details. The hero artwork is illustrative; the page does not show fleet telemetry.

API responses are limited to 3 MiB and an eight-second deadline. Missing X credentials appear as “Credential not configured” from actual hub status. No sample notices or invented security statistics are shipped.

Official NVD lifecycle updates also hide rejected, withdrawn, or revoked CVEs from the public board, including older notices that mention those CVEs. Retractions are remembered across restarts; a newer official reinstatement can restore eligible notices. Coverage depends on the configured NVD feed having observed the status change. Signed client history and cursor sequences remain intact so clients can reassess earlier reports. The hub's private checkpoint now includes lifecycle metadata; back up the stopped hub's state before upgrading and restore that checkpoint if rolling back to an older binary.

## Interactive source installation

The public quickstart has one command:

```sh
curl -fsSL https://45.76.243.18/install.sh | sudo bash
```

The landing page gives the experimental-use warning and a link to the FAQ. The exact first-install risk acknowledgment appears in the interactive installer, not as a second step on the page. The prompt reads `/dev/tty`, so piped script input cannot answer it. No terminal or a mismatched sentence aborts before writes. After successful startup, the acknowledgment is stored in root-owned mode `0600` at `/etc/firefighter/install-risk-acknowledgment`; a valid record skips it on upgrades. Runtime operation still has no approval prompts.

The installer fetches an exact reviewed commit from the [public GitHub repository](https://github.com/jjcm/firefighter), verifies the checked-out revision, and builds the responder and optional Grok Bot bridge locally. It does not download prebuilt Firefighter executables. It uses an existing compatible Go compiler or a checksum-verified official Go archive in a private temporary directory. The installation target is Linux with a running systemd manager and a Go-supported host architecture.

Compilation uses a private `/var/tmp` workspace with Go's scratch directories and caches redirected there, rather than filling a small RAM-backed `/tmp`. The installer requires 2 GiB free on that filesystem and checks this before downloads or provider setup. It compiles packages one at a time and removes the workspace when finished.

Interactive setup offers OpenRouter by default, OpenAI, and Anthropic, allows a model override, and reads the API key without echoing it. A successful build and local configuration check enables and starts the root responder. Existing complete configuration and credentials are preserved; successful upgrades restart the responder. Grok Bot reporting remains optional and needs a separately configured destination. The page therefore has no separate Configure or Run tabs.

The same-origin distribution routes are limited to:

- `/install.sh`, served from the reviewed `deploy/bootstrap.sh`.
- `/downloads/firefighter-hub.pub`, the publisher's public Ed25519 key.

The copyable command points at the public deployment. The public key download is a distribution convenience, not independent proof of authenticity. Verify the pin over a separate trusted channel. The installer is a separate download initiated by an operator; executable instructions never enter the signed notice protocol.

The [FAQ](https://45.76.243.18/faq) describes autonomous operation, costs, and limitations. Model credentials stay in each client's root-only environment file. Relevant local observations are sent to the selected model API, with best-effort secret redaction.

## Hosting and checks

Use a restrictive Content Security Policy such as `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'`, plus `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. Do not place configuration, credentials, hub state, or audit files under the static directory. Do not serve prebuilt client binaries or expose the source checkout through the website.

nginx serves the exact `/install.sh` route from `/opt/firefighter/install.sh`, copied from `deploy/bootstrap.sh`. Only the exact public-key download path is allowed; the old general `/downloads/` route is disabled. nginx does not expose the deployment directory or add shell files to the hub's static extension allowlist. Other API paths retain their existing strict routing and notice schema.

Local preview: `python3 -m http.server 4173 --bind 127.0.0.1 --directory web`. The feed honestly shows unavailable unless an API is supplied on that origin. Check JavaScript syntax with `node --check web/app.js`. Inspect desktop and mobile layouts after changes, including the compact source badges and installation command. Exercise search, source filters, pagination, degraded-source state, literal hostile HTML text, and rejection of `javascript:` source links. Verify that publication ordering overrides ingestion order, sequence breaks publication-time ties, historical years remain visible, and zero dates never produce source-success tooltips.
