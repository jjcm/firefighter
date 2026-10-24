# Shared advisory broadcast

The hub pays for and polls X once, alongside CISA KEV, NVD, and Ubuntu security
notices. Servers subscribe to its signed notice feed instead of each maintaining
an X subscription. Each server retains its own local inventory, evidence,
planner, execution policy, and remediation decisions.

The hub publishes **untrusted advisory data only**. Its wire format contains no
actions, commands, argument arrays, execution policies, or remote-control fields.
A valid signature establishes who published a notice; it does not make advisory
text true or safe to execute. No server inventory, credentials, scans, command
output, or private incident history is sent to the hub by subscribing clients.
The hub does not call an LLM and never performs remediation.

## Run the hub

Build `./cmd/firefighter-hub` and install its binary as
`/usr/local/bin/firefighter-hub`. The service account `firefighter-hub` must exist.
Install `configs/hub.example.json` at `/etc/firefighter-hub/config.json`, readable
by that account. Install the website at the configured absolute `website_dir`.
The hub serves only ordinary web asset extensions, never directory listings or
symlinks escaping that directory. Its state directory must not overlap the site.

Put upstream credentials in `/etc/firefighter-hub/firefighter-hub.env`, a
root-owned file with mode `0600`:

```dotenv
X_BEARER_TOKEN=your-X-API-bearer-token
NVD_API_KEY=your-optional-NVD-key
```

Configuration stores environment variable names, never credential values. X API
recent-search access is required. Without an X token, the hub keeps serving other
sources and reports that source as degraded with `error_code=not_configured`.
Missing NVD credentials use the public NVD API. Credential presence is not a
successful access check; the first upstream poll establishes source health.
The hub requests NVD records in pages of 500 by default; the NVD source accepts
`page_size` from 1 to 2000. Smaller pages can avoid the request deadline when NVD
is slow; the six-second delay between pages still respects the public API budget.

Initialize the signing key once, as the service account after creating and
assigning ownership of `/var/lib/firefighter-hub`:

```sh
sudo -u firefighter-hub /usr/local/bin/firefighter-hub init-key --config /etc/firefighter-hub/config.json
sudo -u firefighter-hub /usr/local/bin/firefighter-hub public-key --config /etc/firefighter-hub/config.json
```

Both commands print only the public key, encoded as standard base64 of 32 bytes.
`init-key` refuses to replace an existing key. Back up the private
`/var/lib/firefighter-hub/signing.key` and durable `hubstate.json` together. The
private key and state files use mode `0600`, inside a `0700` state directory.
Do not put either in the website directory or publish the private key.

Install `deploy/firefighter-hub.service`, reload systemd, and start the service.
The hub runs without root remediation privileges and binds `127.0.0.1:8090`.
Public access requires an HTTPS reverse proxy with a certificate matching the
domain or IP clients use. Never disable certificate verification. A private CA
may be distributed explicitly to clients when appropriate.

For nginx, proxy the site and APIs to the loopback listener and overwrite the
client-address header used by the hub's rate limiter:

```nginx
location / {
    proxy_pass http://127.0.0.1:8090;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 5s;
    proxy_read_timeout 35s;
}
```

Provision TLS separately and restrict access to the private environment/config
files. `firefighter-hub check --config ...` checks local configuration and key
format without calling paid upstream APIs. Actual service health is available at
`/api/v1/status`; `/healthz` reports process liveness, not upstream coverage.

## Signed notice protocol, version 1

`GET /api/v1/notices?after=42&limit=100` returns:

```json
{"key_id":"16-lowercase-hex-characters","payload":"BASE64_JSON_BYTES","signature":"BASE64_ED25519_SIGNATURE"}
```

The signature covers the exact decoded `payload` bytes. Verify against an
independently obtained, pinned public key; do not reconstruct JSON before
verification or accept a public key supplied alongside an untrusted response.
`key_id` is the first 16 hexadecimal characters of SHA-256 of the raw public key.
Payload serialization has fixed field order and contains these fields:

```json
{
  "version": 1,
  "kind": "notices",
  "after": 42,
  "oldest": 1,
  "latest": 44,
  "next_cursor": 44,
  "has_more": false,
  "reset_required": false,
  "reset_to": 0,
  "server_time": "2026-10-24T12:00:00Z",
  "notices": [
    {
      "seq": 43,
      "source": "ubuntu-usn",
      "id": "upstream-advisory-id",
      "title": "Security advisory",
      "summary": "Untrusted upstream advisory excerpt",
      "url": "https://ubuntu.com/security/notices",
      "cves": [],
      "published_at": "2026-10-24T11:00:00Z",
      "observed_at": "2026-10-24T11:59:00Z",
      "untrusted": true
    },
    {
      "seq": 44,
      "source": "x",
      "id": "upstream-post-id",
      "title": "Possible early disclosure",
      "summary": "No CVE assignment is required for ingestion",
      "url": "https://x.com/i/web/status/123456789",
      "cves": [],
      "published_at": "2026-10-24T11:20:00Z",
      "observed_at": "2026-10-24T11:59:00Z",
      "untrusted": true
    }
  ]
}
```

Notices are in strictly increasing, contiguous sequence order. `next_cursor`
equals the last returned sequence, or the requested `after` when no notices are
returned. For ordinary responses, `has_more` is exactly `next_cursor < latest`.
The oldest and latest values describe that request's durable snapshot; newer
notices can arrive between pages. A client can capture the first page's latest
sequence and catch up to that position before starting another polling cycle.
`limit` is 1–500, default 100. A response can contain fewer notices to keep the
raw signed payload near 1 MiB and its base64 envelope below 2 MiB.

All listed fields are always present. Empty `notices` and `cves` are arrays,
never null. Times use UTC RFC3339; `published_at` may be Go's zero timestamp when
the upstream feed has no date. Text limits in UTF-8 bytes are source 128, ID 256,
title 512, summary 4096, URL 2048; there are at most 64 CVE identifiers, each at
most 64 bytes. Summary text is bounded raw source content, not a trusted LLM
analysis. Links are restricted to HTTP(S) without embedded user credentials.

Clients must reject unexpected/duplicate fields, bad signatures, wrong key IDs,
unsupported versions, invalid ranges/order, and stale or replayed checkpoints.
They persist received notices before, or atomically with, their local cursor.
The server has no per-subscriber consumption state: many clients can replay the
same signed range without triggering another X or official-source request.

## Retention, gaps, and recovery

The default retained window is seven days and at most 100,000 notices. A 128 MiB
serialized checkpoint budget may expire additional oldest notices when summaries
or cursor metadata are large. Small servers should configure `max_notices: 10000`.
The global
sequence counter is never reused when older notices expire. A new empty hub has
`oldest=0, latest=0`; a previously populated but now expired hub has
`oldest=latest+1`. Retention runs during scheduled upstream polls.

If `after < oldest-1`, or `after > latest`, the hub returns a **signed** response
with `reset_required=true`, empty notices, `next_cursor=after`, `has_more=false`,
and `reset_to=oldest-1` (zero for a new empty hub). Clients must surface this as
a coverage gap. Firefighter durably queues a factual coverage-gap notice and its
reset checkpoint, then resumes retained history on its next poll. This preserves
availability without pretending missing historical notices were assessed.

Hub ingestion atomically saves upstream cursors with published notices, sequence,
and sanitized source health. A failed upstream request or failed checkpoint does
not advance its cursor. A process lock prevents two local hub instances from
polling the same state directory. Run one active hub for the paid X subscription;
independent state directories or machines are independent ingesters and would
consume additional API usage. Source URL/query changes use a new cursor namespace.

X's first poll uses a fixed `start_time`/`end_time` window. Subsequent polls use
`since_id` and an exclusive `until_id` derived from the same 30-second-delayed
end time using Twitter's Snowflake epoch and timestamp bits. This avoids the
live API's rejection of mixed ID/time bounds while keeping pagination stable.
Invalid bounds or failed pages retain the previous cursor and publish no partial
batch.

X recent search itself covers only seven days. RSS feeds may retain less history.
The hub cannot reconstruct upstream history already dropped during an outage.
Backups of an older hub state can also move its advertised latest sequence behind
subscriber checkpoints; the signed gap path exposes this rather than hiding it.

`GET /api/v1/status` exposes only public source names, health states, timestamps,
failure counts, published-notice counts, error codes, and retention/sequence
metadata. It omits upstream URLs, queries, credential environment names, private
cursor values, raw error messages, and all subscriber host information. The
status endpoint and website board are informational; clients authenticate notice
batches using their pinned signature key. Updates use efficient polling; no SSE
connection or paid upstream request is created for an individual subscriber.

Changing signing identity requires intentionally distributing a new pinned
public key. A signature cannot provide protection if the hub and its private
signing key are both compromised; local responders must still treat every notice
as evidence to investigate, never as authority to run commands.

## Public notice board

`GET /api/v1/recent?limit=60` provides an informational, unsigned board view:

```json
{"version":1,"kind":"recent_notices","server_time":"2026-10-24T12:00:00Z","notices":[]}
```

Each notice uses the same data-only notice schema. The view sorts by publication
time descending, using observation time only when publication time is missing,
and sequence descending to break ties. `limit` defaults to 60 and is capped at
100; the response is also bounded near 1 MiB. This prevents a large historical
catalog import from hiding newly published advisories on the website. Clients
continue to use `/api/v1/notices` for authenticated sequential delivery; the board
does not reorder stored records or change any source or subscriber cursor.
