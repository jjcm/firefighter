# Vulnerability intake

Every source implements `Source.Name()` and `Source.Poll(ctx, cursor)`. Cursors
are opaque and belong to one configured source. Persist returned items durably
before, or atomically with, the returned cursor. Replaying items after a crash is
expected; the caller must deduplicate using source, item ID, and content/version.

On request, parsing, pagination, or page-limit errors, `Poll` returns no items,
an error, and exactly the input cursor. This intentionally retries the complete
window rather than marking unseen pages as ingested. A page-limit error requires
increasing the configured limit or narrowing a noisy X query; it must be reported
as a degraded intake source. Poll sources independently so one outage does not
delay the others. There is no internal retry loop that hides upstream failures.

All requests have a maximum 45-second timeout and a 32 MiB response limit.
Redirects are rejected, including for supplied HTTP clients, to avoid forwarding
credentials. Remote source URLs require HTTPS; localhost HTTP supports local
feed bridges and test fixtures. Response bodies are never executed. `Trust` is
provenance metadata, not permission to execute commands embedded in a source.

## Sources

* `NewKEV(KEVConfig)` reads the [official CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json).
  Zero `Lookback` ingests the entire catalog at first boot; a positive duration
  restricts only first-boot historical items. The snapshot cursor detects edits
  to existing records, including old records, rather than relying on `dateAdded`.
  The full original entry is retained in `Body`, including vendor instructions,
  references, ransomware indicators, and forensic-triage fields if present.
* `NewNVD(NVDConfig)` reads [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities).
  Default initial lookback is 24 hours, overlap is five minutes, page size is
  2,000, and maximum pages is 100. The time range is fixed across pages. Extended
  outages catch up in windows shorter than NVD's 120-day maximum. The default
  six-second inter-page interval respects the unauthenticated request budget;
  the caller must also avoid rapid repeated polls. Set `APIKey` if available.
  Raw CVE records retain affected-product configurations, metrics, and references.
  Publication or database inclusion is not proof the host is vulnerable.
* `NewX(XConfig)` reads [X recent search](https://docs.x.com/x-api/posts/search-recent-posts)
  using an API bearer token and an account with access to that endpoint.
  Default lookback is 24 hours; max pages is 100 with 100 posts per request.
  The default query includes CVEs, zero days, security advisories, remote code
  execution, and active exploitation. Posts without CVE assignments are retained.
  Expanded URLs are retained as references, not followed automatically. Following
  [X pagination guidance](https://docs.x.com/x-api/posts/search/integrate/paginate),
  the same `since_id` is held across pages and the new high-water ID is committed
  only after the final page. X recent search covers only the preceding seven
  days: downtime or a backlog beyond that retention window cannot be recovered
  by this adapter. It is not a firehose or an assurance of complete coverage of X.
* `NewFeed(FeedConfig)` reads RSS 2.0, RSS/RDF, and Atom vendor feeds. Configure a
  unique name, URL, and optional provenance (`Trust`, default `vendor`). Content
  hashes detect changes to IDs even if dates do not change. Feeds often expose
  only their latest entries; long outages can exceed their retained history.

An empty successful X page retains its prior ID cursor. NVD advances to the end
of a successfully completed time window even if no records were returned.
KEV/feed snapshot cursors retain at most 2 MiB of IDs and content hashes.

Changing the meaning of a configured source (for example, an X query or feed
URL) requires resetting that source's cursor to ingest its new lookback/history.
No source can establish that a machine is uncompromised; intake supplies evidence
for host inventory, vulnerability assessment, investigation, and response.
