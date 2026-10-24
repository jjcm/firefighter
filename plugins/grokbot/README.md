# Grok Bot reporting plugin

This plugin forwards Firefighter reports to a configurable **Grok Bot routine webhook**. It is a small standalone Go bridge, with no external dependencies, and runs separately from the root responder.

The integration uses the official [Grok Bot routine webhook contract](https://cursor.com/help/grok-bot/routines#where-do-the-webhook-url-and-key-live-and-what-does-a-200-mean): JSON POST to the URL shown in the routine, authenticated with its bearer key. HTTP 200 means the routine accepted the event and started, not that it finished. The [Grok Bot documentation](https://docs.x.ai/grok-bot/skills-routines-and-automations) links to that contract. No public native runtime plugin SDK was established from these official docs, so this package does not claim to be an installable Connect apps catalog entry or invent a native manifest. The separately named open-source `GrokBot` projects are not used.

## Install and configure

1. Build from the repository root:

   ```sh
   go build -o bin/firefighter-grokbot ./plugins/grokbot/cmd
   ```

2. Create a Grok Bot routine using the instructions in [routine.md](routine.md), and add a webhook trigger. The routine's **Webhook** panel provides its URL and key.

3. Copy [config.example.json](config.example.json) to `/etc/firefighter-grokbot/config.json`. Store these environment variables in `/etc/firefighter/grokbot.env`, mode `0600`:

   ```text
   FIREFIGHTER_REPORT_SECRET=<same random secret as the Firefighter daemon; at least 32 characters>
   GROKBOT_ROUTINE_URL=<the URL shown in the routine>
   GROKBOT_ROUTINE_TOKEN=<the key shown in the routine>
   ```

   The URL and token are installation settings; do not place them in a prompt or commit them. To put the URL in JSON instead, set `routine_url` and set `routine_url_env` to an empty string. The shipped configuration and executable defaults report startup, source failures/recovery, and finished assessments. `include_types` can change which event types wake the bot; an explicit empty list means all events. The responder still records all events locally.

4. Set Firefighter's report configuration to the plugin:

   ```json
   { "report": { "url": "http://127.0.0.1:9087/events", "secret_env": "FIREFIGHTER_REPORT_SECRET" } }
   ```

5. Install the binary at `/usr/local/bin/firefighter-grokbot`, install the included service in `/etc/systemd/system/`, and enable it:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now firefighter-grokbot
   ```

The plugin defaults to a loopback listener. For a receiver on a separate server, terminate TLS at your private gateway and point the daemon to the HTTPS `/events` URL. This also keeps the reporting token outside a potentially compromised protected host. No inbound command channel is exposed; Grok Bot receives reports only and does not gate remediation.

## Wire contract

The daemon sends the event JSON unchanged to `/events` with:

```text
X-Firefighter-Timestamp: <Unix seconds>
X-Firefighter-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + rawBody)>
Idempotency-Key: <event.id>
```

The plugin compares the HMAC in constant time, rejects timestamps more than five minutes away, bounds request size to 1 MiB, and validates the event. An event contains `id`, `time` (RFC3339), `host`, `type`, `summary`, optional `incident_id`, and optional `details`. The plugin forwards this JSON object to the configured Grok Bot webhook:

```json
{
  "source": "firefighter",
  "message": "Firefighter · assessment_finished · event-id\nHost: host-name\n...",
  "event": {
    "id": "event-id",
    "time": "2026-10-24T00:00:00Z",
    "host": "host-name",
    "type": "assessment_finished",
    "incident_id": "incident-id",
    "summary": "Updated the exposed package; service checks passed. Compromise assessment remains uncertain."
  }
}
```

Only HTTP 200 from Grok Bot is acknowledged to the daemon as delivered. Failures return non-2xx so Firefighter can retry its durable outbox. Downstream errors and secrets are not logged. The plugin disables redirects so the bearer key and report cannot move to another endpoint silently. It persists successful host/event IDs for up to seven days or the latest 10,000 events and deduplicates concurrent delivery. Delivery is **at least once**, because a network interruption or crash after downstream acceptance can happen before local persistence; the routine should also use `event.id` for deduplication. The HTTP `Idempotency-Key` header is supplied, but Grok Bot does not document honoring it.

Grok Bot routine limits can constrain high-volume reporting. The default `include_types` is `["started", "source_error", "source_recovered", "assessment_finished"]`; completed assessments include compromise status, remediation failures and deferred work in `event.details`. Add `action_finished` to receive each command's outcome, or use an empty list for all events. Filtering selects event types, not the severity of assessments. A successful webhook means accepted, not that a user saw the report or that the reporting routine completed.

## Validation

```sh
go test ./plugins/grokbot/...
```

Tests use local HTTP fixtures and temporary state files. They do not call Grok Bot or require credentials.
