# Grok Bot reporting plugin

This plugin forwards Firefighter reports to a configurable **Grok Bot routine webhook**. It is a small standalone Go bridge, with no external dependencies, and runs separately from the root responder.

For a new installation, choose **Grok Bot** in the installer's final messaging step. It asks for the routine URL and key, tests delivery, and sends directly to the routine without this bridge. See [interactive setup](../../README.md#connect-grok-bot). The bridge below remains useful for existing signed-webhook integrations and a receiver hosted separately from the protected server.

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

   The URL and token are installation settings; do not place them in a prompt or commit them. To put the URL in JSON instead, set `routine_url` and set `routine_url_env` to an empty string. The shipped configuration and executable defaults report startup, source and assessment health failures/recovery, and finished assessments. `include_types` can change which event types wake the bot; an explicit empty list means all events. The responder still records all events locally.

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

Grok Bot routine limits can constrain high-volume reporting. The bridge's default `include_types` is `["started", "source_error", "source_recovered", "assessment_health_error", "assessment_health_recovered", "assessment_finished"]`; completed assessments include compromise status, remediation failures and deferred work in `event.details`. Add `stopped` for shutdown events and `action_finished` for command outcomes, or use an empty list for all events. Existing explicit `include_types` settings need the two assessment health event names to receive these new aggregate reports. Bridge filtering selects event types, not assessment severity. A successful webhook means accepted, not that a user saw the report or that the reporting routine completed.

Most advisories do not affect a given host. Applicability investigations stay in the local audit, including failed probes and deferred decisions, until the client confirms that the host is affected. A WordPress advisory on a server without WordPress therefore sends no monitoring message. This applies before events enter any external reporting channel, including the signed-webhook bridge. Initial host audits and daemon/source health reports remain visible.

Repeated inability to determine applicability generates one aggregate `assessment_health_error` after three consecutive unresolved assessments. Reminders require at least ten more failures and thirty minutes; counters survive restarts. A completed assessment that resolves applicability ends the streak and sends `assessment_health_recovered` only if a health alert was raised. These events carry `health_scope: advisory_applicability` and `failure_count`, without an advisory ID or raw error. Requested shutdown interruptions do not count. A health alert means investigation needs attention, not that the host is vulnerable or compromised.

Once applicability is confirmed, the installer's direct Grok Bot integration reports declared changes, failed checks, recovery actions, and actionable assessment results. Passing checks whose parent explicitly declares no changes stay local. Real changes and previously reported activity still get an outcome report even if a later verdict is `not_affected`; applicability filtering must not conceal changes or leave a reported incident without closure.

New events identify the advisory/CVEs, daemon `run_id`, build `version` and incident `attempt`. `applicability_status` is `unknown`, `affected`, or `not_affected`; it concerns this advisory on this host, not whether the host is generally secure. `parent_action_id` connects a check to its action; `parent_mutates` states the parent's declared behavior. A verification event's `verified` and `check_outcome` describe command success, not software presence or remediation. The final assessment's `remediation_verified` is separate. `status: completed` says the assessment finished; check `assessment` for remaining exposure and `assessment_scope` for host versus advisory scope. `changed_this_attempt` tracks mutation-declared commands run in the latest attempt; `changed` includes retained incident history. Neither proves success: a failed command may still have changed state partially.

Direct reports keep bounded summaries, follow-up, and evidence without exporting raw command output, arguments, or environments. The structured `event` may contain more detail than `message`; `clipped_fields` and array omission counts make truncation explicit. Chat messages also mark when their provider limit shortens them. Full local evidence remains in the protected host's audit. The optional bridge preserves its incoming signed event contract; use the structured `event` when its short rendered message lacks context.

## Validation

```sh
go test ./plugins/grokbot/...
```

Tests use local HTTP fixtures and temporary state files. They do not call Grok Bot or require credentials.
