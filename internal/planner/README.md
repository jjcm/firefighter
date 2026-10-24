# Planner adapters

`Planner.Decide(context.Context, protocol.Request)` returns a validated `protocol.Decision`. There is no approval response type. The same protocol drives API and external command adapters.

## API

`NewAPI(APIConfig{Backend, BaseURL, Model, APIKey, Timeout, MaxActions, MaxResponseBytes, JSONMode})` supports OpenAI-compatible Chat Completions and native Anthropic Messages. The caller resolves the API key from an environment variable; this package neither provisions nor writes keys. HTTPS is required except for loopback development endpoints, redirects are disabled, and upstream bodies never appear in errors. The daemon validates the returned action protocol and executes it itself; the provider API receives no executable tool definitions.

### OpenAI and OpenRouter

Backend `api` (or an empty backend in the adapter) calls `<BaseURL>/chat/completions` with bearer authentication. OpenAI uses `https://api.openai.com/v1`; OpenRouter uses `https://openrouter.ai/api/v1`.

The default format uses [Chat Completions structured output](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat): `response_format.type=json_schema`, `strict=true`, required object fields, and `additionalProperties=false`. For a compatible provider using JSON-object mode, set `APIConfig.JSONMode=true`; local parsing and validation remain equally strict. Unsupported provider formats fail visibly instead of silently falling back to unstructured commands. Refusals, missing content, multiple choices, and completion reasons other than `stop` are rejected.

New installations default to OpenRouter with `deepseek/deepseek-v4.1-flash-1017` and schema-constrained output (`json_mode: false`). Requests to the exact official OpenRouter Chat Completions endpoint also set [`provider.require_parameters: true`](https://openrouter.ai/docs/guides/features/structured-outputs) so routing requires upstream support for the supplied output format. This provider-specific option is never sent to other endpoints. A provider failure does not trigger an automatic downgrade, output repair, or model switch; returned decisions still pass the full local validator.

Upgrades preserve existing configuration, including `json_mode: true`. Operators may explicitly opt into JSON-object mode for a provider that lacks schema support, but it constrains JSON syntax rather than the decision's shape and may produce more rejected decisions. Set `llm.json_mode` to `false` to request schema-constrained output on an existing installation. The OpenAI option defaults to [`gpt-6.1-sol`](https://developers.openai.com/api/docs/models/gpt-6.1-sol) with strict structured output. Operators can select a different model. Account access and model availability are only established by a successful API request, not by configuration validation.

### Anthropic

Backend `anthropic` calls `<BaseURL>/messages`; use `https://api.anthropic.com/v1` as the base URL. It sends the credential in `x-api-key` and sets `anthropic-version: 2023-06-01`. The request supplies the system policy separately, one user observation message, `max_tokens: 8192`, and [native structured output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs) through `output_config.format` with `type: json_schema` and the same decision schema. `json_mode: true` is invalid for this backend.

The interactive installer defaults to `claude-sonnet-5-5`, with a model override available. A response must be an assistant message with `stop_reason: end_turn` and exactly one nonempty text block containing the decision. Refusals, token-limit truncation, tool blocks, and unexpected content blocks fail closed. Thinking blocks are ignored rather than treated as decisions. The decision then passes the same strict local parser as every other provider.

API errors leave remediation unfinished and retryable, with no implied successful protection. Neither local configuration checks nor installer success establish that the account has access to its selected model.

## Command

`NewCommand(CommandConfig{Argv, Dir, Timeout, MaxActions, MaxResponseBytes, Env})` invokes an adapter directly, without an implicit shell. The executable and any working directory must be absolute so execution cannot depend on the daemon's ambient `PATH` or current directory. The adapter gets one `protocol.Request` JSON object on stdin and must write exactly one `protocol.Decision` to stdout. The `instructions` field includes Firefighter's incident response system policy, JSON schema, action limit, and the configured operator policy.

Only a fixed system `PATH`, locale, and `HOME` are inherited. `Env` explicitly adds the environment variables an adapter needs. Ambient API/reporting credentials are not inherited. The caller is responsible for resolving any explicitly authorized adapter credentials. Stderr is discarded to prevent provider debug dumps from leaking secrets into the daemon's reports. Linux/macOS cancellation kills the adapter's process group; detached descendants may escape this and adapters should not daemonize.

## Enforcement

Both adapters bound request/response size and runtime. Decisions reject unknown keys, duplicate keys, null values, trailing JSON, unsupported assessments, duplicate action IDs, missing mutability flags, and mutating commands with no verification. Only `kind: command` is supported. `argv`, `verify`, and `rollback` are argument arrays. `done: true` requires no pending actions, ensuring the engine has an opportunity to evaluate executed commands before completion.

The prompt directs operating-system and package revision checks, targeted signed package updates, source changes with tests, service and compromise checks, evidence preservation, and configured credential rotation. It treats posts, advisories and host output as untrusted facts, separates exposure from compromise, and forbids treating a clean scan as a clean-host guarantee. These instructions are not an OS sandbox: the root responder still executes model-authored commands under the owner's autonomy authorization.

Incoming-notice assessments stay scoped to the affected product. Unrelated posture findings go into follow-up and memory for the periodic host review; they do not turn an inapplicable CVE into an exposed one. Recent successful observations can be reused across related notices when their time, deployment coverage, and assumptions still apply. Expired or incomplete evidence, relevant changes, and contradictions need targeted refresh. Package-list absence alone does not rule out source or container deployments.

The request's `applicability_required` flag distinguishes incoming notices from periodic local-host reviews. Most notices are expected to be irrelevant to a particular server. The planner first reuses adequate scoped inventory or memory; sufficient evidence of absence or an unaffected version completes the notice without commands. When evidence is incomplete, only minimal targeted read-only observations are appropriate until the product and vulnerable condition are established. Installing diagnostic packages, general hardening, rotation, reboots, and unrelated changes are not applicability checks.

Every provider's decision schema requires `applicability`: an object with `status` (`unknown`, `affected`, or `not_affected`), `product` (at most 500 bytes), `condition` (at most 2000 bytes), and `evidence` (at most 16 nonempty strings, at most 2000 bytes each). Both resolved statuses require product, condition, and at least one local-evidence citation. `affected` must cite local presence and the relevant vulnerable version/configuration or prerequisite; severity or advisory text alone does not establish this. `not_affected` describes observed absence or a fixed/non-vulnerable state, including coverage. An unresolved condition stays `unknown`. After a relevant fix, applicability remains `affected` and the assessment becomes `remediated`.

The parser accepts omitted applicability in older/custom responses and stored decisions for compatibility; omission is not evidence and the engine treats it as unknown. A present object must be complete and valid. These structural checks cannot establish that the model's cited evidence is true or that a model-declared read-only command has no side effects. The prompt's evidence rules and the runtime applicability gate supplement the existing local audit; they do not sandbox the root agent.

Read-only observations normally leave `verify` empty and return their findings for the next decision. Verification belongs to mutations and must assert the fix and service health. The prompt distinguishes expected no-match results from command failures, including the observed failures from querying an absent package or searching a nonexistent directory. Neither the planner nor runner globally turns exit status 1 into success. A missing directory only establishes that path is absent; a failed enumeration cannot establish product absence. These are model instructions, not static shell analysis or a guarantee that generated commands follow them; command output and failures remain available to the next decision and local audit.

Fixed inventory does not invoke container clients: their requests can activate daemons or follow saved remote contexts. Container workload coverage is explicitly incomplete, while package, process, and service observations remain available. Before a targeted runtime query, the planner is instructed to inspect executable/package/snap identity and existing daemon state passively, avoid installer wrappers and absent/stopped runtimes, and select only an observed local endpoint. In particular, Ubuntu's [`lxd-installer` can install LXD from a noninteractive `lxc` invocation](https://lists.ubuntu.com/archives/foundations-bugs/2024-September/522772.html), and [Docker supports socket activation](https://docs.docker.com/reference/cli/dockerd). Finding an executable or passing `list`, `help`, or `--version` does not establish that invoking it is free of side effects. This guidance does not sandbox arbitrary model-generated commands.

Cancellation and deadlines while reading an API response retain their context error so a controlled daemon stop does not appear as an unexplained provider failure. Other body-read errors remain opaque to avoid leaking provider output.

Validation uses deterministic local fixtures:

```sh
go test -race ./internal/planner
```
