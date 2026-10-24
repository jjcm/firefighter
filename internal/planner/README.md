# Planner adapters

`Planner.Decide(context.Context, protocol.Request)` returns a validated `protocol.Decision`. There is no approval response type. The same protocol drives API and external command adapters.

## API

`NewAPI(APIConfig{Backend, BaseURL, Model, APIKey, Timeout, MaxActions, MaxResponseBytes, JSONMode})` supports OpenAI-compatible Chat Completions and native Anthropic Messages. The caller resolves the API key from an environment variable; this package neither provisions nor writes keys. HTTPS is required except for loopback development endpoints, redirects are disabled, and upstream bodies never appear in errors. The daemon validates the returned action protocol and executes it itself; the provider API receives no executable tool definitions.

### OpenAI and OpenRouter

Backend `api` (or an empty backend in the adapter) calls `<BaseURL>/chat/completions` with bearer authentication. OpenAI uses `https://api.openai.com/v1`; OpenRouter uses `https://openrouter.ai/api/v1`.

The default format uses [Chat Completions structured output](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat): `response_format.type=json_schema`, `strict=true`, required object fields, and `additionalProperties=false`. For a compatible provider using JSON-object mode, set `APIConfig.JSONMode=true`; local parsing and validation remain equally strict. Unsupported provider formats fail visibly instead of silently falling back to unstructured commands. Refusals, missing content, multiple choices, and completion reasons other than `stop` are rejected.

Interactive installation defaults to OpenRouter with `deepseek/deepseek-v4.1-flash-1017` in JSON-object mode. The OpenAI option defaults to [`gpt-6.1-sol`](https://developers.openai.com/api/docs/models/gpt-6.1-sol) with strict structured output. Operators can select a different model. Account access and model availability are only established by a successful API request, not by configuration validation.

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

Validation uses deterministic local fixtures:

```sh
go test -race ./internal/planner
```
