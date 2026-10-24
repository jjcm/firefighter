# Planner adapters

`Planner.Decide(context.Context, protocol.Request)` returns a validated `protocol.Decision`. There is no approval response type. The same protocol drives API and external command adapters.

## API

`NewAPI(APIConfig{BaseURL, Model, APIKey, Timeout, MaxActions, MaxResponseBytes})` calls `<BaseURL>/chat/completions`, so an OpenAI base URL is `https://api.openai.com/v1`. The caller resolves the API key from an environment variable; this package neither provisions nor writes keys. HTTPS is required except for loopback development endpoints, redirects are disabled, and upstream bodies never appear in errors.

The API uses [Chat Completions structured output](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=chat): `response_format.type=json_schema`, `strict=true`, required object fields, and `additionalProperties=false`. It requests no API tools; the daemon executes the returned action protocol itself. For another compatible provider that only supports JSON mode, set `APIConfig.JSONMode=true`; local parsing and validation remain equally strict. Unsupported provider formats fail visibly instead of silently falling back to unstructured commands.

The documented [`gpt-6.1-sol`](https://developers.openai.com/api/docs/models/gpt-6.1-sol) supports structured output and Chat Completions without tool calls as of October 24, 2026. Model selection is configurable. A model/API account can still deny a request or lack model access; those errors leave remediation unfinished and retryable, with no implied successful protection.

## Command

`NewCommand(CommandConfig{Argv, Dir, Timeout, MaxActions, MaxResponseBytes, Env})` invokes an adapter directly, without an implicit shell. The executable and any working directory must be absolute so execution cannot depend on the daemon's ambient `PATH` or current directory. The adapter gets one `protocol.Request` JSON object on stdin and must write exactly one `protocol.Decision` to stdout. The `instructions` field includes Firefighter's incident response system policy, JSON schema, action limit, and the configured operator policy.

Only a fixed system `PATH`, locale, and `HOME` are inherited. `Env` explicitly adds the environment variables an adapter needs. Ambient API/reporting credentials are not inherited. The caller is responsible for resolving any explicitly authorized adapter credentials. Stderr is discarded to prevent provider debug dumps from leaking secrets into the daemon's reports. Linux/macOS cancellation kills the adapter's process group; detached descendants may escape this and adapters should not daemonize.

## Enforcement

Both adapters bound request/response size and runtime. Decisions reject unknown keys, duplicate keys, null values, trailing JSON, unsupported assessments, duplicate action IDs, missing mutability flags, and mutating commands with no verification. Only `kind: command` is supported. `argv`, `verify`, and `rollback` are argument arrays. `done: true` requires no pending actions, ensuring the engine has an opportunity to evaluate executed commands before completion.

The prompt directs Ubuntu package revision checks, targeted signed package updates, source changes with tests, service and compromise checks, evidence preservation, and configured credential rotation. It treats posts, advisories and host output as untrusted facts, separates exposure from compromise, and forbids treating a clean scan as a clean-host guarantee. These instructions are not an OS sandbox: the root responder still executes model-authored commands under the owner's autonomy authorization.

Validation uses deterministic local fixtures:

```sh
go test -race ./internal/planner
```
