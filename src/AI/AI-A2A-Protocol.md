# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## What is A2A

A2A (Agent2Agent) is an open protocol that lets one AI agent discover another agent and send it work over HTTP. MCP connects an agent to **tools and data**; A2A connects an agent to **other agents**, which are usually remote services owned by another team or company. An A2A server is a web API with an LLM agent behind it, so the protocol's own objects (agent cards, tasks, push-notification webhooks, extended cards) add specific authentication, IDOR and SSRF checks to a normal API test.<sup>[[1]](#references)[[2]](#references)</sup>

The main pieces are:

- **Agent Card:** a JSON document that describes the agent: name, description, skills, service URL(s), supported transports, capabilities (streaming, push notifications, extended card) and the `securitySchemes` the client must use. It is published at `https://<host>/.well-known/agent-card.json`. Older deployments that follow spec 0.2.x use `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** the unit of work. A message creates a task (with a server-generated `id` and a `contextId`), and the client later reads, cancels or subscribes to it.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 over HTTP (with SSE for streaming), gRPC, and an HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** credentials go in HTTP headers (for example `Authorization: Bearer ...`), never inside the JSON-RPC payload. The agent card says which scheme is required.<sup>[[1]](#references)</sup>

Method names changed between versions, so try both sets:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Send message | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming send | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Get task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| List tasks | - | `ListTasks` | `GET /tasks` |
| Cancel task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

The 1.0 spec uses the `A2A-Version` header (or a request parameter) to select the version, and requests without it are treated as 0.3.<sup>[[1]](#references)</sup>

## Discovery

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

From the card, write down:

- Every service `url` (often an internal hostname, a staging URL or a different port than the public site).
- `skills`: they show what the agent can do and which tools or data are behind it.
- `securitySchemes` / `security`: if they are empty or missing, the agent is probably meant to be called without credentials.
- `capabilities.pushNotifications` and `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

The spec says the public card should not contain credentials or internal implementation details, so internal URLs, keys or detailed tool lists in a public card are already a finding.<sup>[[1]](#references)</sup>

## Testing A2A endpoints

### Unauthenticated task submission

Send a minimal message without any credentials to every `url` listed in the card:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

A `Task` or `Message` result with `PONG`, when the card declares a security scheme, means authentication is not enforced on the RPC endpoint (it may only be enforced on the UI or on the card). If the card declares no scheme, check what the agent's skills can reach: an unauthenticated agent that can read internal data or call tools is the same as an unauthenticated API for those tools.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

The spec requires the server to check, on every request, that the caller may access the task, and to scope `ListTasks` to the caller even when no filter is given.<sup>[[1]](#references)</sup> Test it with two identities (A and B):

1. As A, create a task and save its `id` and `contextId`.
2. As B (or with no credentials), call `tasks/get` / `GetTask` with A's `id`, then `ListTasks` with no parameters.
3. Also try cancel and subscribe on A's task, and send a new message as B that includes A's `taskId` or `contextId` (this would add B's text to A's conversation).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerable: B receives A's history, artifacts or status, or can change A's task. Secure: a `TaskNotFoundError`, with no difference between "exists but not yours" and "does not exist".<sup>[[1]](#references)</sup> Task IDs are often UUIDs, so look for them in places where they leak (shared links, logs, push notification payloads, error messages).

### Push notification webhook SSRF

When `capabilities.pushNotifications` is true, the client gives the agent a webhook URL, and the agent later sends `POST` requests with task updates to that URL. The spec says agents should reject private ranges, localhost and link-local addresses, and use allowlists.<sup>[[1]](#references)</sup> Create a task, register a push notification config whose `url` points to your OAST host to confirm outbound requests, and then (only if the scope allows it) to internal targets such as `http://127.0.0.1:<port>/` or `http://169.254.169.254/`. Compare errors and timing to map internal services. The agent also adds the configured authentication header to these requests, so check that it is not sent to an attacker-chosen host when you can change the URL of another user's config. See [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Extended agent card access

`GetExtendedAgentCard` must require authentication and may return more skills and configuration than the public card.<sup>[[1]](#references)</sup> Call it without credentials and with a low-privilege identity, and compare the result with the public card.

### Push notification config and in-task credential leaks

Push notification configs store a webhook URL and the credentials the agent sends to it. The spec requires every push notification config operation (create, get, list, delete) to verify that the caller may access the task.<sup>[[1]](#references)</sup> Repeat the two-identity test from the [task IDOR section](#task-idor-tasksget-gettask-cancel-subscribe) on these routes. A readable config of another user leaks a webhook token, and a writable one redirects that user's task updates to your host.

When an agent needs extra authorization during a task, it moves the task to `TASK_STATE_AUTH_REQUIRED`. The client can arrange authorization out of band; the specification says agents must receive credentials out of band unless an in-band mechanism was negotiated. In-band exchange can pass a credential across a chain of A2A agents and expose it to every agent in that chain.<sup>[[1]](#references)</sup> In an orchestrator test, check whether a credential that the user gives for one downstream agent appears in messages, artifacts or task history that other agents (or other users through task IDOR) can read.

Agent card fields and task results are also untrusted input for the calling agent. Test them with the indirect prompt injection techniques in [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) and the inter-agent trust checks in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Announcing the Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A specification v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A specification v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)

{{#include ../banners/hacktricks-training.md}}
