# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## What is A2A

A2A (Agent2Agent) is an open protocol that lets one AI agent discover another agent and send it work over HTTP. MCP connects an agent to **tools and data**; A2A connects an agent to **other agents**, which are usually remote services owned by another team or company. Because an A2A server is just a web API that runs an LLM agent behind it, it has the usual web API bugs (missing authentication, IDOR, SSRF) plus prompt-injection risks between agents.<sup>[[1]](#references)[[2]](#references)</sup>

The main pieces are:

- **Agent Card:** a JSON document that describes the agent: name, description, skills, service URL(s), supported transports, capabilities (streaming, push notifications, extended card) and the `securitySchemes` the client must use. It is published at `https://<host>/.well-known/agent-card.json`. Older deployments that follow spec 0.2.x use `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** the unit of work. A message creates a task (with a server-generated `id` and a `contextId`), and the client later reads, cancels or subscribes to it.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 over HTTP (with SSE for streaming), gRPC, and an HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** credentials go in HTTP headers (for example `Authorization: Bearer ...`), never inside the JSON-RPC payload. The agent card says which scheme is required.<sup>[[1]](#references)</sup>

Method names changed between versions, so try both sets:

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Send message | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming send | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Get task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| List tasks | - | `ListTasks` | `GET /tasks` |
| Cancel task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification config | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

The 1.0 spec uses the `A2A-Version` header to select the version; requests without it are treated as 0.3.<sup>[[1]](#references)[[4]](#references)</sup>

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

When `capabilities.pushNotifications` is true, the client gives the agent a webhook URL, and the agent later sends `POST` requests with task updates to that URL. The spec says agents should reject private ranges, localhost and link-local addresses, and use allowlists.<sup>[[1]](#references)</sup> Create a task, register a push notification config whose `url` points to your OAST host to confirm outbound requests, and then (only if the scope allows it) to internal targets such as `http://127.0.0.1:<port>/` or `http://169.254.169.254/`. Compare errors and timing to map internal services. The agent also adds the configured authentication header to these requests, so check that it is not sent to an attacker-chosen host when you can change the URL of another user's config. See [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md).

### Extended agent card access

`GetExtendedAgentCard` must require authentication and may return more skills and configuration than the public card.<sup>[[1]](#references)</sup> Call it without credentials and with a low-privilege identity, and compare the result with the public card.

### Agent-to-agent prompt injection

Everything a remote agent returns (message parts, artifacts, files, even the description and skills in its agent card) is untrusted text that the calling agent will put in its prompt. A malicious or compromised peer agent can therefore inject instructions into the caller, in the same way a malicious MCP tool description does. Test by registering or simulating a peer agent whose card description or task result contains a canary instruction, and check whether the orchestrator follows it or uses its own tools because of it. See [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection), [MCP Servers](AI-MCP-Servers.md) and [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Announcing the Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A specification v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A specification v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)

{{#include ../banners/hacktricks-training.md}}
