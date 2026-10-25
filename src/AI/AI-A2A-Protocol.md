# A2A (Agent2Agent) 协议安全

{{#include ../banners/hacktricks-training.md}}

## 什么是 A2A

A2A (Agent2Agent) 是一种开放协议，允许一个 AI agent 发现另一个 agent，并通过 HTTP 向其发送工作请求。MCP 将 agent 连接到**工具和数据**；A2A 则将 agent 连接到**其他 agent**，这些 agent 通常是由其他团队或公司拥有的远程服务。A2A server 是一个后端运行着 LLM agent 的 web API，因此协议自身的对象（agent cards、tasks、push-notification webhooks、extended cards）会为常规 API 测试增加特定的认证、IDOR 和 SSRF 检查。<sup>[[1]](#references)[[2]](#references)</sup>

主要组成部分包括：

- **Agent Card：** 描述 agent 的 JSON 文档，包含名称、描述、技能、服务 URL、支持的传输方式、功能（streaming、push notifications、extended card）以及客户端必须使用的 `securitySchemes`。它发布在 `https://<host>/.well-known/agent-card.json`。遵循 spec 0.2.x 的旧版部署使用 `/.well-known/agent.json`。<sup>[[1]](#references)[[3]](#references)</sup>
- **Task：** 工作单元。发送消息会创建一个 task（带有 server 生成的 `id` 和 `contextId`），客户端随后可以读取、取消或订阅它。<sup>[[1]](#references)</sup>
- **传输方式：** 通过 HTTP 传输 JSON-RPC 2.0（streaming 使用 SSE）、gRPC，以及 HTTP+JSON REST 绑定。<sup>[[1]](#references)</sup>
- **认证：** 凭据放在 HTTP headers 中（例如 `Authorization: Bearer ...`），绝不能放进 JSON-RPC payload。agent card 会说明所需的 scheme。<sup>[[1]](#references)</sup>

不同版本的方法名称有所变化，因此两套名称都应尝试：<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| 操作 | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| 发送消息 | `message/send` | `SendMessage` | `POST /message:send` |
| 流式发送 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| 获取 task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| 列出 tasks | - | `ListTasks` | `GET /tasks` |
| 取消 task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push notification 配置 | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec 使用 `A2A-Version` header（或请求参数）选择版本；未提供该字段的请求会被视为 0.3。<sup>[[1]](#references)</sup>

## 发现

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

从 card 中记录：

- 每个服务的 `url`（通常是内部主机名、staging URL，或与公共站点不同的端口）。
- `skills`：它们展示 agent 能做什么，以及其背后有哪些工具或数据。
- `securitySchemes` / `security`：如果它们为空或缺失，agent 很可能预期在不提供凭据的情况下被调用。
- `capabilities.pushNotifications` 和 `capabilities.extendedAgentCard`（在 0.3 中为 `supportsAuthenticatedExtendedCard`）。

规范规定，公共 card 不应包含凭据或内部实现细节，因此，公共 card 中出现内部 URL、密钥或详细工具列表，本身就是一项发现。<sup>[[1]](#references)</sup>

## 测试 A2A endpoints

### 未经身份验证的任务提交

向 card 中列出的每个 `url` 发送一条不带任何凭据的最简消息：

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

`Task` 或 `Message` 返回 `PONG`，且 card 声明了 security scheme，意味着 RPC endpoint 未强制执行身份验证（身份验证可能只在 UI 或 card 上强制执行）。如果 card 未声明 scheme，请检查 agent 的 skills 能访问什么：能够读取内部数据或调用工具的未认证 agent，等同于这些工具对应的未认证 API。

### Task IDOR（`tasks/get`、`GetTask`、cancel、subscribe）

规范要求服务器在每次请求时检查调用方是否有权访问该 task，并且即使未提供筛选条件，也要将 `ListTasks` 的结果限定为调用方可访问的内容。<sup>[[1]](#references)</sup> 使用两个身份（A 和 B）进行测试：

1. 以 A 的身份创建 task，并保存其 `id` 和 `contextId`。
2. 以 B 的身份（或不提供凭据）调用 `tasks/get` / `GetTask`，传入 A 的 `id`，然后在不带参数的情况下调用 `ListTasks`。
3. 也尝试对 A 的 task 执行 cancel 和 subscribe，并以 B 的身份发送一条包含 A 的 `taskId` 或 `contextId` 的新消息（这会将 B 的文本添加到 A 的对话中）。

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

存在漏洞：B 可以接收 A 的历史记录、artifacts 或状态，或者更改 A 的任务。安全：返回 `TaskNotFoundError`，且无法区分“任务存在但不属于你”和“任务不存在”。<sup>[[1]](#references)</sup> Task ID 通常是 UUID，因此要在可能发生 leak 的位置查找它们（共享链接、日志、push notification payload、错误消息）。

### Push notification webhook SSRF

当 `capabilities.pushNotifications` 为 true 时，客户端会向 agent 提供 webhook URL，agent 随后会向该 URL 发送包含任务更新的 `POST` 请求。规范规定，agent 应拒绝私有地址范围、localhost 和 link-local 地址，并使用 allowlist。<sup>[[1]](#references)</sup> 创建一个任务，注册一个 `url` 指向你的 OAST 主机的 push notification 配置，以确认是否有出站请求；然后（仅在测试范围允许时）将其指向内部目标，例如 `http://127.0.0.1:<port>/` 或 `http://169.254.169.254/`。比较错误和响应时间，以枚举内部服务。agent 还会在这些请求中添加已配置的认证 header，因此，如果你能更改其他用户配置的 URL，请检查该 header 是否会被发送到攻击者选择的主机。参见 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)。

### Extended agent card 访问

`GetExtendedAgentCard` 必须要求认证，并且可能返回比公开 card 更多的技能和配置。<sup>[[1]](#references)</sup> 不提供凭据及使用低权限身份调用它，并将结果与公开 card 进行比较。

### Push notification 配置和任务内凭据泄露

Push notification 配置会存储 webhook URL 以及 agent 发送到该 URL 的凭据。规范要求，每项 push notification 配置操作（create、get、list、delete）都必须验证调用者是否有权访问该任务。<sup>[[1]](#references)</sup> 在这些路由上重复 [task IDOR 部分](#task-idor-tasksget-gettask-cancel-subscribe)中的双身份测试。可读取的其他用户配置会泄露 webhook token；可写入的配置则会将该用户的任务更新重定向到你的主机。

当 agent 在任务期间需要额外授权时，它会将任务移至 `TASK_STATE_AUTH_REQUIRED`。客户端可以通过带外方式安排授权；规范指出，除非已协商带内机制，否则 agent 必须通过带外方式接收凭据。带内交换可能会让凭据沿 A2A agent 链传递，并暴露给链中的每个 agent。<sup>[[1]](#references)</sup> 在 orchestrator 测试中，检查用户为某个下游 agent 提供的凭据是否会出现在其他 agent 可读取的消息、artifacts 或任务历史中（也包括其他用户通过 task IDOR 读取的情况）。

Agent card 字段和任务结果对于调用方 agent 来说也都是不可信输入。使用 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) 中的间接 prompt injection 技术以及 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) 中的 agent 间信任检查来测试它们。

## References

- [1] [A2A 协议规范](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — 宣布推出 Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A 规范 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A 规范 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
