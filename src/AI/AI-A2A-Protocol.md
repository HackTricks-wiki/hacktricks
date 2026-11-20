# A2A (Agent2Agent) Protocol 安全

{{#include ../banners/hacktricks-training.md}}

## 什么是 A2A

A2A (Agent2Agent) 是一种开放协议，可让一个 AI agent 发现另一个 agent，并通过 HTTP 向它发送工作请求。MCP 将 agent 连接到**工具和数据**；A2A 则将 agent 连接到**其他 agent**，这些 agent 通常是由其他团队或公司拥有的远程服务。A2A server 是一个后端运行着 LLM agent 的 Web API，因此该协议自身的对象（agent cards、tasks、推送通知 webhooks、扩展卡片）会为常规 API 测试带来特定的身份验证、IDOR 和 SSRF 检查。<sup>[[1]](#references)[[2]](#references)</sup>

主要组成部分：

- **Agent Card:** 描述 agent 的 JSON 文档：名称、描述、技能、服务 URL、支持的传输方式、能力（streaming、推送通知、扩展卡片），以及客户端必须使用的 `securitySchemes`。它发布在 `https://<host>/.well-known/agent-card.json`。遵循 spec 0.2.x 的旧版部署使用 `/.well-known/agent.json`。<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** 工作单元。一条消息会创建一个 task（包含 server 生成的 `id` 和 `contextId`），之后客户端可以读取、取消或订阅该 task。<sup>[[1]](#references)</sup>
- **传输方式：**通过 HTTP 使用 JSON-RPC 2.0（streaming 使用 SSE）、gRPC，以及 HTTP+JSON REST 绑定。<sup>[[1]](#references)</sup>
- **身份验证：**凭据放在 HTTP headers 中（例如 `Authorization: Bearer ...`），绝不能放在 JSON-RPC payload 中。agent card 会说明所需的 scheme。<sup>[[1]](#references)</sup>

不同版本的方法名称有所变化，因此请尝试两组名称：<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| 操作 | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| 发送消息 | `message/send` | `SendMessage` | `POST /message:send` |
| 流式发送 | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| 获取 task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| 列出 tasks | - | `ListTasks` | `GET /tasks` |
| 取消 task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| 推送通知配置 | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| 扩展卡片 | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

1.0 spec 使用 `A2A-Version` header（或请求参数）来选择版本；未提供该值的请求会被视为 0.3。<sup>[[1]](#references)</sup>

## 发现

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

从 card 中记录：

- 每个服务的 `url`：在 1.0 中，这些 URL 位于 `supportedInterfaces` 下；较旧的 card 可能会在顶层提供 `url`。记录每个 endpoint 和 transport，包括内部主机名、staging URL 和备用端口。<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`：它们展示 agent 能做什么，以及其背后使用了哪些工具或数据。
- `securitySchemes` / `security`：如果它们为空或缺失，agent 很可能设计为无需凭据即可调用。
- `capabilities.pushNotifications` 和 `capabilities.extendedAgentCard`（在 0.3 中为 `supportsAuthenticatedExtendedCard`）。

规范指出，公开的 card 不应包含凭据或内部实现细节，因此公开 card 中出现内部 URL、密钥或详细工具列表，本身就值得记录为发现。<sup>[[1]](#references)</sup>

### 多 agent 主机中的 Agent Card 名称冲突

card 的 `name` 是供人阅读的标签，不是稳定的路由标识。<sup>[[1]](#references)[[5]](#references)</sup> 如果主机将两个不同的远程 peer 注册为同一个本地名称，其 agent 树、生成的工具名称、客户端映射或 broker 路由可能会把原本发给可信 peer 的任务发送给另一个 peer。<sup>[[5]](#references)</sup> 这要求攻击者控制的 peer 被接纳到**同一个路由命名空间**；仅在 Internet 上发布重复的 card 并不足以触发此问题。<sup>[[5]](#references)</sup>

使用两个受控 peer、不同的 URL 和无害标记，测试主机的**接纳到分发**路径：<sup>[[5]](#references)</sup>

1. 记录可信 peer 的 card、来源和本地选择器。注册第二个 peer，其 card 使用相同的 `name`，但 URL 指向你控制的 endpoint。
2. 触发按名称选择可信 peer 的操作。尝试两种注册顺序；如果名称会成为工具标识符，也尝试主机通常采用的名称规范化方式。捕获哪个 endpoint 收到了标记，以及哪个 agent 返回了响应。
3. 仅更改第二个 card 的名称并重复测试。如果只有在名称冲突时请求才到达第二个 endpoint，就能证明发生了错误的 peer 分发。另行检查是否实际附带了敏感上下文或凭据；名称冲突本身**不能**证明凭据或工具权限发生了转移。

如果调用方使用固定且绑定来源的 endpoint，而不是通过 card 名称进行解析，则此测试不适用。<sup>[[5]](#references)</sup> 若要继续测试恶意 peer 响应和 prompt-injection 的影响，请参阅 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary)。

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

`Task` 或 `Message` 返回 `PONG`，且 card 声明了安全方案时，表示 RPC endpoint 未强制执行身份验证（身份验证可能仅在 UI 或 card 上执行）。如果 card 未声明安全方案，请检查 agent 的 skills 能访问什么：能够读取内部数据或调用工具的未认证 agent，与这些工具对应的未认证 API 无异。

### Task IDOR（`tasks/get`、`GetTask`、cancel、subscribe）

规范要求服务器在每次请求时检查调用者是否有权访问该 task，并且即使未提供过滤条件，`ListTasks` 也必须将结果限定为调用者可访问的 task。<sup>[[1]](#references)</sup> 使用两个身份（A 和 B）进行测试：

1. 以 A 的身份创建一个 task，并保存其 `id` 和 `contextId`。
2. 以 B 的身份（或不提供凭据）调用 `tasks/get` / `GetTask` 并传入 A 的 `id`，然后不带参数调用 `ListTasks`。
3. 另外，尝试对 A 的 task 执行 cancel 和 subscribe，并以 B 的身份发送一条包含 A 的 `taskId` 或 `contextId` 的新消息（这会将 B 的文本添加到 A 的对话中）。

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

易受攻击：B 可以收到 A 的历史记录、制品或状态，或更改 A 的任务。安全：返回 `TaskNotFoundError`，且“存在但不属于你”和“不存在”两种情况没有区别。<sup>[[1]](#references)</sup> Task ID 通常是 UUID，因此要在可能泄露它们的地方查找（共享链接、日志、推送通知 payload、错误消息）。

### 推送通知 webhook SSRF

当 `capabilities.pushNotifications` 为 true 时，客户端会向 agent 提供一个 webhook URL，agent 随后会向该 URL 发送包含任务更新的 `POST` 请求。规范指出，agent 应拒绝私有网段、localhost 和链路本地地址，并使用白名单。<sup>[[1]](#references)</sup> 创建一个任务，注册一个 `url` 指向你 OAST 主机的推送通知配置，以确认出站请求，然后（仅当测试范围允许时）再将其指向内部目标，例如 `http://127.0.0.1:<port>/` 或 `http://169.254.169.254/`。比较错误和响应时间，以识别内部服务。agent 还会在这些请求中添加配置的身份验证 header，因此，如果你能更改另一用户配置的 URL，请检查该 header 是否会被发送到攻击者指定的主机。参见 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/)。

### File-URL 部分作为第二个 SSRF 入口点

A2A 1.0 允许消息或制品携带一个 `Part` 文件引用，其中包含 `url`（0.3 使用 `kind: "file"` 和 `file.uri`）。<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> 协议只传递该引用；是否获取它属于应用程序行为，并非 A2A SDK 的要求。<sup>[[6]](#references)</sup> 这与上面的推送通知回调 URL 是不同的入口点。两个方向都要测试：发送给 A2A server 的客户端提供的文件，以及由信任级别较低的 peer 返回给 orchestrator 的文件 URL。<sup>[[1]](#references)[[6]](#references)</sup>

对于经过授权的 1.0 JSON-RPC endpoint，将常规文本部分替换为指向唯一 OAST 路径的 URL，并检查**哪个组件**发起了请求：<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

只有在接收方对其进行解引用时，才应使用 [SSRF 工作流](../pentesting-web/ssrf-server-side-request-forgery/)测试范围内的内部目标、重定向和 DNS 解析更改。有效的 `Part` 或成功的任务响应本身并不能证明存在 SSRF；应在目标处确认是否发生了获取操作，以及获取的内容是否传递给了 agent。<sup>[[6]](#references)</sup>

### 扩展代理卡访问

`GetExtendedAgentCard` 必须要求身份验证，并且可能返回比公开卡片更多的技能和配置信息。<sup>[[1]](#references)</sup> 不提供凭据调用它，并使用低权限身份调用，然后将结果与公开卡片进行比较。

### 推送通知配置与任务中的凭据泄露

推送通知配置会存储 webhook URL 以及 agent 发送给它的凭据。规范要求每项推送通知配置操作（创建、获取、列出、删除）都验证调用方是否有权访问该任务。<sup>[[1]](#references)</sup> 在这些路由上重复[任务 IDOR 部分](#task-idor-tasksget-gettask-cancel-subscribe)中的双身份测试。若能读取其他用户的配置，就会泄露 webhook token；若能写入配置，就能将该用户的任务更新重定向到你的主机。

当 agent 在任务期间需要额外授权时，它会将任务状态切换为 `TASK_STATE_AUTH_REQUIRED`。客户端可以通过带外方式安排授权；规范规定，除非协商了带内机制，否则 agent 必须通过带外方式接收凭据。带内交换可能会使凭据沿 A2A agent 链传递，并暴露给链中的每个 agent。<sup>[[1]](#references)</sup> 在编排器测试中，检查用户为某个下游 agent 提供的凭据，是否出现在其他 agent（或其他用户通过任务 IDOR）能够读取的消息、制品或任务历史中。

对于调用方 agent，agent 卡片字段和任务结果也都是不可信输入。使用 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) 中的间接 prompt injection 技术，以及 [AI Agent Security Methodology](AI-Agent-Security-Methodology.md) 中的 agent 间信任检查来测试它们。



## References

- [1] [A2A 协议规范](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — 宣布推出 Agent2Agent 协议（A2A）](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A 规范 v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A 规范 v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [多智能体系统中的代理名称冲突攻击](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK 安全指南](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0 迁移指南](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
