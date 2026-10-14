# AI Agent 安全方法论

{{#include ../banners/hacktricks-training.md}}

智能体评估应遵循**从攻击者可控输入到外部可观察效果**的路径。Jailbreaking、字符变化和系统提示泄露可以证明推理通道可被影响，但高影响发现是这条链路最终触及数据访问、未经授权的工具操作、下游注入 sink、持久化或另一个智能体。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 可用于标记覆盖范围（目标劫持、工具滥用、权限滥用、供应链、代码执行、记忆投毒、智能体间信任、级联故障、人类信任和失控智能体）。应先构建端到端攻击路径，再使用这些标签，而不是把模型输出意外文本当作测试终点。<sup>[[1]](#references)[[2]](#references)</sup>

## 构建目标映射

编写 payload 前，为每个智能体工作流记录以下五个维度：<sup>[[2]](#references)</sup>

| 维度 | 要枚举的内容 | 安全问题 |
|---|---|---|
| **不可信输入** | Chat/API 参数、URL、文档、电子邮件、工单、日历条目、检索到的文本块、记忆、工具结果和对等智能体消息 | 攻击者可以在哪里放置内容，使其之后进入模型上下文？ |
| **工具** | 工具名称和 schema、副作用、自动执行、确认行为以及动态加载的工具 | 哪些调用会读取机密、写入状态、发送消息、删除数据、执行代码或转移价值？ |
| **权限** | 用户委派、服务账号、API token、凭据有效期、租户/资源范围和网络可达性 | 每次调用以哪个身份运行？授权是否在工具边界处再次检查？ |
| **处理** | 查询构造器、shell、URL fetcher、模板引擎、解释器、解析器、文件操作和反序列化器 | 模型生成的数据会在哪里变成另一个解释器的语法？ |
| **输出** | 响应、渲染后的 Markdown/HTML、链接、图像 fetch、webhook、电子邮件、文件、日志、报告、指标和对等智能体流量 | 哪个可观察通道可以传递机密或触发二次请求？ |

不要把这些内容简化成一份宣传中的集成列表。有效的产物应将每个来源映射到它进入的确切上下文位置、该位置可用的工具、各工具使用的凭据、下游解释器以及每条数据出口路径。同一个工具使用按用户隔离的读取 token 时影响可能较低，而使用共享管理员凭据时则可能是严重风险。<sup>[[2]](#references)</sup>

## 侦察

### 映射所有投递和摄取路径

从交付面（Web、移动端、API、电子邮件、聊天平台、浏览器扩展）入手，并代理客户端到后端的流量。检查 UI 隐藏的字段、搜索/自动补全/筛选参数、会话状态对象、上传和索引任务、工具响应以及子智能体流量。仅支持移动端的客户端可能需要模拟器和 instrumentation 来绕过 certificate pinning，才能查看真实请求 schema。<sup>[[2]](#references)</sup>

然后映射模型底层的技术栈：编排框架、提示组装、检索和记忆存储、运行时（例如 Python、容器或 WASM）、挂载卷、主机服务、内部 API、云 metadata 可达性以及相邻网络。框架默认行为很重要，因为有些“工具调用”是通过生成或评估代码实现的；运行时/沙箱边界决定了结果能否受到限制。<sup>[[2]](#references)</sup>

### 使用非破坏性探测识别路由

将范围内请求与若干无关请求进行比较，同时保留完整响应、状态码、延迟和流式传输行为。在任何特定任务推理之前就出现稳定拒绝，可能表明存在独立的 gateway/classifier；结合上下文的拒绝意味着请求到达了模型；空响应或纯抽取式回答可能表示使用了关键词搜索或窄范围检索。将这些视为假设，并通过其他 API 字段和摄取路径重放同一探测来确认。<sup>[[2]](#references)</sup>

当评估能够指出最早一个会改变智能体行为的攻击者可控来源，**并且**能列出该来源可触达的工具、身份、解释器和输出时，侦察才算完成。<sup>[[2]](#references)</sup>

## 利用：跨越信任边界

测试通道，而不只是提示措辞。先使用 direct injection 确认可见入口会拦截哪些内容，然后通过以下较不明显的路径重复测试等效意图：<sup>[[2]](#references)</sup>

- **间接内容：**网页、文件、电子邮件、工单、metadata、alt text、HTML 注释、屏幕外文本或零宽字符。payload 投递技术请参阅 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)。
- **检索和记忆：**投毒之后会被检索的内容，或之后会话中会重新加载的状态。记录删除原始来源是否会消除该行为。
- **工具输出和对等智能体：**在工具响应或智能体间消息中放入 marker，以测试内部流量是否绕过了仅应用于用户输入和最终输出的过滤器。
- **供应链：**将工具描述符、plugins、连接的服务器、skills、模型和依赖项视为可信指令来源进行审查。MCP 专项测试请参阅 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)。
- **人工审批：**比较实际的结构化工具调用与模型生成的审批文本。测试攻击者影响是否能隐藏目标、范围、受影响对象或不可逆副作用。

先使用无害且唯一的 marker。保存来源 artifact、可观察到的组装后上下文、选定的工具调用、审批数据、后端请求/响应以及最终状态。这样可以区分真实影响和声称发生了操作的幻觉。<sup>[[2]](#references)</sup>

### 子智能体上下文隔离

非 fork 的 Claude Agent SDK 子智能体会接收自己的 `AgentDefinition.prompt`、委派提示和可用工具，但不会接收父智能体的 system prompt 或对话内容。如果其定义中省略 `tools`，它会继承子智能体可用的工具；项目的 `CLAUDE.md` 仍可能被加载。如果子智能体能使用相同的文件系统或执行工具，仅限制父智能体的提示就不是可靠的边界。<sup>[[4]](#references)</sup>

通过比较父智能体会拒绝的直接请求与委派给具名子智能体的相同任务，测试这条边界。NCC Group 报告称，原本被拒绝的操作系统文件枚举，在改写为让子智能体执行无害的“布局图”任务后成功了。<sup>[[3]](#references)</sup>

检查子智能体实际执行的工具调用和有效工具 allowlist，而不只是父智能体的最终回答；确认子智能体是否访问了父智能体不会访问的文件。<sup>[[4]](#references)</sup>这是 guardrail 继承失效，并不能证明发生了 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 或容器逃逸。<sup>[[3]](#references)[[4]](#references)</sup>

## 执行：证明真实影响

从影响到实际后果有两条不同路径：<sup>[[2]](#references)</sup>

1. **能力滥用：**已获授权的工具本身就能完成目标。例如，读取某个租户的记录并将其写入攻击者可见的报告、发送电子邮件、更改记录、删除文件或发起付款。这不需要利用次级软件漏洞。
2. **下游 sink 利用：**攻击者引导的模型输出变成另一个组件的语法。检查数据库查询是否存在 [SQL injection](../pentesting-web/sql-injection/README.md) 或 [NoSQL injection](../pentesting-web/nosql-injection.md)，shell wrapper 是否存在 [command injection](../pentesting-web/command-injection.md)，指定的 URL 是否导致 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)，文件操作是否存在路径遍历，模板/代码求值器是否可能导致 RCE，以及对象解析器是否存在 [unsafe deserialization](../pentesting-web/deserialization/README.md)。

对于每个候选项，证明以下链路：<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

只读集成仍可能被利用：只要后续任何组件能够发布它读取的内容，就存在风险。测试常规响应，以及较不明显的外传途径，例如攻击者可控的链接、自动获取的图片、webhook、日志、报告、计数器、通知，以及发送给其他 agent 的消息。<sup>[[2]](#references)</sup>

## 针对目标执行操作

确认某项操作后，应评估完整的影响范围，而不是在首次观察到效果后就停止：<sup>[[2]](#references)</sup>

- **数据外传：**机密信息、用户记录、内部文件、对话数据或提示词/上下文内容通过可观察的渠道泄露。
- **未授权操作：**agent 利用合法的写入能力达成攻击者的目标。
- **拒绝服务：**破坏性工具或反复执行高成本操作影响完整性或可用性。
- **持久化：**遭投毒的记忆、索引内容、受信任状态或运行时变更，在发起会话结束或来源移除后仍然存在。
- **传播：**受信任的 peer 使用遭入侵的 agent 发送的消息或共享状态，并利用自身工具和凭据重复执行该操作。

严重程度应依据可访问的数据、有效权限、接收端的可利用性、外传途径、持久性和传播性来判断，而不是看模型生成的文本有多出人意料。<sup>[[2]](#references)</sup>

## 评估期间需要验证的控制措施

提示词过滤器和更完善的系统提示词可以提高攻击者的成本，但不应被视为授权边界。通过直接输入、间接内容、记忆、工具和 peer agents 重新执行同一条攻击链，验证以下控制措施：<sup>[[2]](#references)</sup>

- 确定性策略层会在**每次工具调用**时检查经过身份验证的用户、租户、对象、操作和目标；模型无法提供或覆盖调用方身份。
- 读取和写入能力使用分离的、遵循最小权限原则的短期凭据；高影响工具仅在需要时开放，且绝不会因摄取内容而自动执行。
- 网络外传和内部目标的允许列表独立于模型选择的 URL；除非确有必要，否则应阻止运行时访问元数据端点、挂载的机密信息和相邻服务。
- 审批 UI 根据规范的结构化请求生成，并显示确切的参数、身份、目标、受影响对象和副作用，而不是模型生成的自由格式摘要。
- 从目标系统或权威数据源验证操作是否成功。agent 的描述、工具调用请求或 HTTP 重定向，都不能证明其声称的状态变更确实发生。
- 记忆和检索条目保留来源信息和信任标签，可被作废，并在后续操作中使用时重新授权。
- agent 间的消息应作为不可信请求进行身份验证和授权；peer 的声誉或 agent card 不会自动赋予接收方的工具使用权限。

## References

- [1] [2026 年 OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [《The Hacker's Guide to Attacking AI Agents》](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [《How Hard Is It Really to Break an AI Agent Out of Its Sandbox?》](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [《Subagents in the SDK》](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
