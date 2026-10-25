# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessment 应遵循 **从攻击者可控输入到外部可观察影响** 的路径。Jailbreaking、字符变更和 system-prompt 泄露可以证明推理通道会受到影响，但高影响发现是这条路径进一步通向数据访问、未经授权的工具操作、下游注入 sink、持久化或其他 agent。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 可用于标记覆盖范围（目标劫持、工具滥用、权限滥用、供应链、代码执行、记忆投毒、agent 间信任、级联故障、人类信任和 rogue agents）。应先构造端到端攻击路径，再使用这些标签，而不是把模型输出意外文本当作测试终点。<sup>[[1]](#references)[[2]](#references)</sup>

## 绘制目标图

编写 payload 前，为每个 agent 工作流记录以下五个维度：<sup>[[2]](#references)</sup>

| 维度 | 需要枚举的内容 | 安全问题 |
|---|---|---|
| **不可信输入** | Chat/API 参数、URL、文档、电子邮件、工单、日历条目、检索到的文本块、记忆、工具结果和 peer-agent 消息 | 攻击者可以在哪里放置之后会进入模型上下文的内容？ |
| **工具** | 工具名称和 schema、副作用、自动执行、确认行为和动态加载的工具 | 哪些调用会读取机密、写入状态、发送消息、删除数据、执行代码或转移价值？ |
| **权限** | 用户委派、服务账号、API token、凭据有效期、租户/资源范围和网络可达性 | 每次调用以哪个身份运行？是否在工具边界重复授权检查？ |
| **处理** | 查询构造器、shell、URL fetcher、模板引擎、解释器、解析器、文件操作和反序列化器 | 模型生成的数据会在哪里变成另一个解释器的语法？ |
| **输出** | 响应、渲染后的 Markdown/HTML、链接、图片 fetch、webhook、电子邮件、文件、日志、报告、指标和 peer-agent 流量 | 哪个可观察通道可能泄露机密或触发二次请求？ |

不要把它简化成广告中列出的集成清单。有效的产物应将每个来源映射到它进入的确切上下文位置、该位置可用的工具、各工具使用的凭据、下游解释器以及所有出口路径。相同的工具使用按用户隔离的只读 token 时影响可能很低，使用共享管理员凭据时则可能影响严重。<sup>[[2]](#references)</sup>

## 侦察

### 绘制所有传递和摄取路径

从传递界面（web、移动端、API、电子邮件、聊天平台、浏览器扩展）入手，并代理客户端到后端的流量。检查 UI 隐藏的字段、搜索/自动补全/筛选参数、对话状态对象、上传和索引任务、工具响应以及子 agent 流量。移动端专用客户端可能需要先使用 emulator 和 instrumentation 绕过 certificate pinning，才能看到真实请求 schema。<sup>[[2]](#references)</sup>

然后绘制模型底层的技术栈：编排框架、prompt 组装、检索和记忆存储、运行时（例如 Python、container 或 WASM）、挂载卷、主机服务、内部 API、云 metadata 可达性以及相邻网络。框架默认设置很重要，因为有些“tool calls”是通过生成或评估代码实现的；运行时/sandbox 边界决定了结果是否仍被限制在隔离范围内。<sup>[[2]](#references)</sup>

### 使用无破坏性探测识别路由

将范围内的请求与多个无关请求进行比较，同时保留完整响应、状态码、延迟和流式行为。在任何特定任务推理开始前稳定拒绝，可能表示存在独立的 gateway/classifier；基于上下文的拒绝则表明请求已到达模型；空响应或纯抽取式回答可能表示使用了关键词搜索或有限检索。将这些视为假设，并通过不同 API 字段和摄取路径重放相同探测来确认。<sup>[[2]](#references)</sup>

完成侦察后，评估方应能指出最早的攻击者可控来源，该来源会改变 agent 行为，**并且**能列出从该来源可触达的工具、身份、解释器和输出。<sup>[[2]](#references)</sup>

## 利用：跨越信任边界

测试通道，而不仅仅是 prompt 措辞。从直接注入开始，确认可见入口会拦截什么，再通过以下不太显眼的路径重复传递相同意图：<sup>[[2]](#references)</sup>

- **间接内容：** 网页、文件、电子邮件、工单、metadata、alt text、HTML 注释、屏幕外文本或零宽字符。有关 payload 传递技术，请参阅 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)。
- **检索和记忆：** 投毒之后会被检索的内容，或之后会重新加载的状态。记录删除原始来源是否会消除该行为。
- **工具输出和 peer agents：** 在工具响应或 agent 间消息中放置标记，测试内部流量是否绕过仅应用于用户输入和最终输出的过滤器。
- **供应链：** 将工具描述符、plugins、连接的服务器、skills、模型和依赖项视为可信指令来源进行审查。MCP 专项测试请参阅 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)。
- **人工审批：** 对比实际的结构化工具调用与模型生成的审批文本。测试攻击者影响是否能省略目标、范围、受影响对象或不可逆副作用。

先使用无害且唯一的标记。保留源文件、可观察到的组装上下文、选定的工具调用、审批数据、后端请求/响应和最终状态。这样可以区分实际影响与模型幻觉声称操作已发生。<sup>[[2]](#references)</sup>

### 工具风险判定器中的策略式文本

基于模型的工具 gate 可能会在其他有用的分类上下文中接收到攻击者可控文本。例如，LangChain 的实验性 `AutoModeMiddleware` 会向 TypeSafe `is_risky` 判定器发送待执行的工具调用、参数、可选的工具描述以及最多 30 条近期消息。当返回的 Noul 概率至少为 `0.5` 时，它会拦截已配置的工具；此 middleware 不会对未列出的工具进行分类。<sup>[[5]](#references)</sup> TypeSafe 也警告称，即使 state 预期只作为数据使用，其中的对抗性文本仍可能影响分类结果。<sup>[[6]](#references)</sup>

**伪造策略**不同于简单地声称自己是 system message。它会在较低信任级别的 state 中加入其他标签或风险定义，诱导判定器使用这些定义，而不是开发者定义的标准。在 Datadog 的测试中，用户可编辑的 `profile_description` 与 `can_edit:false` 一同被复制到工具参数中。其中类似策略的文本称，由于独立权限检查会在发生任何变更前拒绝写入尝试，因此该尝试风险较低。在 40 次运行中，`is_risky` 的平均分从 `0.893` 降至 `0.290`，而直接角色伪造对照组的平均分为 `0.905`。平均值低于 `0.5` 并不能证明每次调用都通过了 gate，而且该实验**并未**证明未经授权的写入已成功完成。<sup>[[7]](#references)</sup>

测试此边界时，要区分分类器判定与工具实际的授权结果。检查哪些可编辑字段会传给判定器，比较带有和不带有策略式文本时相同的待执行操作，并独立验证最终状态。独立权限检查仍必须依据经过身份验证的请求者权限，而不是 connector 的服务账号权限。<sup>[[7]](#references)</sup> 有关其他分类器失效模式，请参阅 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)；[LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) 讨论的是不同的路由和凭据边界。

### 子 agent 上下文隔离

非 fork 的 Claude Agent SDK 子 agent 会收到自己的 `AgentDefinition.prompt`、委派 prompt 和可用工具，但不会收到父 agent 的 system prompt 或对话。如果定义中省略 `tools`，子 agent 会继承可供子 agent 使用的工具；项目的 `CLAUDE.md` 仍可能加载。因此，当子 agent 能使用相同的文件系统或执行工具时，仅限制父 agent 的 prompt 并不是可靠的边界。<sup>[[4]](#references)</sup>

通过将父 agent 拒绝的直接请求与委派给命名子 agent 的相同任务进行比较，测试此边界。NCC Group 报告称，将被拒绝的操作系统文件枚举改写为无害的“布局图”任务后，子 agent 成功完成了该操作。<sup>[[3]](#references)</sup>

检查子 agent 实际的工具调用和有效的工具 allowlist，而不只是父 agent 的最终回答；确认子 agent 是否访问了父 agent 无法访问的文件。<sup>[[4]](#references)</sup> 这是 guardrail 继承失效，并不能证明发生了 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 或 container escape。<sup>[[3]](#references)[[4]](#references)</sup>

## 执行：证明真实影响

从影响到实际危害有两种不同路径：<sup>[[2]](#references)</sup>

1. **能力滥用：** 已授权工具本身就能实现目标。例如，读取某个租户的记录并将其写入攻击者可见的报告、发送电子邮件、更改记录、删除文件或发起付款。无需存在次级软件漏洞。
2. **下游 sink 利用：** 攻击者控制的模型输出变成另一个组件的语法。检查数据库查询是否存在 [SQL injection](../pentesting-web/sql-injection/README.md) 或 [NoSQL injection](../pentesting-web/nosql-injection.md)，shell wrapper 是否存在 [command injection](../pentesting-web/command-injection.md)，用户指定 URL 是否存在 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)，文件操作是否存在路径遍历，模板/代码求值器是否存在 RCE，以及对象解析器是否存在 [unsafe deserialization](../pentesting-web/deserialization/README.md)。

对于每个候选发现，都要证明以下链路：<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

只读集成仍可能被利用：只要后续任一组件能够发布其读取的内容即可。测试普通响应，以及不太显眼的出站渠道，例如攻击者控制的链接、自动图片抓取、webhook、日志、报告、计数器、通知和发给其他 agent 的消息。<sup>[[2]](#references)</sup>

## 针对目标的操作

确认某项操作成功后，应评估完整的影响范围，而不是在观察到第一个明显效果后就停止：<sup>[[2]](#references)</sup>

- **数据外泄：**机密、用户记录、内部文件、对话数据或 prompt/context 内容通过可观察的渠道流出。
- **未授权操作：**agent 利用合法的写入能力达成攻击者的目的。
- **拒绝服务：**破坏性工具或反复执行的高成本操作影响完整性或可用性。
- **持久化：**被污染的记忆、索引内容、受信任状态或运行时更改在发起会话结束或来源移除后仍然存在。
- **传播：**受信任的 peer 使用被攻陷 agent 的消息或共享状态，并利用自身工具和凭据重复执行该操作。

严重程度应取决于可访问的数据、有效权限、sink 的可利用性、出站渠道、持久化和传播，而不是模型输出看起来有多么出乎意料。<sup>[[2]](#references)</sup>

## 评估期间要验证的控制措施

Prompt 过滤器和更完善的 system prompt 可以提高攻击者的成本，但不应被视为授权边界。通过直接输入、间接内容、记忆、工具和 peer agent 重新运行同一条攻击链，验证以下控制措施：<sup>[[2]](#references)</sup>

- 确定性的策略层会在**每次工具调用**时检查经过身份验证的用户、租户、对象、操作和目标；模型无法提供或覆盖调用者身份。
- 读写能力使用独立的最小权限短期凭据；高影响工具仅在需要时开放，绝不会因摄取的内容而自动执行。
- 网络出站流量和内部目标采用独立于模型所选 URL 的允许列表；除非确有需要，否则阻止运行时访问元数据端点、挂载的机密和相邻服务。
- 审批 UI 根据规范化的结构化请求生成，并显示准确的参数、身份、目标、受影响对象和副作用，而不是模型的自由格式摘要。
- 通过目标系统或权威数据源验证操作是否成功。agent 的叙述、工具调用请求或 HTTP 重定向都不能证明其声称的状态变更确已发生。
- 记忆和检索条目保留来源信息和信任标签，可被作废，并且在后续操作中使用时需要重新授权。
- agent 间的消息应作为不可信请求进行身份验证和授权；peer 的声誉或 agent card 不会隐式授予接收方使用其工具的权限。

有关 A2A agent card、任务流程及其攻击面，请参阅 [A2A Protocol Security](AI-A2A-Protocol.md)。

## References

- [1] [2026 年 OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [攻击 AI Agents 指南](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [将 AI Agent 脱离其 Sandbox 到底有多难？](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK 中的 Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode 中间件源码](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness：对抗性内容](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [将 Jev 用作裁判：伪造的策略如何操控 Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
