# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

Agent assessment 应遵循**从攻击者可控输入到外部可观察影响**的路径。Jailbreaking、字符变化和 system prompt 泄露，能够证明推理通道可被影响；但高影响发现应是进一步导致数据访问、未授权工具操作、下游注入 sink、持久化或影响其他 agent 的完整链路。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 可用于标注测试覆盖范围（目标劫持、工具滥用、权限滥用、供应链、代码执行、记忆投毒、agent 间信任、级联故障、人类信任和 rogue agent）。应在构建端到端攻击路径后再使用这些标签，而不是把模型输出意外文本当作测试终点。<sup>[[1]](#references)[[2]](#references)</sup>

## 构建目标映射

在编写 payload 前，为每个 agent 工作流记录以下五个维度：<sup>[[2]](#references)</sup>

| 维度 | 需要枚举的内容 | 安全问题 |
|---|---|---|
| **不可信输入** | Chat/API 参数、URL、文档、邮件、工单、日历条目、检索到的文本块、记忆、工具结果和 peer-agent 消息 | 攻击者可以在哪里放置之后会进入模型上下文的内容？ |
| **工具** | 工具名称和 schema、副作用、自动执行、确认行为以及动态加载的工具 | 哪些调用会读取机密、写入状态、发送消息、删除数据、执行代码或转移价值？ |
| **权限** | 用户委派、服务账号、API token、凭证有效期、租户/资源范围和网络可达性 | 每个调用以哪个身份运行？工具边界是否会重新进行授权？ |
| **处理过程** | 查询构造器、shell、URL fetcher、模板引擎、解释器、解析器、文件操作和反序列化器 | 模型生成的数据会在哪里变成另一个解释器的语法？ |
| **输出** | 响应、渲染后的 Markdown/HTML、链接、图片 fetch、webhook、邮件、文件、日志、报告、指标和 peer-agent 流量 | 哪个可观察通道能够传出机密或触发次级请求？ |

不要将这些内容简化为一份宣传中的集成列表。实用的映射应将每个来源关联到其进入的确切上下文位置、该位置可用的工具、每个工具使用的凭证、下游解释器以及所有出站路径。同一个工具使用按用户隔离的只读 token 时影响可能很低，使用共享管理员凭证时则可能是严重风险。<sup>[[2]](#references)</sup>

## 侦察

### 映射所有传递和摄取路径

从传递面（web、mobile、API、email、chat platform、browser extension）入手，并代理客户端到后端的流量。检查 UI 隐藏的字段、搜索/自动补全/过滤参数、对话状态对象、上传和索引任务、工具响应以及子 agent 流量。仅提供 mobile 客户端的场景可能需要使用 emulator 和 instrumentation 绕过 certificate pinning，之后才能看见真实的请求 schema。<sup>[[2]](#references)</sup>

然后映射模型下方的技术栈：orchestration framework、prompt 组装、检索和记忆存储、runtime（例如 Python、container 或 WASM）、挂载卷、主机服务、内部 API、云 metadata 可达性以及相邻网络。Framework 默认行为很重要，因为某些“工具调用”实际上通过生成或求值代码来实现；runtime/sandbox 边界决定了结果能否被限制在其中。<sup>[[2]](#references)</sup>

### 使用非破坏性探测识别路由

将范围内的请求与几个无关请求进行比较，同时保留完整响应、状态码、延迟和流式传输行为。在任何特定任务推理之前稳定拒绝，可能表示存在独立的 gateway/classifier；结合上下文的拒绝则表明请求到达了模型；空响应或纯抽取式答案可能表明使用了关键词搜索或范围有限的检索。将这些视为假设，并通过备用 API 字段和摄取路径重放相同探测来确认。<sup>[[2]](#references)</sup>

侦察完成的标准是：评估能够指出最早一个会改变 agent 行为的攻击者可控来源，**并且**能指出从该来源可达的工具、身份、解释器和输出。<sup>[[2]](#references)</sup>

## 利用：跨越信任边界

测试通道，而不只是测试 prompt 用词。从直接注入开始，确认可见入口会拦截哪些内容，然后通过以下不那么显眼的路径重复测试等效意图：<sup>[[2]](#references)</sup>

- **间接内容：**网页、文件、邮件、工单、metadata、alt text、HTML 注释、屏幕外文本或零宽字符。关于 payload 传递技术，请参阅 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)。
- **检索和记忆：**投毒之后会被检索的内容，或之后的会话中会重新加载的状态。记录删除原始来源是否会消除该行为。
- **工具输出和 peer agent：**将标记放入工具响应或 agent 间消息，测试内部流量是否绕过了仅应用于用户输入和最终输出的过滤器。
- **供应链：**将工具描述符、插件、已连接的服务器、skills、模型和依赖项视为可信指令来源。MCP 专项测试请参阅 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)。
- **人工审批：**将实际结构化工具调用与模型生成的审批文本进行比较。测试攻击者影响是否能省略目标、范围、受影响对象或不可逆副作用。

先使用无害且唯一的标记。保留来源 artifact、可观察时的组装后上下文、选定的工具调用、审批数据、后端请求/响应以及最终状态。这样可以区分实际影响与模型对操作已发生的幻觉式声称。<sup>[[2]](#references)</sup>

### 工具风险判定器中的伪造策略文本

基于模型的工具 gate 可能会在其他有用的分类上下文中收到攻击者可控文本。例如，LangChain 的实验性 `AutoModeMiddleware` 会将提议的工具调用、其参数、可选工具描述以及最多 30 条近期消息发送给 TypeSafe `is_risky` judge。当返回的 Noul 概率大于或等于 `0.5` 时，它会拦截已配置的工具；此 middleware 不会对未列出的工具进行分类。<sup>[[5]](#references)</sup> TypeSafe 也提醒，即使 state 本意是数据，其中的对抗性文本仍可能影响分类。<sup>[[6]](#references)</sup>

**伪造策略**不同于简单地声称自己是 system message。它会在较低信任级别的 state 中放入替代标签或风险定义，并诱使 judge 使用这些定义，而不是开发者定义的标准。在 Datadog 的测试中，可由用户编辑的 `profile_description` 与 `can_edit:false` 一起被复制到工具参数中。类似策略的文本辩称，写入尝试风险较低，因为独立的权限检查会在任何修改发生前将其拒绝。在 40 次运行中，`is_risky` 平均分数从 `0.893` 降至 `0.290`，而直接伪装角色的对照组平均分数为 `0.905`。平均分低于 `0.5` 并不能证明每次调用都通过了 gate，而且该实验**没有**证明发生了已完成的未授权写入。<sup>[[7]](#references)</sup>

测试此边界时，应区分分类器的判定与工具实际的授权结果。检查哪些可编辑字段会传给 judge，对比包含和不包含类似策略文本时相同的拟议操作，并独立验证最终状态。独立权限检查仍必须使用经过身份验证的请求者权限，而不是 connector 的服务账号权限。<sup>[[7]](#references)</sup> 其他分类器失效模式请参阅 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)；[LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) 涉及不同的路由和凭证边界。

### Subagent 上下文隔离

非 fork 的 Claude Agent SDK subagent 会收到自己的 `AgentDefinition.prompt`、委派 prompt 和可用工具，但不会收到 parent system prompt 或对话。如果定义中省略 `tools`，它会继承 subagent 可用的工具；项目中的 `CLAUDE.md` 仍可能加载。因此，当 child 可以使用相同的文件系统或执行工具时，仅 parent prompt 中的限制并不是可靠的边界。<sup>[[4]](#references)</sup>

通过比较 parent 拒绝的直接请求与委派给具名 subagent 的同一任务来测试该边界。NCC Group 报告称，将被拒绝的操作系统文件枚举任务重新表述为无害的“布局图”，交给 child 后便成功了。<sup>[[3]](#references)</sup>

检查 child 实际的工具调用和有效工具 allowlist，而不只是 parent 的最终答案；确认 child 是否访问了 parent 不会访问的文件。<sup>[[4]](#references)</sup> 这是 guardrail 继承失效，并不能证明发生了 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 或 container escape。<sup>[[3]](#references)[[4]](#references)</sup>

## 执行：证明真实影响

从影响到实际效果有两条不同路径：<sup>[[2]](#references)</sup>

1. **能力滥用：**已授权的工具本身就能完成目标。例如，读取某个租户的记录并将其写入攻击者可见的报告、发送邮件、修改记录、删除文件或发起付款。这不需要次级软件漏洞。
2. **利用下游 sink：**攻击者引导的模型输出变成另一个组件的语法。检查数据库查询中是否存在 [SQL injection](../pentesting-web/sql-injection/README.md) 或 [NoSQL injection](../pentesting-web/nosql-injection.md)，shell wrapper 中是否存在 [command injection](../pentesting-web/command-injection.md)，攻击者可控 URL 是否导致 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)，文件操作是否存在路径遍历，模板/代码求值器是否可导致 RCE，以及对象解析器是否存在 [unsafe deserialization](../pentesting-web/deserialization/README.md)。

对每个候选项，证明以下链路：<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

只读集成仍可能被利用：只要后续任何组件能够发布其读取的内容即可。测试普通响应，也要测试较不明显的出站渠道，例如攻击者控制的链接、自动获取的图像、webhook、日志、报告、计数器、通知，以及发送给其他 agent 的消息。<sup>[[2]](#references)</sup>

## 对目标采取行动

确认某项操作后，应评估完整的影响范围，而不是在首次出现可见效果时就停止：<sup>[[2]](#references)</sup>

- **数据外泄：**机密、用户记录、内部文件、对话数据或提示词/上下文内容通过可观察的渠道流出。
- **未授权操作：**agent 利用合法的写入能力来达成攻击者的目标。
- **拒绝服务：**破坏性工具或反复执行的高成本操作影响完整性或可用性。
- **持久化：**遭到投毒的记忆、索引内容、可信状态或运行时变更，在发起它的会话结束或源内容移除后仍然存在。
- **传播：**可信的对等方使用遭到入侵的 agent 发来的消息或共享状态，并使用自身的工具和凭据重复执行该操作。

严重程度应依据可触达的数据、实际权限、接收端的可利用性、出站能力、持久化和传播情况来判断，而非模型输出的文本有多么出人意料。<sup>[[2]](#references)</sup>

## 评估期间要验证的控制措施

提示词过滤器和更完善的系统提示词可以提高攻击成本，但不应将其视为授权边界。通过直接输入、间接内容、记忆、工具和对等 agent，重新运行同一攻击链，以验证以下控制措施：<sup>[[2]](#references)</sup>

- 确定性的策略层会在**每次工具调用**时检查已认证用户、租户、对象、操作和目标；模型无法提供或覆盖调用者身份。
- 读写能力使用相互隔离、遵循最小权限原则且有效期较短的凭据；高影响工具仅在需要时开放，绝不会因摄取的内容而自动执行。
- 网络出站流量和内部目标会独立于模型选定的 URL 进行允许列表限制；除非有必要，否则会阻止运行时访问元数据端点、已挂载的机密和相邻服务。
- 审批界面根据规范化的结构化请求生成，并显示确切参数、身份、目标、受影响对象和副作用，而不是模型自由撰写的摘要。
- 成功状态会从目标系统或权威数据源中验证。agent 的描述、工具调用请求或 HTTP 重定向，都不能证明所声称的状态变更确实发生。
- 记忆和检索条目会保留来源信息和信任标签，可以被作废，并在用于后续操作时重新授权。
- agent 间的消息会经过身份验证，并作为不可信请求进行授权；对等方的声誉或 agent card 不会自动赋予接收方工具的使用权限。

## References

- [1] [2026 年 OWASP Agentic Applications 十大风险](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [攻击 AI Agent 指南](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [将 AI Agent 逃出其沙箱到底有多难？](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK 中的 Subagents](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode 中间件源码](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev 模型的参差性：对抗性内容](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [作为裁判的 Jev：伪造策略如何影响 Jev 的判断](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
