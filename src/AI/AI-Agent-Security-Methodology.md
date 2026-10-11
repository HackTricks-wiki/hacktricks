# AI Agent 安全方法论

{{#include ../banners/hacktricks-training.md}}

Agent assessment 应遵循**从攻击者可控输入到外部可观察效果**的路径。Jailbreaking、字符变更和系统提示词泄露可以证明推理通道可被影响，但高影响发现是进一步形成一条链，触及数据访问、未授权工具操作、下游注入 sink、持久化或其他 agent。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 可用于标记覆盖范围（目标劫持、工具滥用、权限滥用、供应链、代码执行、记忆投毒、agent 间信任、级联故障、人类信任和 rogue agent）。应先构建端到端攻击路径，再使用这些标签，而不是把模型输出意外文本当作测试终点。<sup>[[1]](#references)[[2]](#references)</sup>

## 构建目标映射

编写 payload 前，记录每个 agent 工作流的以下五个维度：<sup>[[2]](#references)</sup>

| 维度 | 枚举内容 | 安全问题 |
|---|---|---|
| **不可信输入** | Chat/API 参数、URL、文档、电子邮件、工单、日历条目、检索到的文本块、记忆、工具结果和 peer-agent 消息 | 攻击者可以将内容放在哪里，使其之后进入模型上下文？ |
| **工具** | 工具名称和 schema、副作用、自动执行、确认行为和动态加载的工具 | 哪些调用会读取机密、写入状态、发送消息、删除数据、执行代码或转移价值？ |
| **权限** | 用户授权、服务账号、API token、凭证有效期、租户/资源范围和网络可达性 | 每次调用以哪个身份运行？工具边界处是否会重复授权检查？ |
| **处理过程** | 查询构建器、shell、URL fetcher、模板引擎、解释器、解析器、文件操作和反序列化器 | 模型生成的数据会在哪里变成另一个解释器的语法？ |
| **输出** | 响应、渲染后的 Markdown/HTML、链接、图像抓取、webhook、电子邮件、文件、日志、报告、指标和 peer-agent 流量 | 哪个可观察通道可能携带机密或触发二次请求？ |

不要把这些内容简化成一份产品宣传中的集成列表。实用的交付物应将每个来源映射到它到达的确切上下文位置、该位置可用的工具、每个工具使用的凭证、下游解释器以及所有出站路径。同一个工具使用用户专属的只读 token 时影响可能很低，使用共享管理员凭证时则可能造成严重影响。<sup>[[2]](#references)</sup>

## 侦察

### 映射所有传递和摄取路径

从传递入口（Web、移动端、API、电子邮件、聊天平台、浏览器扩展）入手，并代理客户端到后端的流量。检查 UI 隐藏的字段、搜索/自动补全/筛选参数、对话状态对象、上传和索引任务、工具响应以及子 agent 流量。仅支持移动端的客户端可能需要使用 emulator 和 instrumentation 绕过 certificate pinning，才能看到真实请求 schema。<sup>[[2]](#references)</sup>

然后映射模型下方的技术栈：编排框架、提示词组装、检索和记忆存储、运行时（例如 Python、container 或 WASM）、挂载卷、主机服务、内部 API、云 metadata 可达性以及相邻网络。框架默认设置很重要，因为某些“工具调用”是通过生成或执行代码实现的；运行时/sandbox 边界决定了结果是否会被限制在其中。<sup>[[2]](#references)</sup>

### 使用无破坏性探测识别路由

将一个范围内的请求与多个无关请求进行比较，同时保留完整响应、状态码、延迟和流式传输行为。在任何特定任务推理开始前就出现稳定拒绝，可能表示存在独立的 gateway/classifier；上下文相关的拒绝则表明请求已到达模型；空响应或纯抽取式回答可能表示使用了关键词搜索或范围狭窄的检索。将这些视为假设，并通过其他 API 字段和摄取路径重放相同探测来确认。<sup>[[2]](#references)</sup>

当 assessment 能指出最早一个会改变 agent 行为的攻击者可控来源，**并且**能列出从该来源可到达的工具、身份、解释器和输出时，侦察才算完成。<sup>[[2]](#references)</sup>

## 利用：跨越信任边界

测试通道，而不只是提示词措辞。先通过直接注入确认可见入口会阻止什么，再通过以下较隐蔽的路径重复测试等效意图：<sup>[[2]](#references)</sup>

- **间接内容：**页面、文件、电子邮件、工单、metadata、alt 文本、HTML 注释、屏幕外文本或零宽字符。payload 传递技巧请参阅 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)。
- **检索和记忆：**投毒之后会被检索的内容，或之后会在其他会话中重新加载的状态。记录删除原始来源是否会消除该行为。
- **工具输出和 peer agent：**在工具响应或 agent 间消息中放置 marker，以测试内部流量是否绕过了仅应用于用户输入和最终输出的过滤器。
- **供应链：**将工具描述符、插件、连接的服务器、skills、模型和依赖项视为可信指令来源进行审查。MCP 专项测试请参阅 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)。
- **人工审批：**比较实际的结构化工具调用与模型生成的审批文本。测试攻击者影响是否能省略目的地、范围、受影响对象或不可逆副作用。

先使用无害且唯一的 marker。保留来源 artifact、可观察到的组装上下文、选中的工具调用、审批数据、后端请求/响应以及最终状态。这样可以区分实际影响与模型声称操作已执行但实际上只是幻觉的情况。<sup>[[2]](#references)</sup>

## 执行：证明真实影响

从影响到实际效果有两条不同路径：<sup>[[2]](#references)</sup>

1. **能力滥用：**已授权的工具本身就能完成目标。例如读取某个租户的记录并将其写入攻击者可见的报告、发送电子邮件、修改记录、删除文件或发起付款。无需存在次级软件漏洞。
2. **利用下游 sink：**攻击者引导的模型输出变成另一个组件的语法。检查数据库查询是否存在 [SQL injection](../pentesting-web/sql-injection/README.md) 或 [NoSQL injection](../pentesting-web/nosql-injection.md)，shell wrapper 是否存在 [command injection](../pentesting-web/command-injection.md)，指定的 URL 是否导致 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)，文件操作是否存在路径遍历，模板/代码求值器是否存在 RCE，以及对象解析器是否存在 [unsafe deserialization](../pentesting-web/deserialization/README.md)。

针对每个候选项，证明以下链条：<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

只读集成仍可能被利用：只要后续任何组件能够发布它读取的内容，就存在风险。测试常规响应以及不太明显的外传途径，例如攻击者控制的链接、自动获取的图片、webhook、日志、报告、计数器、通知，以及发送给其他代理的消息。<sup>[[2]](#references)</sup>

## 对目标采取行动

确认某项操作后，应评估完整的影响范围，而不是在出现第一个可见效果时就停止：<sup>[[2]](#references)</sup>

- **数据外传：**机密、用户记录、内部文件、对话数据或提示词/上下文内容通过可观测渠道泄露。
- **未授权操作：**代理利用合法的写入能力实现攻击者的目标。
- **拒绝服务：**破坏性工具或反复执行高成本操作影响完整性或可用性。
- **持久化：**被污染的记忆、索引内容、可信状态或运行时变更，在发起会话结束或移除源内容后仍然存在。
- **传播：**可信的对等方使用受感染代理发送的消息或共享状态，并利用自己的工具和凭证重复执行该操作。

严重性应根据可触达的数据、实际权限、接收端的可利用性、外传途径、持久化和传播能力来评估，而不是看模型输出有多出人意料。<sup>[[2]](#references)</sup>

## 评估期间需要验证的控制措施

提示词过滤器和更好的系统提示词可以提高攻击者的成本，但不应被视为授权边界。通过直接输入、间接内容、记忆、工具和对等代理，重新运行同一攻击链，以验证以下控制措施：<sup>[[2]](#references)</sup>

- 确定性的策略层会在**每次工具调用**时检查已认证的用户、租户、对象、操作和目标；模型不能提供或覆盖调用方身份。
- 读取和写入能力使用相互独立、遵循最小权限原则且短期有效的凭证；高影响工具仅在需要时开放，且绝不根据摄取的内容自动执行。
- 网络外传和内部目标分别通过允许列表进行限制，不受模型选择的 URL 影响；除非确有需要，否则阻止运行时访问元数据端点、挂载的机密和相邻服务。
- 审批 UI 根据规范化的结构化请求生成，并展示准确的参数、身份、目标、受影响对象和副作用，而非模型的自由格式摘要。
- 从目标系统或事实来源验证操作是否成功。代理的叙述、工具调用请求或 HTTP 重定向，都不能证明所声称的状态变更确实发生。
- 记忆和检索条目保留来源信息和信任标签，可被作废，并在用于后续操作时重新授权。
- 代理间消息经过身份验证，并被视为未经信任的请求；对等代理的声誉或 agent card 不会自动授予接收方工具的使用权限。

## References

- [1] [2026 年 OWASP Agentic Applications 十大风险](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [攻击 AI Agents 指南](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
