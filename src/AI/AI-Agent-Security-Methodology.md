# AI Agent 安全方法论

{{#include ../banners/hacktricks-training.md}}

Agent assessment 应遵循**从攻击者可控输入到外部可观察影响**的路径。Jailbreaking、字符变更和 system prompt 泄露可以证明推理通道可受影响，但高影响发现是这条链路最终触及数据访问、未经授权的工具操作、下游注入 sink、持久化或其他 agent。<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) 可用于标记覆盖范围（目标劫持、工具滥用、权限滥用、供应链、代码执行、记忆投毒、agent 间信任、级联故障、人类信任和 rogue agents）。应先构建端到端攻击路径，再使用这些标签，而不是把模型生成意外文本视为测试终点。<sup>[[1]](#references)[[2]](#references)</sup>

## 构建目标图谱

编写 payload 前，先记录每个 agent 工作流的以下五个维度：<sup>[[2]](#references)</sup>

| 维度 | 需要枚举的内容 | 安全问题 |
|---|---|---|
| **不可信输入** | Chat/API 参数、URL、文档、电子邮件、工单、日历条目、检索到的文本块、记忆、工具结果和 peer-agent 消息 | 攻击者能把内容放在哪里，使其之后进入模型上下文？ |
| **工具** | 工具名称和 schema、副作用、自动执行、确认行为和动态加载的工具 | 哪些调用会读取机密、写入状态、发送消息、删除数据、执行代码或转移价值？ |
| **权限** | 用户委派、服务账户、API token、凭证有效期、租户/资源范围和网络可达性 | 每个调用以哪个身份运行？是否在工具边界重复执行授权检查？ |
| **处理** | 查询构造器、shell、URL fetcher、模板引擎、解释器、解析器、文件操作和反序列化器 | 模型生成的数据会在哪里变成另一个解释器的语法？ |
| **输出** | 响应、渲染后的 Markdown/HTML、链接、图像 fetch、webhook、电子邮件、文件、日志、报告、指标和 peer-agent 流量 | 哪个可观察通道可能泄露机密或触发次级请求？ |

不要把这些内容简化成一份宣传中的集成列表。实用的产物应将每个来源映射到其进入的确切上下文位置、该位置可用的工具、每个工具使用的凭证、下游解释器以及所有出站路径。同一个工具使用按用户隔离的读取 token 时影响可能较低，使用共享管理员凭证时则可能是严重风险。<sup>[[2]](#references)</sup>

## 侦察

### 映射所有传递和摄取路径

从传递面开始（web、mobile、API、电子邮件、聊天平台、browser extension），并代理客户端到后端的流量。检查 UI 隐藏的字段、搜索/自动补全/筛选参数、对话状态对象、上传和索引任务、工具响应以及 sub-agent 流量。仅支持 mobile 的客户端可能需要 emulator 和 instrumentation 来绕过 certificate pinning，之后才能看到真实请求 schema。<sup>[[2]](#references)</sup>

接着梳理模型下方的技术栈：编排框架、prompt 组装、检索和记忆存储、运行时（例如 Python、container 或 WASM）、挂载卷、主机服务、内部 API、云 metadata 可达性以及邻近网络。框架默认设置很重要，因为某些“工具调用”是通过生成或求值代码实现的；运行时/sandbox 边界决定了结果能否被限制在隔离范围内。<sup>[[2]](#references)</sup>

### 使用非破坏性探测识别路由

将范围内的请求与若干无关请求进行比较，同时保留完整响应、状态码、延迟和流式传输行为。在任何特定任务推理前就稳定拒绝，可能说明存在独立的 gateway/classifier；上下文相关的拒绝表明请求已到达模型；空回答或纯抽取式回答可能表示使用了关键词搜索或有限检索。将这些视为假设，并通过其他 API 字段和摄取路径重放同一探测来确认。<sup>[[2]](#references)</sup>

当 assessment 能指出最早的攻击者可控来源（该来源会改变 agent 行为），**并且**能确定从该来源可到达的工具、身份、解释器和输出时，侦察才算完成。<sup>[[2]](#references)</sup>

## 利用：跨越信任边界

测试通道，而不只是 prompt 措辞。先通过直接 injection 确认可见入口会拦截什么，然后通过以下不那么显眼的路径重复测试等效意图：<sup>[[2]](#references)</sup>

- **间接内容：**网页、文件、电子邮件、工单、metadata、alt text、HTML 注释、屏幕外文本或零宽字符。有关 payload 传递技术，参见 [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)。
- **检索和记忆：**投毒内容，使其之后会被检索；或投毒状态，使其在后续会话中重新加载。记录删除原始来源是否会消除该行为。
- **工具输出和 peer agents：**在工具响应或 agent-to-agent 消息中放入标记，以测试内部流量是否绕过了仅应用于用户输入和最终输出的过滤器。
- **供应链：**将工具描述符、插件、已连接的服务器、skills、模型和依赖项视为可信指令来源进行审查。MCP 专项测试参见 [MCP Servers](AI-MCP-Servers.md#mcp-vulns)。
- **人工审批：**将实际的结构化工具调用与模型生成的审批文本进行比较。测试攻击者影响是否能省略目标位置、范围、受影响对象或不可逆副作用。

先使用无害且唯一的标记。保留源文件、可观察到的组装后上下文、选定的工具调用、审批数据、后端请求/响应和最终状态。这样可以区分实际影响与模型声称操作已发生的幻觉。<sup>[[2]](#references)</sup>

### 工具风险判定器中的策略式文本

基于模型的工具门控可能会在原本有用的分类上下文中收到攻击者可控文本。例如，LangChain 的实验性 `AutoModeMiddleware` 会向 TypeSafe `is_risky` 判定器发送拟议的工具调用、其参数、可选的工具描述以及最近最多 30 条消息。如果返回的 Noul 概率大于或等于 `0.5`，它就会阻止已配置的工具；此 middleware 不会对未列出的工具进行分类。<sup>[[5]](#references)</sup> TypeSafe 也警告称，即使 state 原本只作为数据使用，其中的对抗性文本仍可能影响分类。<sup>[[6]](#references)</sup>

**伪造策略**不同于单纯声称自己是 system message。它会在低信任级别的 state 中加入另一套标签或风险定义，并诱导判定器使用这些定义，而非开发者定义的标准。在 Datadog 的测试中，用户可编辑的 `profile_description` 与 `can_edit:false` 一同被复制进工具参数。其策略式文本声称写入尝试风险较低，因为独立的权限检查应在任何修改发生前拒绝该操作。在 40 次运行中，`is_risky` 平均分从 `0.893` 降至 `0.290`，而直接 role-spoofing 对照组的平均分为 `0.905`。平均分低于 `0.5` 并不能证明每次调用都通过了门控，而且该实验**没有**证明发生了未经授权的写入。<sup>[[7]](#references)</sup>

测试这个边界时，要区分分类器的判定和工具实际的授权结果。检查哪些可编辑字段会传递给判定器；比较加入和不加入策略式文本时对同一拟议操作的判定；并独立验证最终状态。独立的权限检查仍必须依据经过身份验证的请求者权限，而不能依据 connector 的服务账户权限。<sup>[[7]](#references)</sup>其他分类器失效模式参见 [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass)；[LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) 涉及的是不同的路由和凭证边界。

### Subagent 上下文隔离

非 fork 的 Claude Agent SDK subagent 会收到自己的 `AgentDefinition.prompt`、委派 prompt 和可用工具，但不会收到 parent system prompt 或对话。如果其定义中省略了 `tools`，它会继承 subagent 可用的工具；项目的 `CLAUDE.md` 仍可能被加载。如果 child 能使用相同的 filesystem 或执行工具，那么仅对 parent 设置 prompt 限制就不是可靠的边界。<sup>[[4]](#references)</sup>

通过比较 parent 拒绝的直接请求与委派给指定 subagent 的同一任务来测试边界。NCC Group 报告称，将被拒绝的操作系统文件枚举任务改述为对 child 执行无害的“布局映射”后，成功完成了该操作。<sup>[[3]](#references)</sup>

检查 child 的实际工具调用和有效工具 allowlist，而不只是 parent 的最终回答；确认 child 是否访问了 parent 不会访问的文件。<sup>[[4]](#references)</sup>这是 guardrail 继承失效，并不能证明发生了 [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) 或 container escape。<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI agents：屏幕指令和操作重绑定

Phone GUI agent 可能会在选择下一步跨应用操作前，将每张截图发送给 cloud model。要测试**间接视觉 injection**，可将攻击者可控文本放在 agent 会在授权任务期间查看的 SMS、电子邮件或网页中。比较直接任务 prompt 与仅在截图中可见的相同指令，然后检查下一步操作以及任何高风险操作判定。在被评估的 assistant 中，客户端的 `checkPrompt` 会筛查直接任务文本，但不会对截图内容应用等效过滤。这是 [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md) 的 mobile 跨应用变体，并非绕过 Android 组件认证的方法。<sup>[[9]](#references)</sup>

一个说明性的副作用测试是使用攻击者控制的表单，要求 agent 填写敏感字段，然后请求人工点击“upload”；与此同时，页面会在字段发生变化时立即提交已填内容。人工介入无法保护已被页面代码发送的数据；应验证实际提交，而不要把 agent 的叙述视为操作发生的证明。来源将其描述为一种可能的模式，而非每个 assistant 都已遭到入侵的证明。<sup>[[9]](#references)</sup>

**GUI TOCTOU / 操作重绑定**是另一种独立的失效模式：agent 根据 `t0` 时观察到的屏幕规划输入，但在 `t1` 注入输入之前，前台 UI 已发生变化。<sup>[[8]](#references)</sup>之后在 `t2` 截取的屏幕截图无法撤销已经执行的操作。<sup>[[9]](#references)</sup>在获得授权的 Android 测试中，可复用的工作流如下：<sup>[[8]](#references)</sup>

1. 确定目标控件的屏幕坐标，并在受控 app 中的相同位置渲染一个无害控件。
2. 让该载体保持可见，直到 agent 观察到它，然后在其观察与操作之间的间隙触发正常的前台切换。
3. 检查规划的点击是否落在新 app 的控件上，并在目标 app 中验证最终状态，而不要依赖 agent 的叙述。

原始的操作重绑定研究使用一个不持有危险权限的 app 展示了这一方法；研究还描述了通过 agent 的任务恢复循环重复切换，以处理多步骤流程。<sup>[[8]](#references)</sup>

**不要**假设这一原语可以不加修改地适用于所有 assistant。在 Doubao assessment 中，如果顶层 Activity 已发生变化，`OpClickUI` 会跳过点击；如果前面的三步中出现过 `OpOpenApp`，它就会比较屏幕截图。因此，单击、长按和双击都几乎无法提供可靠的攻击者可控时机。`OpTypeText`、`OpSwipeUI` 和 `OpScrollWheelAction` 没有同等的防护措施，但报告认为它们的实际影响较有限。<sup>[[9]](#references)</sup>

## 执行：证明实际影响

从影响到实际结果有两条不同的路径：<sup>[[2]](#references)</sup>

1. **能力滥用：**已授权的工具本身就能完成目标。例如，读取一个租户的记录并将其写入攻击者可见的报告、发送电子邮件、修改记录、删除文件或发起付款。这不需要额外的软件漏洞。
2. **利用下游 sink：**攻击者引导的模型输出成为另一个组件的语法。检查数据库查询中的 [SQL injection](../pentesting-web/sql-injection/README.md) 或 [NoSQL injection](../pentesting-web/nosql-injection.md)、shell wrapper 中的 [command injection](../pentesting-web/command-injection.md)、攻击者可选 URL 中的 [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md)、文件操作中的路径穿越、模板/代码求值器中的 RCE，以及对象解析器中的 [unsafe deserialization](../pentesting-web/deserialization/README.md)。

对每个候选项，都要证明以下链路：<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

只读集成仍可能被利用，只要后续任何组件能够发布其读取的内容。测试常规响应，以及不太显眼的出站通道，例如攻击者控制的链接、自动获取的图片、webhook、日志、报告、计数器、通知，以及发送给其他 agent 的消息。<sup>[[2]](#references)</sup>

## 对目标采取行动

确认某项操作后，应评估完整的影响范围，而不是在首次显现效果时就停止：<sup>[[2]](#references)</sup>

- **数据外泄：**机密信息、用户记录、内部文件、对话数据或提示词/上下文内容通过可观察的通道外泄。
- **未授权操作：**agent 利用合法的写入能力实现攻击者的目标。
- **拒绝服务：**破坏性工具或反复执行的高成本操作影响完整性或可用性。
- **持久化：**被投毒的记忆、索引内容、可信状态或运行时变更，在发起会话结束或源内容被移除后仍然存在。
- **传播：**可信的对等方使用受损 agent 发送的消息或共享状态，并使用自身工具和凭证重复执行该操作。

严重程度应根据可访问的数据、有效权限、接收端的可利用性、出站通道、持久化和传播情况来评估，而不是根据模型生成的文本看起来有多么出乎意料。<sup>[[2]](#references)</sup>

## 评估期间需验证的控制措施

提示词过滤器和更完善的 system prompt 可以提高攻击者的成本，但不应被视为授权边界。应通过直接输入、间接内容、记忆、工具和对等 agent，重新执行同一攻击链，以验证以下控制措施：<sup>[[2]](#references)</sup>

- 确定性的策略层会在**每次工具调用**时检查经过身份验证的用户、租户、对象、操作和目标位置；模型无法提供或覆盖调用者身份。
- 读取和写入能力使用相互独立、遵循最小权限原则且有效期较短的凭证；高影响工具仅在需要时开放，绝不因摄取的内容而自动执行。
- 网络出站流量和内部目标位置采用独立于模型所选 URL 的允许列表；除非必要，否则应阻止运行时访问元数据端点、挂载的机密信息和相邻服务。
- 审批 UI 根据规范的结构化请求生成，并显示确切的参数、身份、目标位置、受影响对象和副作用，而非模型的自由格式摘要。
- 应从目标系统或权威数据源验证操作是否成功。agent 的叙述、工具调用请求或 HTTP 重定向，都不能证明其所声称的状态变更已发生。
- 记忆和检索条目保留来源信息和信任标签，可被作废；在后续操作中使用时，必须重新授权。
- agent 间消息应作为不可信请求进行身份验证和授权；对等方的声誉或 agent card 不会自动委托接收方的工具权限。

有关 A2A agent card、任务流程及其攻击面，请查看 [A2A Protocol Security](AI-A2A-Protocol.md)。

## References

- [1] [2026 年 OWASP Agentic Applications Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [《黑客攻击 AI Agent 指南》](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [《要让 AI Agent 逃出沙箱，究竟有多难？》](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [SDK 中的 Subagent](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [LangChain TypeSafe Auto Mode 中间件源代码](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev 模型的锯齿性：对抗性内容](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [让 Jev 担任评判：伪造的策略如何操控 Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [零权限操控：我们能信任由大型多模态模型驱动的 GUI Agent 吗？](https://arxiv.org/html/2601.12349v1)
- [9] [当 AI 助手成为黑客攻击链的一环 | 豆包手机安全分析](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
