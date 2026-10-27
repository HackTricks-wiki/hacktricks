# Burp MCP：LLM 辅助流量审查

{{#include ../banners/hacktricks-training.md}}

## 概述

Burp 的 **MCP Server** 扩展可以向支持 MCP 的 LLM 客户端提供被拦截的 HTTP(S) 流量，以便它们基于**真实请求/响应进行分析**，发现漏洞并起草报告。以 Burp 为事实来源：使用被动分析或有意进行单变量重放，而不是盲目扫描。<sup>[[8]](#references)</sup>

## 架构

- **Burp MCP Server (BApp)** 默认监听 `127.0.0.1:9876`，并通过 MCP 提供被拦截的流量。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** 将 stdio（客户端一侧）桥接到 Burp 的 MCP SSE 端点。
- **可选的本地反向代理**（Caddy）会规范化标头，以满足严格的 MCP 握手检查。
- **客户端/后端**：Codex CLI（cloud）、Gemini CLI（cloud）或 Ollama（local）。

## 设置

### 1) 安装 Burp MCP Server

从 Burp BApp Store 安装 **MCP Server**，并确认其正在监听 `127.0.0.1:9876`。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) 提取 proxy JAR

在 MCP Server 选项卡中，点击 **Extract server proxy jar** 并保存 `mcp-proxy-all.jar`。<sup>[[7]](#references)</sup>

### 3) 配置 MCP 客户端（以 Codex 为例）

将客户端指向 proxy JAR 和 Burp 的直接 SSE 端点。打包的 proxy 是一个 stdio-to-SSE 桥接程序；它不会取代 Burp 监听器。<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

等效的 Codex 命令是：<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

然后运行 Codex 并列出 MCP 工具：

```bash
codex
# inside Codex: /mcp
```

### 4) 使用 Caddy 修复严格的 Origin/请求头验证（如有需要）

如果 MCP 握手因严格的 `Origin` 检查或额外请求头而失败，请使用本地反向代理规范化请求头（这与针对 Burp MCP 严格验证问题的变通方法一致）。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
brew install caddy
mkdir -p ~/burp-mcp
cat >~/burp-mcp/Caddyfile <<'EOF'
:19876

reverse_proxy 127.0.0.1:9876 {
  # lock Host/Origin to the Burp listener
  header_up Host "127.0.0.1:9876"
  header_up Origin "http://127.0.0.1:9876"

  # strip client headers that trigger Burp's 403 during SSE init
  header_up -User-Agent
  header_up -Accept
  header_up -Accept-Encoding
  header_up -Connection
}
EOF
```

启动代理和客户端，并且仅在使用此 Caddy 监听器时，将配置的 `--sse-url` 更改为 `http://127.0.0.1:19876`：<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) 将浏览器状态与代理证据关联（Playwright MCP）

配置 Playwright MCP，使其浏览器使用 Burp 的代理。这样，agent 就能将渲染后的 DOM/无障碍状态与生成它的确切 HTTP 历史记录关联起来。<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

调整 listener 地址，重启 Codex，并使用 `/mcp` 验证两个集成。示例禁用了浏览器证书错误，以免 Burp 本地生成的证书阻止 HTTPS 拦截。<sup>[[6]](#references)[[8]](#references)</sup>

## 支持代理的浏览器自动化（OpenBurp）

Burp MCP 连接和被拦截的浏览器流量是两条独立的数据流。MCP 服务在 `127.0.0.1:9876` 上提供 Burp 工具，而专用的 Chromium 实例会通过 `127.0.0.1:8080` 上的 Burp 代理发送 HTTP(S) 流量。因此，MCP 工具直接生成的请求可能不会出现在 **Proxy > HTTP history** 中；如果需要观察、编辑请求/响应或将其保留为证据，请使用经过代理的浏览器。<sup>[[2]](#references)[[9]](#references)</sup>

支持 SSE 的客户端可以直接注册 Burp。仅支持 stdio 的客户端则可以启动 PortSwigger 的代理 JAR。无论哪种情况，都要注册第二个浏览器控制 MCP，并将其指向 Burp 内置的 Chromium（`BURP_CHROMIUM` 是本地可执行文件路径）：<sup>[[9]](#references)</sup>

```bash
# Claude Code: direct SSE plus a proxied browser
claude mcp add -s project -t sse burpsuite http://127.0.0.1:9876/
claude mcp add -s project -t stdio chrome-devtools -- chrome-devtools-mcp \
  --executablePath "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --accept-insecure-certs --isolated

# Codex: SSE-to-stdio bridge plus a proxied browser
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
codex mcp add burp-browser -- npx -y @playwright/mcp@latest \
  --executable-path "$BURP_CHROMIUM" --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors --isolated
```

TLS-bypass flag 会接受由拦截代理生成的证书，而 `--isolated` 可防止评估过程复用操作人员的常规浏览器配置文件。隔离能保护配置文件状态，但**不是安全沙箱**：控制器仍可访问在该测试浏览器中打开的已认证会话，Burp MCP 也可能暴露敏感请求、响应和配置。<sup>[[9]](#references)</sup>

在调试客户端桥接之前，请单独测试 SSE 监听器：<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

健康的 listener 会返回 `Content-Type: text/event-stream`。收到 headers 后超时是预期行为，因为 SSE stream 会保持打开，以便接收后续 events。如果客户端仍然失败，请确认 extension 配置的 route：PortSwigger 指出，endpoint 可能是根路径或 `/sse`，具体取决于客户端和 extension 配置。<sup>[[9]](#references)[[7]](#references)</sup>

## 使用不同的客户端

### Codex CLI

- 按上述说明配置 `~/.codex/config.toml`。
- 运行 `codex`，然后运行 `/mcp`，确认 Burp 工具列表。

### Gemini CLI

**burp-mcp-agents** repo 提供了启动器辅助工具：<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama（本地）

使用提供的启动器助手并选择一个本地模型：

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

示例本地模型及其大致 VRAM 需求：

- `deepseek-r1:14b`（~16GB VRAM）
- `gpt-oss:20b`（~20GB VRAM）
- `llama3.1:70b`（48GB+ VRAM）

## 基于证据的重放与验证

不要让 agent 把看似合理的解释或中间响应当作证明。使用 Burp 请求/响应以及独立观察到的浏览器状态，让每项测试都可证伪。<sup>[[8]](#references)</sup>

1. 保存一组基线请求/响应，并确定由攻击者控制的确切组件。
2. 比较授权情况时，在修改标识符、cookie 或 token 之前，分别在两个账户下独立捕获相同的工作流。
3. 重放修改前，记录假设、证据位置、预期信号，以及哪些结果会推翻该假设。
4. 每次只修改一个组件，保留生成的请求/响应对，并分别标注直接观察结果与推断。
5. 将每个候选项标记为 `open`、`blocked`、`rejected` 或 `confirmed`；仅当新证据改变了机制或前提条件时才重新检查。
6. 确认攻击者控制能力、可达性、可重复性、约束绕过、影响及最终应用状态。如果所声称的状态变化发生在后续环节，那么重定向或成功的工具调用并不能证明该变化。

将利用细节保留在相关技术页面中。例如，浏览器消息候选项应归入 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)，而 token key-selection 行为应归入 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)。<sup>[[8]](#references)</sup>

简洁的假设记录有助于避免并行 agent 重复尝试同一条看似诱人的分支：<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## 使用 Burp MCP 对 WebSocket frame 进行分流排查

官方扩展通过 `get_proxy_websocket_history_regex` 提供对 Burp WebSocket history 的只读分页搜索。它接受 `regex`、`count` 和 `offset`；与 `send_http1_request` 不同，它不会发送 WebSocket frame。即使关闭 Intercept，Burp 也会记录两个方向的消息，因此在将少量相关 frame 交给模型前，应先筛选 history。<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. 使用两个分别通过身份验证的测试账户，通过 Burp 代理浏览器触发同一个由 WebSocket 支持的操作。将每个 upgrade handshake 及其 cookies、connection ID、frame 方向和 response frames 一并保留；第一个账户连接上的 server-to-client event，不能证明第二个账户收到了该 event。
2. 使用范围较窄的表达式搜索 `get_proxy_websocket_history_regex`，例如 `(?i)(subscribe|room|tenant|objectId)`，并设置 `count: 20` 和 `offset: 0`。递增 `offset` 以检查后续匹配项。对比 outbound frame 中的 object 或 topic identifier 与**同一 connection**上的 response。
3. 在 **Proxy > WebSockets history** 中，将候选 outbound frame 发送到 Repeater。将其附加到相应的开放 connection，或使用第二个账户的 handshake 重新连接。只更改 object/topic identifier，并将生成的 server messages 和 application state 与两个基线进行比较。MCP history 工具无法执行此重放；WebSocket Repeater 可以编辑、重新发送和重新连接 frames。

对于 cross-site WebSocket hijacking 和 broker topic authorization 等特定协议测试，请参阅 [WebSocket Attacks](../pentesting-web/websocket-attacks.md)。不要将成功的 upgrade 或 client-side echo 视为受保护 subscription 成功的证据。

## 使用 Burp MCP 进行定向带外验证

Burp Suite Professional 通过官方 MCP 扩展提供 `generate_collaborator_payload` 和 `get_collaborator_interactions`。将它们与 `get_proxy_http_history_regex` 及一次 `send_http1_request` 重放结合使用，可测试疑似 server-side URL fetch，而无需扫描整个目标。Burp 可能需要单独批准读取 history 和发送 request。<sup>[[2]](#references)[[10]](#references)</sup>

1. 筛选 history，查找包含 URL 的候选 request，例如包含 `url=`、`webhook` 或 `callback` 的 request。保存原始 request 和 response。history 工具接受 `regex`、`count` 和 `offset`；应分页检索，而不是让模型检查每个条目。<sup>[[10]](#references)</sup>
2. 生成新的 Collaborator payload，并保留其返回的 **payload ID**。将捕获的 request 重放到同一 host 和 port，只将候选 URL 改为该 payload domain 下的 HTTPS URL。对于 `send_http1_request`，将完整的 HTTP/1.1 request 作为 `content` 传入，并提供 `targetHostname`、`targetPort` 和 `usesHttps`；destination fields 指定的是 **application**，而非 Collaborator host。<sup>[[10]](#references)</sup>
3. 使用该 payload ID 轮询 `get_collaborator_interactions`，并将 interaction 时间与重放时间关联起来。HTTP interaction 支持存在 fetch 的判断，而仅有 DNS 记录只能说明发生了解析，不能证明完成了 HTTP request。检查 interaction source 和 request headers，以区分 server egress 与 browser-side loading；然后使用新的 payload 重复测试，以排除无关流量。<sup>[[10]](#references)[[11]](#references)</sup>

MCP request 工具会直接返回 response，且不一定会将其写入 **Proxy > HTTP history**。请保存其 request/response 结果，或使用代理浏览器或 Repeater 获取可在 history 中查证的记录。选择 SSRF payload 及进行后续测试时，请参阅 [SSRF 章节](../pentesting-web/ssrf-server-side-request-forgery/)，不要将带外 callback 视为内部网络受影响的证据。测试 MCP server 本身，请参阅 [MCP server 测试](AI-MCP-Servers.md#remote-mcp-server-testing-workflow)。<sup>[[7]](#references)[[11]](#references)</sup>

## 被动审查提示词包

**burp-mcp-agents** repo 包含用于基于证据分析 Burp traffic 的提示词模板：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：广泛发现被动漏洞。
- `idor_hunter.md`：检查 IDOR/BOLA/object/tenant 偏差及 auth 不匹配。
- `auth_flow_mapper.md`：比较已通过身份验证与未通过身份验证的路径。
- `ssrf_redirect_hunter.md`：从 URL fetch 参数和 redirect chains 中发现 SSRF/open-redirect 候选项。
- `logic_flaw_hunter.md`：发现多步骤逻辑缺陷。
- `session_scope_hunter.md`：发现 token audience/scope 误用。
- `rate_limit_abuse_hunter.md`：发现 throttling/abuse 缺口。
- `report_writer.md`：撰写以证据为重点的报告。

## 可选的流量归因标记

若要在日志中标记 Burp/LLM 流量，请添加 header rewrite（proxy 或 Burp Match/Replace）：<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## 安全注意事项

- 当流量包含敏感数据时，优先使用 **本地模型**。
- 仅分享发现问题所需的最少证据。
- 将 Burp 作为事实来源；使用模型进行**分析和报告**，而不是 scanning。

## Burp AI Agent（AI 辅助分诊 + MCP 工具）

**Burp AI Agent** 是一款 Burp 扩展，可将本地/云端 LLM 与被动/主动分析（62 种漏洞类别）结合，并提供 53+ 个 MCP 工具，供外部 MCP 客户端协调 Burp 操作。<sup>[[5]](#references)</sup> 主要功能：

- **上下文菜单分诊**：通过 Proxy 捕获流量，打开 **Proxy > HTTP History**，右键单击请求 → **Extensions > Burp AI Agent > Analyze this request**，即可启动一个绑定到该请求/响应的 AI 聊天会话。
- **后端**（可针对每个配置文件选择）：
  - 本地 HTTP：**Ollama**、**LM Studio**。
  - 远程 HTTP：**OpenAI-compatible** 端点（base URL + model name）。
  - 云端 CLI：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` 或 `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（按提供商完成登录）。
- **Agent 配置文件**：提示模板会自动安装到 `~/.burp-ai-agent/AGENTS/`；将其他 `*.md` 文件放入该目录，即可添加自定义分析/扫描行为。
- **MCP 服务器**：通过 **Settings > MCP Server** 启用，即可向任意 MCP 客户端开放 Burp 操作（53+ 个工具）。可通过编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows），将 Claude Desktop 指向该服务器。
- **隐私控制**：STRICT / BALANCED / OFF 会在将敏感请求数据发送到远程模型前进行脱敏；处理密钥时优先使用本地后端。
- **审计日志**：JSONL 日志会为每条记录计算 SHA-256 完整性哈希，以便对 AI/MCP 操作进行防篡改追踪。
- **构建/加载**：下载发布版 JAR，或使用 Java 21 构建：

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

操作注意事项：除非启用隐私模式，否则云后端可能会泄露 session cookies/PII；MCP 暴露会授予对 Burp 的远程编排能力，因此应仅允许可信代理访问，并监控经过完整性哈希处理的审计日志。



## References

- [1] [Burp MCP + Codex CLI 集成及 Caddy 握手修复](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server 严格 Origin/header 验证问题](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（工作流、启动器、提示词包）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [如何使用 Codex 进行 Bug Bounty 研究：广泛探索，严格验证](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp：为 Claude Code 和 Codex 编排 Burp Suite](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server 工具实现及参数](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF 漏洞](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets 历史记录](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - 在 Burp Repeater 中处理 WebSocket 消息](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
