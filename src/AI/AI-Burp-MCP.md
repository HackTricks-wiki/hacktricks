# Burp MCP：LLM 辅助流量审查

{{#include ../banners/hacktricks-training.md}}

## 概述

Burp 的 **MCP Server** 扩展可以将拦截的 HTTP(S) 流量提供给支持 MCP 的 LLM 客户端，让它们能够**基于真实请求/响应进行推理**，以发现漏洞并起草报告。应以 Burp 为事实来源：使用被动分析，或有意进行单变量重放，而不是盲目扫描。<sup>[[8]](#references)</sup>

## 架构

- **Burp MCP Server (BApp)** 默认监听 `127.0.0.1:9876`，并通过 MCP 提供拦截的流量。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** 在 stdio（客户端）与 Burp 的 MCP SSE endpoint 之间充当桥接。
- **可选的本地反向代理**（Caddy）可为严格的 MCP 握手检查规范化 headers。
- **客户端/后端**：Codex CLI（云端）、Gemini CLI（云端）或 Ollama（本地）。

## 设置

### 1) 安装 Burp MCP Server

从 Burp BApp Store 安装 **MCP Server**，并确认它正在监听 `127.0.0.1:9876`。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) 提取 proxy JAR

在 MCP Server 选项卡中，点击 **Extract server proxy jar** 并保存 `mcp-proxy-all.jar`。<sup>[[7]](#references)</sup>

### 3) 配置 MCP 客户端（以 Codex 为例）

将客户端指向 proxy JAR 和 Burp 的直接 SSE endpoint。打包的 proxy 是一个 stdio-to-SSE 桥接程序；它不会取代 Burp listener。<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

对应的 Codex 命令是：<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

然后运行 Codex 并列出 MCP 工具：

```bash
codex
# inside Codex: /mcp
```

### 4) 使用 Caddy 修复严格的 Origin/标头验证（如有需要）

如果 MCP 握手因严格的 `Origin` 检查或额外标头而失败，请使用本地反向代理规范化标头（这与 Burp MCP 严格验证问题的变通方法一致）。<sup>[[1]](#references)[[3]](#references)</sup>

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

### 5) 将浏览器状态与代理证据配对（Playwright MCP）

配置 Playwright MCP，使其浏览器使用 Burp 的代理。这样，代理就能将渲染后的 DOM/无障碍状态与生成这些状态的确切 HTTP 历史记录关联起来。<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

调整监听器地址，重启 Codex，并使用 `/mcp` 验证两个集成。示例禁用了浏览器证书错误，以避免 Burp 本地生成的证书阻止 HTTPS 拦截。<sup>[[6]](#references)[[8]](#references)</sup>

## 支持代理的浏览器自动化（OpenBurp）

Burp MCP 连接和被拦截的浏览器流量是独立的数据流。MCP 服务在 `127.0.0.1:9876` 上提供 Burp 工具，而专用 Chromium 实例则通过 Burp 在 `127.0.0.1:8080` 上的代理发送 HTTP(S) 流量。因此，MCP 工具直接生成的请求可能不会出现在 **Proxy > HTTP history** 中；如果需要观察、编辑请求/响应或将其保留为证据，请使用经过代理的浏览器。<sup>[[2]](#references)[[9]](#references)</sup>

支持 SSE 的客户端可以直接注册 Burp。仅支持 stdio 的客户端则可以启动 PortSwigger 的代理 JAR。两种情况下，都要注册第二个浏览器控制 MCP，并将其指向 Burp 内置的 Chromium（`BURP_CHROMIUM` 是本地可执行文件路径）：<sup>[[9]](#references)</sup>

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

TLS-bypass 标志允许使用拦截代理生成的证书，而 `--isolated` 可防止评估复用操作者的常规浏览器配置文件。隔离能保护配置文件状态，但**不是安全沙箱**：控制器仍可访问在该测试浏览器中打开的已认证会话，Burp MCP 也可能暴露敏感请求、响应和配置。<sup>[[9]](#references)</sup>

在排查客户端桥接问题之前，请单独测试 SSE 监听器：<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

正常工作的 listener 会返回 `Content-Type: text/event-stream`。收到 headers 后发生 timeout 是预期行为，因为 SSE stream 会保持打开状态以接收后续 events。如果 client 仍然失败，请确认 extension 配置的 route：PortSwigger 指出，endpoint 可能是根路径或 `/sse`，具体取决于 client 和 extension 配置。<sup>[[9]](#references)[[7]](#references)</sup>

## 使用不同的 clients

### Codex CLI

- 按上述说明配置 `~/.codex/config.toml`。
- 运行 `codex`，然后运行 `/mcp` 以确认 Burp tools 列表。

### Gemini CLI

**burp-mcp-agents** repo 提供 launcher helpers：<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama（本地）

使用提供的启动器辅助工具并选择一个本地模型：

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

本地模型示例及大致 VRAM 需求：

- `deepseek-r1:14b`（约 16GB VRAM）
- `gpt-oss:20b`（约 20GB VRAM）
- `llama3.1:70b`（48GB+ VRAM）

## 基于证据的重放与验证

不要让 agent 把看似合理的解释或中间响应当作证据。使用 Burp 请求/响应和独立观察到的浏览器状态，让每项测试都可证伪。<sup>[[8]](#references)</sup>

1. 保存一组基线请求/响应，并确定由攻击者控制的确切组件。
2. 对比授权情况时，在修改标识符、cookie 或 token 之前，分别使用两个账户独立捕获相同工作流。
3. 重放修改前，记录假设、证据位置、预期信号，以及哪些结果会推翻该假设。
4. 每次只修改一个组件，保存修改后的请求/响应对，并将直接观察与推断分开标注。
5. 将每个候选项标记为 `open`、`blocked`、`rejected` 或 `confirmed`；只有新证据改变了机制或前置条件时才重新检查。
6. 确认攻击者控制能力、可达性、可重复性、约束绕过、影响和最终应用状态。如果所声称的状态变更发生在后续环节，那么重定向或工具调用成功并不能作为证据。

将利用细节放在相关技术页面中。例如，浏览器消息候选项应放在 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md) 中，而 token 密钥选择行为应放在 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md) 中。<sup>[[8]](#references)</sup>

简洁的假设记录能避免并行 agent 重复探索同一条看似诱人的路径：<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## 使用 Burp MCP 进行定向带外验证

Burp Suite Professional 通过官方 MCP 扩展提供 `generate_collaborator_payload` 和 `get_collaborator_interactions`。将它们与 `get_proxy_http_history_regex` 以及一次 `send_http1_request` 重放结合使用，即可测试疑似服务器端 URL 获取行为，而无需扫描整个目标。Burp 可能需要分别批准读取历史记录和发送请求。<sup>[[2]](#references)[[10]](#references)</sup>

1. 筛选历史记录，找到包含 URL 的候选请求，例如包含 `url=`、`webhook` 或 `callback` 的请求。保存原始请求和响应。历史记录工具接受 `regex`、`count` 和 `offset` 参数；请分页查询，而不要要求模型检查所有条目。<sup>[[10]](#references)</sup>
2. 生成一个新的 Collaborator payload，并保留其返回的 **payload ID**。将捕获的请求重放到同一主机和端口，只将候选 URL 改为该 payload 域名下的 HTTPS URL。对于 `send_http1_request`，将完整的 HTTP/1.1 请求作为 `content` 传入，并提供 `targetHostname`、`targetPort` 和 `usesHttps`；目标字段标识的是**应用程序**，而不是 Collaborator 主机。<sup>[[10]](#references)</sup>
3. 使用该 payload ID 轮询 `get_collaborator_interactions`，并将交互时间与重放时间进行关联。HTTP 交互说明发生了获取行为；只有 DNS 则仅表明完成了解析，并不代表已完成 HTTP 请求。检查交互来源和请求头，区分服务器端出站请求与浏览器端加载，然后使用新的 payload 重复测试，以排除无关流量。<sup>[[10]](#references)[[11]](#references)</sup>

MCP 请求工具会直接返回响应，不一定会将其写入 **Proxy > HTTP history**。请保留其请求/响应结果，或使用经代理的浏览器或 Repeater 生成可在历史记录中查看的凭据。有关 SSRF payload 的选择和后续测试，请参阅 [SSRF 章节](../pentesting-web/ssrf-server-side-request-forgery/)，不要将带外 callback 视为内部网络受到影响的证明。有关测试 MCP server 本身，请参阅 [MCP server 测试](AI-MCP-Servers.md#remote-mcp-server-testing-workflow)。<sup>[[7]](#references)[[11]](#references)</sup>

## 被动审查提示词包

**burp-mcp-agents** repo 包含用于基于证据分析 Burp 流量的提示词模板：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：广泛发现被动漏洞。
- `idor_hunter.md`：检查 IDOR/BOLA/对象/租户偏差以及认证不匹配。
- `auth_flow_mapper.md`：比较已认证与未认证的路径。
- `ssrf_redirect_hunter.md`：从 URL 获取参数/重定向链中发现 SSRF/open-redirect 候选项。
- `logic_flaw_hunter.md`：发现多步骤逻辑漏洞。
- `session_scope_hunter.md`：检查 token 的受众/作用域滥用。
- `rate_limit_abuse_hunter.md`：发现限流/滥用防护缺口。
- `report_writer.md`：撰写侧重证据的报告。

## 可选的流量归因标记

要在日志中标记 Burp/LLM 流量，请添加请求头重写规则（proxy 或 Burp Match/Replace）：<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## 安全注意事项

- 当流量包含敏感数据时，优先使用**本地模型**。
- 仅分享发现所需的最少证据。
- 以 Burp 为准；使用模型进行**分析和报告**，而非扫描。

## Burp AI Agent（AI 辅助分诊 + MCP 工具）

**Burp AI Agent** 是一款 Burp 扩展，可将本地/云端 LLM 与被动/主动分析（62 类漏洞）结合，并提供 53+ 个 MCP 工具，让外部 MCP 客户端能够编排 Burp。<sup>[[5]](#references)</sup> 主要功能：

- **上下文菜单分诊**：通过 Proxy 捕获流量，打开 **Proxy > HTTP History**，右键单击请求 → **Extensions > Burp AI Agent > Analyze this request**，即可启动绑定到该请求/响应的 AI 聊天。
- **后端**（可按配置档案选择）：
  - 本地 HTTP：**Ollama**、**LM Studio**。
  - 远程 HTTP：**OpenAI-compatible** 端点（基础 URL + 模型名称）。
  - 云端 CLI：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` 或 `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（特定于提供商的登录方式）。
- **Agent 配置档案**：提示词模板会自动安装到 `~/.burp-ai-agent/AGENTS/`；将额外的 `*.md` 文件放入该目录，即可添加自定义分析/扫描行为。
- **MCP server**：通过 **Settings > MCP Server** 启用，即可向任意 MCP 客户端开放 Burp 操作（53+ 个工具）。编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows），即可将 Claude Desktop 指向该 server。
- **隐私控制**：STRICT / BALANCED / OFF 会在将敏感请求数据发送到远程模型之前对其进行脱敏；处理机密信息时优先使用本地后端。
- **审计日志**：JSONL 日志包含每条记录的 SHA-256 完整性哈希，可对 AI/MCP 操作进行防篡改追踪。
- **构建/加载**：下载 release JAR，或使用 Java 21 构建：

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

操作注意事项：除非启用隐私模式，否则云端后端可能会外传 session cookies/PII；暴露 MCP 会授予远程编排 Burp 的能力，因此应限制访问权限，仅允许受信任的 agents 访问，并监控经过完整性哈希处理的审计日志。



## References

- [1] [Burp MCP + Codex CLI 集成及 Caddy 握手修复](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server 的严格 Origin/header 验证问题](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（工作流、启动器、prompt 包）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [如何使用 Codex 进行 Bug Bounty 研究：广泛探索，严格验证](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp：为 Claude Code 和 Codex 编排 Burp Suite](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server 工具实现与参数](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF 漏洞](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
