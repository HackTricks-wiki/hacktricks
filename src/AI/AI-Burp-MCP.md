# Burp MCP：LLM-assisted 流量审查

{{#include ../banners/hacktricks-training.md}}

## 概述

Burp 的 **MCP Server** extension 可以将拦截的 HTTP(S) 流量暴露给支持 MCP 的 LLM clients，使其能够针对**真实请求/响应进行推理**，用于漏洞发现和报告草拟。将 Burp 作为事实来源：使用被动分析或有意进行的单变量重放，而不是盲目扫描。<sup>[[8]](#references)</sup>

## 架构

- **Burp MCP Server (BApp)** 默认监听 `127.0.0.1:9876`，并通过 MCP 暴露拦截的流量。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** 将 stdio（client side）桥接到 Burp 的 MCP SSE endpoint。
- **可选的本地 reverse proxy**（Caddy）可为严格的 MCP handshake checks 规范化 headers。
- **Clients/backends**：Codex CLI（cloud）、Gemini CLI（cloud）或 Ollama（local）。

## 设置

### 1) 安装 Burp MCP Server

从 Burp BApp Store 安装 **MCP Server**，并确认其正在 `127.0.0.1:9876` 上监听。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) 提取 proxy JAR

在 MCP Server tab 中，点击 **Extract server proxy jar**，并保存 `mcp-proxy-all.jar`。<sup>[[7]](#references)</sup>

### 3) 配置 MCP client（Codex 示例）

将 client 指向 proxy JAR 和 Burp 的 direct SSE endpoint。打包的 proxy 是一个 stdio-to-SSE bridge；它不会取代 Burp listener。<sup>[[7]](#references)</sup>
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
### 4) 使用 Caddy 修复严格的 Origin/header validation（如需要）

如果 MCP handshake 因严格的 `Origin` 检查或额外 headers 而失败，请使用本地 reverse proxy 来规范化 headers（这与 Burp MCP strict validation issue 的 workaround 一致）。<sup>[[1]](#references)[[3]](#references)</sup>
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
启动 proxy 和 client，并且仅在使用此 Caddy listener 时，将配置的 `--sse-url` 更改为 `http://127.0.0.1:19876`：<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) 将浏览器状态与 proxy 证据配对（Playwright MCP）

配置 Playwright MCP，使其浏览器使用 Burp 的 proxy。这样，agent 就能将渲染后的 DOM/accessibility 状态与生成该状态的确切 HTTP history 关联起来。<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
调整 listener 地址，重启 Codex，并使用 `/mcp` 验证两个 integrations。该示例禁用了浏览器证书错误，因此 HTTPS interception 不会被 Burp 本地生成的证书阻止。<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP connection 与 intercepted browser path 是两条独立的数据流。MCP service 在 `127.0.0.1:9876` 暴露 Burp tools，而专用 Chromium instance 则通过 `127.0.0.1:8080` 上的 Burp proxy 发送其 HTTP(S) traffic。因此，直接由 MCP tool 生成的 requests 可能不会出现在 **Proxy > HTTP history** 中；当 request/response 必须可观察、可编辑或作为 evidence 保留时，请使用 proxied browser。<sup>[[2]](#references)[[9]](#references)</sup>

支持 SSE 的 client 可以直接注册 Burp。仅支持 stdio 的 client 则可以启动 PortSwigger 的 proxy JAR。无论采用哪种方式，都要再注册一个 browser-control MCP，并将其指向 Burp 内置的 Chromium（`BURP_CHROMIUM` 是本地 executable path）：<sup>[[9]](#references)</sup>
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
TLS-bypass flag 会接受由 interception proxy 生成的证书，而 `--isolated` 可防止 assessment 复用 operator 的常规 browser profile。Isolation 可保护 profile state，但**不是 security sandbox**：controller 仍可访问在该 test browser 中打开的 authenticated sessions，并且 Burp MCP 可能暴露敏感的 requests、responses 和 configuration。<sup>[[9]](#references)</sup>

在调试 client bridge 之前，先独立测试 SSE listener：<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
正常的 listener 会返回 `Content-Type: text/event-stream`。在 headers 之后发生 timeout 是预期行为，因为 SSE stream 会保持打开状态以接收未来的 events。如果 client 仍然失败，请确认 extension 配置的 route：PortSwigger 指出，根据 client 和 extension configuration，endpoint 可能是 root path 或 `/sse`。<sup>[[9]](#references)[[7]](#references)</sup>

## Using different clients

### Codex CLI

- 按上述内容配置 `~/.codex/config.toml`。
- 运行 `codex`，然后运行 `/mcp` 以验证 Burp tools 列表。

### Gemini CLI

**burp-mcp-agents** repo 提供了 launcher helpers：<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama（本地）

使用提供的 launcher helper 并选择一个本地 model：
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
本地模型示例及大致 VRAM 需求：

- `deepseek-r1:14b`（约 16GB VRAM）
- `gpt-oss:20b`（约 20GB VRAM）
- `llama3.1:70b`（48GB+ VRAM）

## 基于证据的重放与验证

不要让 agent 将合理的解释或中间响应视为证据。使用 Burp 请求/响应，以及独立观察到的浏览器状态，使每项测试都可证伪。<sup>[[8]](#references)</sup>

1. 保存一组基线请求/响应，并确定确切的攻击者控制组件。
2. 对于授权比较，在修改标识符、cookies 或 tokens 之前，分别在两个账户下独立捕获相同的工作流。
3. 在重放修改之前，记录假设、证据位置、预期信号，以及能够证伪该假设的结果。
4. 一次只修改一个组件，保留生成的请求/响应对，并将直接观察结果与推断分别标记。
5. 将每个候选项跟踪为 `open`、`blocked`、`rejected` 或 `confirmed`；仅当新证据改变了机制或前置条件时才重新检查。
6. 确认攻击者控制权、可达性、可重复性、约束绕过、影响及最终应用状态。如果所声称的状态变化发生在下游，那么重定向或成功的 tool call 并不能作为证据。

将 exploitation 细节保留在相关 technique 页面中。例如，浏览器消息候选项应归入 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)，而 token key-selection 行为应归入 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)。<sup>[[8]](#references)</sup>

简洁的假设记录可以避免并行 agent 重复探索同一条看似有吸引力的路径：<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## 被动审查的 Prompt 包

**burp-mcp-agents** repo 包含用于对 Burp 流量进行基于证据分析的 prompt 模板：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：广泛发现被动漏洞。
- `idor_hunter.md`：IDOR/BOLA、对象/tenant 漂移和 auth 不匹配。
- `auth_flow_mapper.md`：比较 authenticated 与 unauthenticated 路径。
- `ssrf_redirect_hunter.md`：从 URL fetch 参数/redirect chains 中发现 SSRF/open-redirect 候选项。
- `logic_flaw_hunter.md`：发现多步骤逻辑缺陷。
- `session_scope_hunter.md`：发现 token audience/scope 误用。
- `rate_limit_abuse_hunter.md`：发现 throttling/abuse 缺口。
- `report_writer.md`：编写以证据为重点的报告。

## 可选的 attribution tagging

要在日志中标记 Burp/LLM 流量，请添加 header rewrite（proxy 或 Burp Match/Replace）：<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 安全注意事项

- 当流量包含敏感数据时，优先使用 **local models**。
- 仅分享 finding 所需的最少证据。
- 让 Burp 作为事实来源；使用模型进行**分析和报告**，而不是扫描。

## Burp AI Agent（AI 辅助分流 + MCP tools）

**Burp AI Agent** 是一个 Burp extension，将 local/cloud LLMs 与被动/主动分析（62 个漏洞类别）结合起来，并暴露 53+ 个 MCP tools，使外部 MCP clients 能够编排 Burp。<sup>[[5]](#references)</sup> 主要功能：

- **Context-menu triage**：通过 Proxy 捕获流量，打开 **Proxy > HTTP History**，右键单击请求 → **Extensions > Burp AI Agent > Analyze this request**，启动一个绑定到该请求/响应的 AI chat。
- **Backends**（可按 profile 选择）：
- Local HTTP：**Ollama**、**LM Studio**。
- Remote HTTP：**OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` 或 `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（特定于 provider 的 login）。
- **Agent profiles**：prompt templates 会自动安装到 `~/.burp-ai-agent/AGENTS/`；将额外的 `*.md` 文件放入其中，即可添加自定义的分析/扫描行为。
- **MCP server**：通过 **Settings > MCP Server** 启用，将 Burp operations 暴露给任何 MCP client（53+ 个 tools）。可以通过编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows），让 Claude Desktop 连接到该 server。
- **Privacy controls**：STRICT / BALANCED / OFF 会在将敏感请求数据发送到 remote models 前对其进行 redact；处理 secrets 时优先使用 local backends。
- **Audit logging**：JSONL logs 会为每条记录使用 SHA-256 integrity hashing，以提供 AI/MCP actions 的防篡改可追溯性。
- **Build/load**：下载 release JAR，或使用 Java 21 构建：
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
操作注意事项：除非强制启用 privacy mode，否则 cloud backends 可能会窃取 session cookies/PII；MCP exposure 可远程编排 Burp，因此应将访问限制为受信任的 agents，并监控经过 integrity-hashed 的 audit log。

## References

- [1] [Burp MCP + Codex CLI 集成与 Caddy 握手修复](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server 严格 Origin/header 验证问题](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（workflows、launchers、prompt pack）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [如何使用 Codex 进行 Bug Bounty 研究：广泛探索，严格验证](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp：面向 Claude Code 和 Codex 的 Burp Suite 编排](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
