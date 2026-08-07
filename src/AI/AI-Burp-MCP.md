# Burp MCP：LLM 辅助的流量审查

{{#include ../banners/hacktricks-training.md}}

## 概述

Burp 的 **MCP Server** extension 可以将拦截到的 HTTP(S) 流量暴露给支持 MCP 的 LLM 客户端，使其能够针对**真实请求/响应进行推理**，用于被动漏洞发现和报告草拟。其目标是基于证据进行审查（不进行 fuzzing 或盲目扫描），并让 Burp 作为事实来源。

## 架构

- **Burp MCP Server (BApp)** 监听 `127.0.0.1:9876`，并通过 MCP 暴露拦截到的流量。<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** 将 stdio（客户端侧）桥接到 Burp 的 MCP SSE endpoint。
- **可选的本地 reverse proxy**（Caddy）用于规范化 headers，以满足严格的 MCP handshake 检查。
- **Clients/backends**：Codex CLI（cloud）、Gemini CLI（cloud）或 Ollama（local）。

## 设置

### 1) 安装 Burp MCP Server

从 Burp BApp Store 安装 **MCP Server**，并确认其正在监听 `127.0.0.1:9876`。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) 提取 proxy JAR

在 MCP Server tab 中，点击 **Extract server proxy jar** 并保存为 `mcp-proxy.jar`。

### 3) 配置 MCP client（Codex 示例）

将 client 指向 proxy JAR 和 Burp 的 SSE endpoint：
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
然后运行 Codex 并列出 MCP tools：
```bash
codex
# inside Codex: /mcp
```
### 4) 使用 Caddy 修复严格的 Origin/请求头验证（如有需要）

如果 MCP 握手因严格的 `Origin` 检查或额外请求头而失败，请使用本地反向代理来规范化请求头（这与 Burp MCP strict validation issue 的 workaround 一致）。<sup>[[1]](#references)[[3]](#references)</sup>
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
启动 proxy 和 client：
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## 使用不同的客户端

### Codex CLI

- 按上述内容配置 `~/.codex/config.toml`。
- 运行 `codex`，然后运行 `/mcp` 以验证 Burp 工具列表。

### Gemini CLI

**burp-mcp-agents** repo 提供了启动器辅助工具：<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama（本地）

使用提供的 launcher helper 并选择一个本地模型：
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
示例本地 models 及其大致 VRAM 需求：

- `deepseek-r1:14b`（约 16GB VRAM）
- `gpt-oss:20b`（约 20GB VRAM）
- `llama3.1:70b`（48GB+ VRAM）

## 用于被动 review 的 Prompt pack

**burp-mcp-agents** repo 包含用于对 Burp traffic 进行 evidence-driven analysis 的 prompt templates：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：广泛发现 passive vulnerabilities。
- `idor_hunter.md`：IDOR/BOLA/object/tenant drift 及 auth mismatches。
- `auth_flow_mapper.md`：比较 authenticated 与 unauthenticated paths。
- `ssrf_redirect_hunter.md`：从 URL fetch params/redirect chains 中发现 SSRF/open-redirect candidates。
- `logic_flaw_hunter.md`：发现 multi-step logic flaws。
- `session_scope_hunter.md`：发现 token audience/scope misuse。
- `rate_limit_abuse_hunter.md`：发现 throttling/abuse gaps。
- `report_writer.md`：以 evidence 为重点进行 reporting。

## 可选的 attribution tagging

要在 logs 中标记 Burp/LLM traffic，可添加 header rewrite（proxy 或 Burp Match/Replace）：<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 安全注意事项

- 当流量包含敏感数据时，优先使用 **local models**。
- 对于每个发现，仅分享所需的最少证据。
- 将 Burp 作为事实来源；使用模型进行**分析和报告**，而不是扫描。

## Burp AI Agent（AI 辅助分流 + MCP 工具）

**Burp AI Agent** 是一个将 local/cloud LLMs 与被动/主动分析（62 类 vulnerability classes）结合起来的 Burp 扩展，并暴露 53+ 个 MCP 工具，使外部 MCP 客户端能够编排 Burp。<sup>[[5]](#references)</sup> 主要功能：

- **Context-menu triage**：通过 Proxy 捕获流量，打开 **Proxy > HTTP History**，右键单击一个 request → **Extensions > Burp AI Agent > Analyze this request**，即可启动一个绑定到该 request/response 的 AI chat。
- **Backends**（可按 profile 选择）：
- Local HTTP：**Ollama**、**LM Studio**。
- Remote HTTP：**OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` 或 `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（provider-specific login）。
- **Agent profiles**：prompt templates 会自动安装到 `~/.burp-ai-agent/AGENTS/`；将额外的 `*.md` 文件放入其中，即可添加自定义的分析/扫描行为。
- **MCP server**：通过 **Settings > MCP Server** 启用，可向任何 MCP 客户端暴露 Burp 操作（53+ 个工具）。可以通过编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows），将 Claude Desktop 指向该 server。
- **Privacy controls**：STRICT / BALANCED / OFF 会在将敏感 request data 发送到 remote models 前对其进行 redact；处理 secrets 时优先使用 local backends。
- **Audit logging**：JSONL logs 为每个条目生成 SHA-256 integrity hashing，从而为 AI/MCP actions 提供防篡改的 traceability。
- **Build/load**：下载 release JAR，或使用 Java 21 构建：
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
操作注意事项：除非强制启用 privacy mode，否则 cloud backends 可能会 exfiltrate session cookies/PII；MCP exposure 可远程 orchestration Burp，因此应将访问限制为 trusted agents，并监控经过 integrity-hashed 的 audit log。

## 参考资料

- [1] [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
