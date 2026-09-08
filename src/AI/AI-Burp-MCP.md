# Burp MCP：LLM 辅助流量审查

{{#include ../banners/hacktricks-training.md}}

## 概述

Burp 的 **MCP Server** extension 可以将拦截到的 HTTP(S) 流量暴露给支持 MCP 的 LLM clients，使其能够针对**真实请求/响应**进行推理，以发现漏洞并起草报告。让 Burp 作为事实来源：使用被动分析或有意进行的单变量重放，而不是盲目扫描。<sup>[[8]](#references)</sup>

## 架构

- **Burp MCP Server (BApp)** 默认监听 `127.0.0.1:9876`，并通过 MCP 暴露拦截到的流量。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** 将 stdio（客户端侧）桥接到 Burp 的 MCP SSE endpoint。
- **可选的本地 reverse proxy**（Caddy）可为严格的 MCP handshake 检查规范化 headers。
- **Clients/backends**：Codex CLI（cloud）、Gemini CLI（cloud）或 Ollama（local）。

## 设置

### 1) 安装 Burp MCP Server

从 Burp BApp Store 安装 **MCP Server**，并确认其正在监听 `127.0.0.1:9876`。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) 提取 proxy JAR

在 MCP Server tab 中，点击 **Extract server proxy jar** 并保存 `mcp-proxy-all.jar`。<sup>[[7]](#references)</sup>

### 3) 配置 MCP client（Codex 示例）

将 client 指向 proxy JAR 和 Burp 的 direct SSE endpoint。打包的 proxy 是一个 stdio-to-SSE bridge；它不会替代 Burp listener。<sup>[[7]](#references)</sup>
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
### 4) 使用 Caddy 修复严格的 Origin/header 验证（如有需要）

如果 MCP handshake 因严格的 `Origin` 检查或额外的 headers 而失败，请使用本地 reverse proxy 规范化 headers（这与 Burp MCP strict validation issue 的 workaround 一致）。<sup>[[1]](#references)[[3]](#references)</sup>
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
启动 proxy 和客户端，并仅在使用此 Caddy listener 时，将配置的 `--sse-url` 更改为 `http://127.0.0.1:19876`：<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) 将浏览器状态与 proxy evidence 配对 (Playwright MCP)

注册 Playwright MCP，使其浏览器使用 Burp 的 proxy。这样，agent 就能将渲染后的 DOM/accessibility 状态与生成该状态的精确 HTTP history 关联起来。<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
调整 listener address，重启 Codex，并使用 `/mcp` 验证两个集成。该示例会禁用浏览器证书错误，因此通过 Burp 本地生成的证书进行 HTTPS interception 时不会被阻止。<sup>[[6]](#references)[[8]](#references)</sup>

## 使用不同客户端

### Codex CLI

- 按上述内容配置 `~/.codex/config.toml`。
- 运行 `codex`，然后使用 `/mcp` 验证 Burp tools 列表。

### Gemini CLI

**burp-mcp-agents** repo 提供了启动辅助工具：<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

使用提供的 launcher helper 并选择一个本地 model：
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
示例 local models 及大致的 VRAM 需求：

- `deepseek-r1:14b`（约 16GB VRAM）
- `gpt-oss:20b`（约 20GB VRAM）
- `llama3.1:70b`（48GB+ VRAM）

## 基于证据的 replay 与验证

不要让 agent 将看似合理的解释或中间响应视为证据。使用 Burp requests/responses 以及独立观察到的浏览器状态，让每项测试都可以被证伪。<sup>[[8]](#references)</sup>

1. 保存一组 baseline request/response，并确定由攻击者控制的确切组件。
2. 进行 authorization 对比时，在修改 identifiers、cookies 或 tokens 之前，分别在两个账号下独立捕获相同的 workflow。
3. 在 replay 某项 mutation 之前，记录 hypothesis、证据位置、预期 signal，以及能够证伪该 hypothesis 的结果。
4. 一次只修改一个组件，保留生成的 pair，并将直接观察结果与 inference 分开标记。
5. 将每个候选项标记为 `open`、`blocked`、`rejected` 或 `confirmed`；只有当新证据改变了其 mechanism 或 prerequisite 时，才重新检查该候选项。
6. 确认 attacker control、reachability、repeatability、constraint bypass、impact 以及最终的 application state。如果所声称的 state change 是下游行为，那么 redirect 或成功的 tool call 都不能作为证据。

将 exploitation 细节保留在相关的 technique 页面中。例如，browser-message 候选项应归入 [PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)，而 token key-selection 行为应归入 [JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)。<sup>[[8]](#references)</sup>

简洁的 hypothesis record 可以避免并行 agent 重复探索同一条看似有吸引力的分支：<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## 用于被动审查的 Prompt pack

**burp-mcp-agents** repo 包含用于对 Burp 流量进行 evidence-driven analysis 的 prompt templates：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：广泛发现被动 vulnerability。
- `idor_hunter.md`：IDOR/BOLA/object/tenant drift 和 auth mismatches。
- `auth_flow_mapper.md`：比较 authenticated 与 unauthenticated paths。
- `ssrf_redirect_hunter.md`：从 URL fetch params/redirect chains 中发现 SSRF/open-redirect candidates。
- `logic_flaw_hunter.md`：multi-step logic flaws。
- `session_scope_hunter.md`：token audience/scope misuse。
- `rate_limit_abuse_hunter.md`：throttling/abuse gaps。
- `report_writer.md`：以 evidence 为重点的 reporting。

## Optional attribution tagging

要在 logs 中标记 Burp/LLM 流量，可添加 header rewrite（proxy 或 Burp Match/Replace）：<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 安全注意事项

- 当流量包含敏感数据时，优先使用 **local models**。
- 对于某个 finding，仅分享所需的最少证据。
- 将 Burp 作为事实来源；使用模型进行 **analysis and reporting**，而非 scanning。

## Burp AI Agent（AI-assisted triage + MCP tools）

**Burp AI Agent** 是一个 Burp extension，将 local/cloud LLMs 与被动/主动分析（62 类漏洞）结合，并暴露 53+ 个 MCP tools，使外部 MCP clients 能够编排 Burp。<sup>[[5]](#references)</sup> 主要功能：

- **Context-menu triage**：通过 Proxy 捕获流量，打开 **Proxy > HTTP History**，右键单击请求 → **Extensions > Burp AI Agent > Analyze this request**，启动绑定到该请求/响应的 AI chat。
- **Backends**（可按 profile 选择）：
- Local HTTP：**Ollama**、**LM Studio**。
- Remote HTTP：**OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` 或 `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（provider-specific login）。
- **Agent profiles**：prompt templates 会自动安装到 `~/.burp-ai-agent/AGENTS/`；将额外的 `*.md` 文件放入其中，即可添加自定义的 analysis/scanning behaviors。
- **MCP server**：通过 **Settings > MCP Server** 启用，将 Burp operations 暴露给任意 MCP client（53+ tools）。可以通过编辑 `~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）或 `%APPDATA%\Claude\claude_desktop_config.json`（Windows），让 Claude Desktop 指向该 server。
- **Privacy controls**：STRICT / BALANCED / OFF 会在将敏感请求数据发送到 remote models 前进行 redact；处理 secrets 时优先使用 local backends。
- **Audit logging**：JSONL logs 为每个条目生成 SHA-256 integrity hashing，提供 AI/MCP actions 的防篡改可追溯性。
- **Build/load**：下载 release JAR，或使用 Java 21 构建：
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
操作注意事项：除非强制启用 privacy mode，否则 cloud backends 可能会窃取 session cookies/PII；MCP exposure 允许远程编排 Burp，因此应将访问权限限制为受信任的 agents，并监控经过完整性哈希处理的 audit log。

## References

- [1] [Burp MCP + Codex CLI 集成与 Caddy handshake 修复](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server 严格 Origin/header 验证问题](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（workflows、launchers、prompt pack）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [如何使用 Codex 进行 Bug Bounty 研究：广泛探索，严格验证](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
