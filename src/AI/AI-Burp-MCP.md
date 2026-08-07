# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## 概要

Burp の **MCP Server** extension は、intercept した HTTP(S) traffic を MCP 対応の LLM clients に公開し、**実際の requests/responses を reasoning** させて、passive vulnerability discovery や report drafting を行えるようにします。目的は evidence-driven review であり、fuzzing や blind scanning は行わず、Burp を source of truth として維持します。

## Architecture

- **Burp MCP Server (BApp)** は `127.0.0.1:9876` で listen し、intercept した traffic を MCP 経由で公開します。<sup>[[1]](#references)[[2]](#references)</sup>
- **MCP proxy JAR** は stdio（client 側）を Burp の MCP SSE endpoint に bridge します。
- **Optional local reverse proxy**（Caddy）は、strict MCP handshake checks 用に headers を normalize します。
- **Clients/backends**: Codex CLI（cloud）、Gemini CLI（cloud）、または Ollama（local）。

## Setup

### 1) Install Burp MCP Server

Burp BApp Store から **MCP Server** を install し、`127.0.0.1:9876` で listen していることを verify します。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) Extract the proxy JAR

MCP Server tab で **Extract server proxy jar** を click し、`mcp-proxy.jar` として save します。

### 3) Configure an MCP client (Codex example)

client の接続先を proxy JAR と Burp の SSE endpoint に設定します。
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
次に Codex を実行し、MCP tools を一覧表示します：
```bash
codex
# inside Codex: /mcp
```
### 4) Caddyで厳密なOrigin/header検証を修正する（必要な場合）

MCP handshakeが厳密な`Origin`チェックまたは追加のheadersが原因で失敗する場合は、local reverse proxyを使用してheadersをnormalizeします（これはBurp MCPの厳密な検証問題に対する回避策と同じです）。<sup>[[1]](#references)[[3]](#references)</sup>
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
プロキシとクライアントを起動します:
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
## 異なるクライアントの使用

### Codex CLI

- 上記のとおり `~/.codex/config.toml` を設定します。
- `codex` を実行し、続いて `/mcp` を実行して Burp tools list を確認します。

### Gemini CLI

**burp-mcp-agents** repo には launcher helpers が用意されています：<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama（ローカル）

提供されている launcher helper を使用し、ローカルモデルを選択します。
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
ローカルモデルの例とおおよその VRAM 必要量：

- `deepseek-r1:14b`（約 16GB VRAM）
- `gpt-oss:20b`（約 20GB VRAM）
- `llama3.1:70b`（48GB 以上の VRAM）

## passive review 用の Prompt pack

**burp-mcp-agents** repo には、Burp traffic の evidence-driven analysis 用の prompt template が含まれています：<sup>[[4]](#references)</sup>

- `passive_hunter.md`：幅広い passive vulnerability の発見。
- `idor_hunter.md`：IDOR/BOLA/object/tenant drift と auth mismatch。
- `auth_flow_mapper.md`：authenticated path と unauthenticated path の比較。
- `ssrf_redirect_hunter.md`：URL fetch parameter や redirect chain に基づく SSRF/open-redirect candidate。
- `logic_flaw_hunter.md`：multi-step logic flaw。
- `session_scope_hunter.md`：token audience/scope の misuse。
- `rate_limit_abuse_hunter.md`：throttling/abuse の gap。
- `report_writer.md`：evidence-focused reporting。

## Optional attribution tagging

log 内の Burp/LLM traffic に tag を付けるには、header rewrite（proxy または Burp Match/Replace）を追加します：<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- トラフィックに機密データが含まれる場合は、**local models**を優先する。
- finding に必要な最小限の evidence だけを共有する。
- Burp を source of truth として維持し、model は scanning ではなく**分析とレポート作成**に使用する。

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent**は、local/cloud LLMs と passive/active analysis（62 vulnerability classes）を連携させ、外部の MCP clients が Burp をオーケストレーションできるように 53 以上の MCP tools を公開する Burp extension です。<sup>[[5]](#references)</sup> 主な特徴:

- **Context-menu triage**: Proxy でトラフィックを取得し、**Proxy > HTTP History** を開いて request を右クリック → **Extensions > Burp AI Agent > Analyze this request** を選択すると、その request/response に紐付いた AI chat が起動する。
- **Backends**（profile ごとに選択可能）:
- Local HTTP: **Ollama**、**LM Studio**。
- Remote HTTP: **OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs: **Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` または `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（provider-specific login）。
- **Agent profiles**: prompt templates は `~/.burp-ai-agent/AGENTS/` に自動インストールされる。この場所に追加の `*.md` ファイルを配置すると、custom analysis/scanning behaviors を追加できる。
- **MCP server**: **Settings > MCP Server** から有効化すると、任意の MCP client に Burp operations（53 以上の tools）を公開できる。Claude Desktop は、`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または `%APPDATA%\Claude\claude_desktop_config.json`（Windows）を編集して server を指定できる。
- **Privacy controls**: STRICT / BALANCED / OFF は、remote models に送信する前に sensitive request data を redact する。secrets を扱う場合は local backends を優先する。
- **Audit logging**: tamper-evident traceability of AI/MCP actions のため、entry ごとに SHA-256 integrity hashing を含む JSONL logs。
- **Build/load**: release JAR を download するか、Java 21 で build する:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
運用上の注意: privacy mode が強制されていない場合、cloud backends が session cookies/PII を exfiltrate する可能性があります。MCP exposure により Burp の remote orchestration が可能になるため、アクセスを trusted agents に制限し、integrity-hashed audit log を監視してください。

## 参考文献

- [1] [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)

{{#include ../banners/hacktricks-training.md}}
