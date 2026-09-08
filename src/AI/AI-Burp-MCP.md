# Burp MCP: LLMによるtraffic review

{{#include ../banners/hacktricks-training.md}}

## 概要

Burpの**MCP Server** extensionは、interceptしたHTTP(S) trafficをMCP対応LLM clientに公開し、脆弱性の発見やレポートの草稿作成のために、**実際のrequest/responseを分析**できるようにします。Burpをsource of truthとして維持し、blind scanningではなく、passive analysisまたは1つの変数だけを意図的に変更したreplayを使用してください。<sup>[[8]](#references)</sup>

## アーキテクチャ

- **Burp MCP Server (BApp)**はデフォルトで`127.0.0.1:9876`をlistenし、interceptしたtrafficをMCP経由で公開します。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**は、stdio（client側）をBurpのMCP SSE endpointにbridgeします。
- **Optional local reverse proxy**（Caddy）は、strict MCP handshake checks向けにheaderを正規化します。
- **Clients/backends**: Codex CLI（cloud）、Gemini CLI（cloud）、またはOllama（local）。

## セットアップ

### 1) Burp MCP Serverをインストールする

Burp BApp Storeから**MCP Server**をインストールし、`127.0.0.1:9876`でlistenしていることを確認します。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JARをextractする

MCP Server tabで**Extract server proxy jar**をクリックし、`mcp-proxy-all.jar`を保存します。<sup>[[7]](#references)</sup>

### 3) MCP clientを設定する（Codexの例）

clientがproxy JARとBurpのdirect SSE endpointを参照するように設定します。パッケージ化されたproxyはstdio-to-SSE bridgeであり、Burp listenerの代わりにはなりません。<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
同等の Codex command は次のとおりです:<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
次に Codex を実行し、MCP tools を一覧表示します:
```bash
codex
# inside Codex: /mcp
```
### 4) CaddyでstrictなOrigin/header validationを修正する（必要な場合）

strictな`Origin` checksまたは追加のheadersが原因でMCP handshakeに失敗する場合は、local reverse proxyを使用してheadersをnormalizeします（これはBurp MCPのstrict validation issueに対するworkaroundと同じです）。<sup>[[1]](#references)[[3]](#references)</sup>
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
proxy と client を起動し、この Caddy listener の使用中に限り、設定された `--sse-url` を `http://127.0.0.1:19876` に変更します:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) ブラウザの状態をプロキシの証拠とペアリングする（Playwright MCP）

Playwright MCP を登録し、そのブラウザが Burp の proxy を使用するように設定します。これにより、エージェントはレンダリングされた DOM/accessibility state と、それを生成した正確な HTTP history を関連付けられます。<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
リスナーのアドレスを適応し、Codex を再起動して、`/mcp` を使用して両方の integration を確認します。この例では browser certificate errors を無効にしているため、Burp がローカルで生成した証明書によって HTTPS interception がブロックされません。<sup>[[6]](#references)[[8]](#references)</sup>

## 異なる clients の使用

### Codex CLI

- 上記のように `~/.codex/config.toml` を設定します。
- `codex` を実行し、続いて `/mcp` を実行して Burp tools の一覧を確認します。

### Gemini CLI

**burp-mcp-agents** repo には launcher helpers が用意されています。<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

提供された launcher helper を使用し、local model を選択します:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
ローカルモデルの例とおおよそのVRAM要件：

- `deepseek-r1:14b`（約16GB VRAM）
- `gpt-oss:20b`（約20GB VRAM）
- `llama3.1:70b`（48GB以上のVRAM）

## Evidence-driven replay and validation

agentに、もっともらしい説明や中間レスポンスを証拠として扱わせないでください。すべてのtestを反証可能にするため、Burpのrequests/responsesと、独立して観測したbrowser stateを使用します。<sup>[[8]](#references)</sup>

1. baselineのrequest/responseペアを保存し、attacker-controlledなcomponentを正確に特定します。
2. authorizationの比較では、identifier、cookie、tokenを変更する前に、両方のaccountで同じworkflowを独立してcaptureします。
3. mutationをreplayする前に、hypothesis、evidenceの場所、expected signal、およびそれを反証するresultを記録します。
4. 一度に1つのcomponentだけをmutationし、生成されたペアを保持し、直接観測した内容とinferenceを分けて記録します。
5. 各candidateを`open`、`blocked`、`rejected`、`confirmed`として追跡し、mechanismまたはprerequisiteを変える新しいevidenceが得られた場合のみ再検討します。
6. attacker control、reachability、repeatability、constraint bypass、impact、および最終的なapplication stateを確認します。主張されたstate changeがdownstreamで発生する場合、redirectやtool callの成功だけでは証拠になりません。

exploitationの詳細は、関連するtechnique pageに記載してください。たとえば、browser-messageのcandidateは[PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)に、token key-selectionの挙動は[JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)に記載します。<sup>[[8]](#references)</sup>

簡潔なhypothesis recordにより、parallel agentが同じ魅力的なbranchを繰り返すことを防げます。<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## passive review 用 Prompt pack

**burp-mcp-agents** repo には、Burp トラフィックの evidence-driven analysis 用 Prompt template が含まれています:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: passive な vulnerability の幅広い surfacing。
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift と auth mismatch。
- `auth_flow_mapper.md`: authenticated path と unauthenticated path の比較。
- `ssrf_redirect_hunter.md`: URL fetch param/redirect chain からの SSRF/open-redirect 候補。
- `logic_flaw_hunter.md`: multi-step logic flaw。
- `session_scope_hunter.md`: token audience/scope の misuse。
- `rate_limit_abuse_hunter.md`: throttling/abuse gap。
- `report_writer.md`: evidence-focused reporting。

## Optional attribution tagging

ログ内の Burp/LLM トラフィックに tag を付けるには、header rewrite（proxy または Burp Match/Replace）を追加します:<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- トラフィックに機密データが含まれる場合は、**local models**を優先してください。
- finding に必要な最小限の evidence のみを共有してください。
- Burp を source of truth として維持し、model は scanning ではなく **analysis and reporting** に使用してください。

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** は、local/cloud LLMs と passive/active analysis（62 vulnerability classes）を連携させ、外部 MCP clients が Burp をオーケストレーションできるように 53+ MCP tools を公開する Burp extension です。<sup>[[5]](#references)</sup> 主な機能:

- **Context-menu triage**: Proxy 経由で traffic を取得し、**Proxy > HTTP History** を開いて request を右クリック → **Extensions > Burp AI Agent > Analyze this request** を選択すると、その request/response に紐付いた AI chat が起動します。
- **Backends**（profile ごとに選択可能）:
- Local HTTP: **Ollama**、**LM Studio**。
- Remote HTTP: **OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs: **Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` または `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（provider-specific login）。
- **Agent profiles**: prompt templates は `~/.burp-ai-agent/AGENTS/` に自動インストールされます。そこに追加の `*.md` files を配置すると、custom analysis/scanning behaviors を追加できます。
- **MCP server**: **Settings > MCP Server** から有効にすると、任意の MCP client に Burp operations（53+ tools）を公開できます。Claude Desktop から server を参照するには、`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または `%APPDATA%\Claude\claude_desktop_config.json`（Windows）を編集します。
- **Privacy controls**: STRICT / BALANCED / OFF は、remote models に送信する前に sensitive request data を redact します。secrets を扱う場合は local backends を優先してください。
- **Audit logging**: JSONL logs には、AI/MCP actions の tamper-evident traceability のため、entry ごとの SHA-256 integrity hashing が含まれます。
- **Build/load**: release JAR を download するか、Java 21 で build します:
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
Operational cautions: cloud backends may exfiltrate session cookies/PII unless privacy mode is enforced; MCP exposure grants remote orchestration of Burp so restrict access to trusted agents and monitor the integrity-hashed audit log.

## References

- [1] [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [How to use Codex for Bug Bounty research: explore broadly, validate rigorously](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
{{#include ../banners/hacktricks-training.md}}
