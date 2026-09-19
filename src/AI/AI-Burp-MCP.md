# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## 概要

Burp の **MCP Server** extension は、intercept した HTTP(S) traffic を MCP 対応の LLM client に公開し、**実際の request/response を基に推論**して vulnerability discovery や report drafting を行えるようにします。Burp を信頼できる情報源として維持し、blind scanning ではなく、passive analysis または意図的に変数を1つだけ変更した replay を使用してください。<sup>[[8]](#references)</sup>

## アーキテクチャ

- **Burp MCP Server (BApp)** はデフォルトで `127.0.0.1:9876` を listen し、intercept した traffic を MCP 経由で公開します。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** は stdio（client 側）を Burp の MCP SSE endpoint に bridge します。
- **Optional local reverse proxy**（Caddy）は、厳格な MCP handshake check に対応するため header を正規化します。
- **Clients/backends**: Codex CLI（cloud）、Gemini CLI（cloud）、または Ollama（local）。

## セットアップ

### 1) Burp MCP Server をインストールする

Burp BApp Store から **MCP Server** をインストールし、`127.0.0.1:9876` で listen していることを確認します。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JAR を抽出する

MCP Server tab で **Extract server proxy jar** をクリックし、`mcp-proxy-all.jar` を保存します。<sup>[[7]](#references)</sup>

### 3) MCP client を設定する（Codex の例）

client が proxy JAR と Burp の direct SSE endpoint を使用するように設定します。パッケージ化された proxy は stdio-to-SSE bridge であり、Burp listener の代わりになるものではありません。<sup>[[7]](#references)</sup>
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```
対応する Codex コマンドは次のとおりです：<sup>[[7]](#references)[[8]](#references)</sup>
```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
--sse-url http://127.0.0.1:9876
```
次にCodexを実行してMCP toolsを一覧表示します:
```bash
codex
# inside Codex: /mcp
```
### 4) 必要に応じて Caddy で厳格な Origin/header 検証を修正

厳格な `Origin` チェックまたは追加の header が原因で MCP handshake に失敗する場合は、ローカル reverse proxy を使用して header を正規化します（これは Burp MCP の厳格な検証問題に対する workaround と同じです）。<sup>[[1]](#references)[[3]](#references)</sup>
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
プロキシとクライアントを起動し、この Caddy listener の使用中に限り、設定済みの `--sse-url` を `http://127.0.0.1:19876` に変更します。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```
### 5) ブラウザの状態をプロキシの証拠と紐付ける（Playwright MCP）

Playwright MCP を登録し、そのブラウザが Burp のプロキシを使用するように設定します。これにより、agent は、レンダリングされた DOM/アクセシビリティ state と、それを生成した正確な HTTP history を関連付けられます。<sup>[[6]](#references)[[8]](#references)</sup>
```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
--proxy-server=http://127.0.0.1:8080 \
--ignore-https-errors
```
リスナーアドレスを適切に設定し、Codexを再起動して、`/mcp`を使用して両方のintegrationsを確認します。この例では、Burpがローカルで生成した証明書によってHTTPS interceptionがブロックされないよう、ブラウザーの証明書エラーを無効化しています。<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP接続とinterceptされたブラウザーパスは、別々のデータフローです。MCP serviceは`127.0.0.1:9876`でBurp toolsを公開し、専用のChromium instanceは`127.0.0.1:8080`のBurp proxy経由でHTTP(S) trafficを送信します。そのため、MCP toolから直接生成されたrequestsは**Proxy > HTTP history**に存在しない場合があります。request/responseを監視、編集、またはevidenceとして保持する必要がある場合は、proxied browserを使用してください。<sup>[[2]](#references)[[9]](#references)</sup>

SSE supportを持つclientは、Burpを直接registerできます。stdio-only clientは、代わりにPortSwiggerのproxy JARを起動できます。どちらの場合も、2つ目のbrowser-control MCPをregisterし、Burpのembedded Chromium（`BURP_CHROMIUM`はlocal executable path）を指すように設定します。<sup>[[9]](#references)</sup>
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
TLS-bypassフラグはinterception proxyによって生成された証明書を許容し、`--isolated`はassessmentでoperatorの通常のブラウザプロファイルが再利用されるのを防ぎます。Isolationはプロファイルの状態を保護しますが、**security sandboxではありません**: controllerはそのテストブラウザで開かれた認証済みセッションに引き続きアクセスでき、Burp MCPは機密性の高いリクエスト、レスポンス、設定を公開する可能性があります。<sup>[[9]](#references)</sup>

client bridgeをデバッグする前に、SSE listenerを個別にテストしてください:<sup>[[9]](#references)</sup>
```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```
正常な listener は `Content-Type: text/event-stream` を返します。ヘッダー受信後の timeout は、SSE stream が今後のイベントを待つため開いたままになることから、想定される動作です。クライアントが引き続き失敗する場合は、extension に設定された route を確認してください。PortSwigger によると、endpoint はクライアントと extension の設定に応じて、root path または `/sse` になる場合があります。<sup>[[9]](#references)[[7]](#references)</sup>

## Using different clients

### Codex CLI

- 上記のとおり `~/.codex/config.toml` を設定します。
- `codex` を実行し、続けて `/mcp` を実行して Burp tools list を確認します。

### Gemini CLI

**burp-mcp-agents** repo には launcher helpers が用意されています。<sup>[[4]](#references)</sup>
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (ローカル)

提供されているランチャーヘルパーを使用し、ローカルモデルを選択します：
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
ローカルモデルとおおよそのVRAM要件の例：

- `deepseek-r1:14b`（約16GB VRAM）
- `gpt-oss:20b`（約20GB VRAM）
- `llama3.1:70b`（48GB以上のVRAM）

## Evidence-driven replay and validation

もっともらしい説明や中間レスポンスを、agentに証拠として扱わせないでください。すべてのテストを反証可能にするため、Burpのリクエスト/レスポンスと、独立して観測したbrowserの状態を使用します。<sup>[[8]](#references)</sup>

1. ベースラインとなるリクエスト/レスポンスのペアを保存し、attackerが制御する正確なコンポーネントを特定します。
2. authorizationの比較では、identifier、cookie、tokenを変更する前に、両方のaccountで同じworkflowを独立して取得します。
3. mutationをreplayする前に、仮説、証拠の場所、期待されるsignal、およびそれを反証する結果を記録します。
4. 一度に1つのcomponentだけをmutationし、結果のペアを保存して、直接観測した内容と推論を別々にラベル付けします。
5. 各candidateを`open`、`blocked`、`rejected`、`confirmed`として追跡し、mechanismまたはprerequisiteを変える新しい証拠が得られた場合にのみ再検討します。
6. attackerによるcontrol、到達可能性、再現性、constraint bypass、impact、および最終的なapplication stateを確認します。主張されたstate changeがdownstreamで発生する場合、redirectやtool callの成功だけでは証拠になりません。

exploitの詳細は、該当するtechnique pageに記載してください。たとえば、browser-messageのcandidateは[PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)に、token key-selectionの挙動は[JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)に記載します。<sup>[[8]](#references)</sup>

簡潔な仮説記録により、parallel agentが同じ魅力的なbranchを繰り返し試すことを防げます。<sup>[[8]](#references)</sup>
```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```
## パッシブレビュー用のPrompt pack

**burp-mcp-agents** repo には、Burp traffic の evidence-driven analysis 用 prompt templates が含まれています:<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 幅広い passive vulnerability surfacing。
- `idor_hunter.md`: IDOR/BOLA/object/tenant drift と auth mismatches。
- `auth_flow_mapper.md`: authenticated と unauthenticated paths を比較。
- `ssrf_redirect_hunter.md`: URL fetch params/redirect chains から SSRF/open-redirect candidates を特定。
- `logic_flaw_hunter.md`: multi-step logic flaws。
- `session_scope_hunter.md`: token audience/scope misuse。
- `rate_limit_abuse_hunter.md`: throttling/abuse gaps。
- `report_writer.md`: evidence-focused reporting。

## Optional attribution tagging

logs 内の Burp/LLM traffic に tag を付けるには、header rewrite（proxy または Burp Match/Replace）を追加します:<sup>[[1]](#references)</sup>
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## Safety notes

- トラフィックに機密データが含まれる場合は、**local models** を優先する。
- finding に必要な最小限の証拠のみを共有する。
- Burp を source of truth として維持し、model は **analysis and reporting** に使用し、scanning には使用しない。

## Burp AI Agent (AI-assisted triage + MCP tools)

**Burp AI Agent** は、local/cloud LLMs と passive/active analysis（62 種類の vulnerability classes）を連携させ、外部の MCP clients が Burp をオーケストレーションできるよう 53 個以上の MCP tools を公開する Burp extension である。<sup>[[5]](#references)</sup> 主な機能：

- **Context-menu triage**: Proxy 経由でトラフィックを取得し、**Proxy > HTTP History** を開いて request を右クリック → **Extensions > Burp AI Agent > Analyze this request** を選択すると、その request/response に紐付いた AI chat が起動する。
- **Backends**（profile ごとに選択可能）：
- Local HTTP: **Ollama**、**LM Studio**。
- Remote HTTP: **OpenAI-compatible** endpoint（base URL + model name）。
- Cloud CLIs: **Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...` または `claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（provider 固有の login）。
- **Agent profiles**: prompt templates は `~/.burp-ai-agent/AGENTS/` に自動インストールされる。この場所に追加の `*.md` files を配置すると、custom analysis/scanning behaviors を追加できる。
- **MCP server**: **Settings > MCP Server** から有効化すると、任意の MCP client に Burp operations を公開できる（53 個以上の tools）。Claude Desktop は、`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または `%APPDATA%\Claude\claude_desktop_config.json`（Windows）を編集して server を指定できる。
- **Privacy controls**: STRICT / BALANCED / OFF は、remote models に送信する前に機密性の高い request data を redact する。secrets を扱う場合は local backends を優先する。
- **Audit logging**: エントリごとに SHA-256 integrity hashing を付与した JSONL logs により、AI/MCP actions の改ざん検知可能な traceability を実現する。
- **Build/load**: release JAR を download するか、Java 21 で build する：
```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```
運用上の注意: privacy mode が強制されていない場合、cloud backends によって session cookies/PII が exfiltrate される可能性があります。MCP exposure により Burp の remote orchestration が可能になるため、アクセスを trusted agents に制限し、integrity-hashed audit log の完全性を監視してください。

## References

- [1] [Burp MCP + Codex CLI の統合と Caddy handshake の修正](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server の strict Origin/header validation の問題](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（workflows、launchers、prompt pack）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty research に Codex を使用する方法: 幅広く探索し、厳密に検証する](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code と Codex のための Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
{{#include ../banners/hacktricks-training.md}}
