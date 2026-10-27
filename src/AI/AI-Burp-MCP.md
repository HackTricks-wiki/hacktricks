# Burp MCP: LLMを活用したトラフィックレビュー

{{#include ../banners/hacktricks-training.md}}

## 概要

Burpの**MCP Server** extensionを使うと、インターセプトしたHTTP(S)トラフィックをMCP対応のLLMクライアントに公開し、脆弱性の発見やレポートの下書き作成のために、実際のリクエスト／レスポンスを**分析**できます。Burpを信頼できる唯一の情報源とし、無差別なスキャンではなく、passive analysisや意図的に1つの変数だけを変更したリプレイを使用してください。<sup>[[8]](#references)</sup>

## アーキテクチャ

- **Burp MCP Server (BApp)**は、デフォルトで`127.0.0.1:9876`をリッスンし、インターセプトしたトラフィックをMCP経由で公開します。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR**は、stdio（クライアント側）とBurpのMCP SSE endpointを接続します。
- **任意のローカルreverse proxy**（Caddy）は、厳格なMCP handshakeチェックに対応するようheaderを正規化します。
- **クライアント／バックエンド**：Codex CLI（cloud）、Gemini CLI（cloud）、またはOllama（local）。

## セットアップ

### 1) Burp MCP Serverをインストールする

Burp BApp Storeから**MCP Server**をインストールし、`127.0.0.1:9876`でリッスンしていることを確認します。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JARを抽出する

MCP Serverタブで**Extract server proxy jar**をクリックし、`mcp-proxy-all.jar`を保存します。<sup>[[7]](#references)</sup>

### 3) MCPクライアントを設定する（Codexの例）

クライアントをproxy JARとBurpの直接のSSE endpointに接続します。パッケージ化されたproxyはstdioからSSEへのbridgeであり、Burpのlistenerを置き換えるものではありません。<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

同等の Codex コマンドは次のとおりです:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

次にCodexを実行し、MCPツールを一覧表示します:

```bash
codex
# inside Codex: /mcp
```

### 4) Caddyで厳密なOrigin/header検証を修正する（必要な場合）

厳密な`Origin`チェックや追加ヘッダーが原因でMCPハンドシェイクに失敗する場合は、ローカルのリバースプロキシを使ってヘッダーを正規化してください（これはBurp MCPの厳密な検証問題に対する回避策と同じです）。<sup>[[1]](#references)[[3]](#references)</sup>

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

proxy と client を起動し、この Caddy listener を使用している間に限り、設定済みの `--sse-url` を `http://127.0.0.1:19876` に変更します:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) ブラウザーの状態をproxyの証拠と組み合わせる（Playwright MCP）

Playwright MCPを登録し、ブラウザーがBurpのproxyを使うようにします。これにより、agentはレンダリングされたDOM/accessibilityの状態を、それを生成した正確なHTTP履歴と関連付けられます。<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

リスナーアドレスを設定し、Codexを再起動して、`/mcp`を使って両方の連携を確認します。この例では、Burpがローカルで生成した証明書によってHTTPSのinterceptionが妨げられないよう、ブラウザーの証明書エラーを無効にしています。<sup>[[6]](#references)[[8]](#references)</sup>

## Proxyを認識したブラウザー自動化（OpenBurp）

Burp MCP接続と、interceptされるブラウザーパスは別々のデータフローです。MCPサービスは`127.0.0.1:9876`でBurpツールを公開し、専用のChromiumインスタンスはBurpのproxy（`127.0.0.1:8080`）経由でHTTP(S)トラフィックを送信します。そのため、MCPツールから直接生成されたリクエストは**Proxy > HTTP history**に表示されない場合があります。リクエスト／レスポンスを確認、編集、または証拠として保存する必要がある場合は、proxy経由のブラウザーを使用してください。<sup>[[2]](#references)[[9]](#references)</sup>

SSEに対応したクライアントでは、Burpを直接登録できます。stdioのみ対応するクライアントでは、代わりにPortSwiggerのproxy JARを起動できます。どちらの場合も、2つ目のブラウザー制御用MCPを登録し、Burpに組み込まれたChromiumを指定します（`BURP_CHROMIUM`はローカルの実行ファイルパスです）。<sup>[[9]](#references)</sup>

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

TLS-bypassフラグを使うと、interception proxyが生成した証明書を許容できます。一方、`--isolated`を指定すると、assessmentでオペレーターの通常のブラウザプロファイルが再利用されなくなります。分離によってプロファイルの状態は保護されますが、**セキュリティサンドボックスではありません**。controllerは、テスト用ブラウザで開いた認証済みセッションに引き続きアクセスでき、Burp MCPから機密性の高いリクエスト、レスポンス、設定が漏れる可能性があります。<sup>[[9]](#references)</sup>

クライアントブリッジのデバッグを始める前に、SSE listenerを個別にテストしてください。<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

正常な listener は `Content-Type: text/event-stream` を返します。ヘッダー送信後にタイムアウトするのは、SSE stream が今後のイベントを待って開いたままになるため、想定どおりです。それでもクライアントが失敗する場合は、extension で設定されている route を確認してください。PortSwigger によると、endpoint はクライアントと extension の設定によって、root path または `/sse` の場合があります。<sup>[[9]](#references)[[7]](#references)</sup>

## 異なるクライアントの使用

### Codex CLI

- 上記のとおり `~/.codex/config.toml` を設定します。
- `codex` を実行し、続いて `/mcp` を実行して Burp tools の一覧を確認します。

### Gemini CLI

**burp-mcp-agents** repo には launcher helper が用意されています。<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

用意されているランチャーヘルパーを使い、ローカルモデルを選択します。

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

ローカルモデルの例とおおよそのVRAM要件:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 証拠に基づくリプレイと検証

もっともらしい説明や中間応答を、エージェントに証拠として扱わせないでください。Burpのリクエスト／レスポンスと、ブラウザーで独立して観察した状態を使い、すべてのテストを反証可能にしてください。<sup>[[8]](#references)</sup>

1. ベースラインのリクエスト／レスポンスのペアを保存し、攻撃者が制御するコンポーネントを正確に特定します。
2. 認可の比較では、識別子、Cookie、トークンを変更する前に、両方のアカウントで同じワークフローを個別にキャプチャします。
3. 変更をリプレイする前に、仮説、証拠の場所、予想されるシグナル、および仮説を反証する結果を記録します。
4. 一度に1つのコンポーネントだけを変更し、変更後のペアを保存して、直接観察した事実と推論を分けて記録します。
5. 各候補を `open`、`blocked`、`rejected`、または `confirmed` として追跡し、新たな証拠によって仕組みまたは前提条件が変わった場合にのみ再検討します。
6. 攻撃者による制御、到達可能性、再現性、制約のbypass、影響、および最終的なアプリケーションの状態を確認します。主張されている状態変更が後続処理で発生する場合、リダイレクトやツール呼び出しの成功だけでは証明になりません。

exploitの詳細は、該当する手法のページに記載してください。たとえば、ブラウザーメッセージの候補は[PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)に、トークンのkey-selectionの挙動は[JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)に記載します。<sup>[[8]](#references)</sup>

簡潔な仮説記録があれば、並行して作業するエージェントが同じ魅力的な分岐を繰り返し調査するのを防げます。<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP を使った WebSocket フレームのトリアージ

公式拡張は、Burp の WebSocket history を読み取り専用でページネーション検索する `get_proxy_websocket_history_regex` を公開しています。引数は `regex`、`count`、`offset` です。`send_http1_request` とは異なり、WebSocket frame は送信しません。Intercept がオフでも Burp は双方向のメッセージを記録するため、関連するフレームを少数に絞ってからモデルに渡してください。<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>

1. Burp 経由のブラウザーで、同じ WebSocket ベースの操作を、個別に認証した2つのテストアカウントで実行します。各 upgrade handshake とその cookie、接続 ID、フレームの方向、レスポンスフレームをひとまとまりにして扱います。1つ目のアカウントの接続で発生したサーバーからクライアントへのイベントは、2つ目のアカウントがそれを受信した証拠にはなりません。
2. `get_proxy_websocket_history_regex` を、`(?i)(subscribe|room|tenant|objectId)` のような絞り込んだ式と、`count: 20`、`offset: 0` で検索します。後続の一致を確認するには `offset` を進めます。送信フレームの object または topic identifier を、**同じ接続**上のレスポンスと比較します。
3. **Proxy > WebSockets history** で、候補となる送信フレームを Repeater に送ります。適切なオープン接続にアタッチするか、2つ目のアカウントの handshake を使って再接続します。object/topic identifier だけを変更し、返されるサーバーメッセージとアプリケーションの状態を両方のベースラインと比較します。MCP history tool ではこのリプレイを実行できません。WebSocket Repeater では、フレームの編集、再送信、再接続が可能です。

cross-site WebSocket hijacking や broker topic authorization など、プロトコル固有のテストについては、[WebSocket Attacks](../pentesting-web/websocket-attacks.md) を参照してください。upgrade が受け入れられたことや、クライアント側の echo を、保護された subscription が成功した証拠として扱わないでください。

## Burp MCP を使ったピンポイントの out-of-band 検証

Burp Suite Professional は、公式 MCP 拡張を通じて `generate_collaborator_payload` と `get_collaborator_interactions` を公開しています。これらを `get_proxy_http_history_regex` と1回の `send_http1_request` リプレイと組み合わせると、ターゲット全体をスキャンせずに、疑わしいサーバー側 URL fetch をテストできます。Burp では、history の読み取りとリクエストの送信にそれぞれ個別の承認が必要な場合があります。<sup>[[2]](#references)[[10]](#references)</sup>

1. `url=`、`webhook`、`callback` を含むものなど、URL を含む候補リクエストを history から絞り込みます。元のリクエストとレスポンスを保存します。history tool の引数は `regex`、`count`、`offset` です。モデルにすべてのエントリーを確認させるのではなく、ページネーションしてください。<sup>[[10]](#references)</sup>
2. 新しい Collaborator payload を生成し、返された **payload ID** を保持します。キャプチャしたリクエストを同じ host と port にリプレイし、候補 URL だけをその payload domain 配下の HTTPS URL に変更します。`send_http1_request` では、HTTP/1.1 リクエスト全体を `content` として渡し、さらに `targetHostname`、`targetPort`、`usesHttps` を指定します。宛先フィールドが示すのは Collaborator host ではなく、**アプリケーション**です。<sup>[[10]](#references)</sup>
3. その payload ID を指定して `get_collaborator_interactions` をポーリングし、interaction の発生時刻をリプレイと照合します。HTTP interaction は fetch があったことを裏付けますが、DNS のみの場合は名前解決を示すだけで、HTTP リクエストが完了したことまでは示しません。interaction の発生元とリクエストヘッダーを確認して、サーバーからの通信とブラウザー側の読み込みを区別します。その後、新しい payload で再テストし、無関係なトラフィックでないことを確認します。<sup>[[10]](#references)[[11]](#references)</sup>

MCP request tool はレスポンスを直接返すため、**Proxy > HTTP history** に記録されるとは限りません。そのリクエストとレスポンスの結果を保存するか、プロキシ経由のブラウザーまたは Repeater を使って history に記録される成果物を取得してください。SSRF payload の選定と後続テストについては、out-of-band callback を内部ネットワークへの影響の証拠として扱わず、[SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) を参照してください。MCP server 自体のテストについては、[MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) を参照してください。<sup>[[7]](#references)[[11]](#references)</sup>

## パッシブレビュー用プロンプト集

**burp-mcp-agents** repo には、Burp traffic を証拠に基づいて分析するためのプロンプトテンプレートが含まれています。<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 幅広いパッシブな脆弱性の検出。
- `idor_hunter.md`: IDOR/BOLA/object/tenant の不整合と認証の不一致。
- `auth_flow_mapper.md`: 認証済みパスと未認証パスの比較。
- `ssrf_redirect_hunter.md`: URL fetch パラメーターやリダイレクトチェーンからの SSRF/open-redirect 候補の検出。
- `logic_flaw_hunter.md`: 複数ステップにまたがるロジックの欠陥。
- `session_scope_hunter.md`: token audience/scope の誤用。
- `rate_limit_abuse_hunter.md`: throttling/abuse の不備。
- `report_writer.md`: 証拠を重視したレポート作成。

## 任意の帰属タグ付け

ログで Burp/LLM traffic をタグ付けするには、header rewrite（proxy または Burp Match/Replace）を追加します。<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## 安全上の注意

- トラフィックに機密データが含まれる場合は、**ローカルモデル**を優先してください。
- finding に必要な最小限の証拠のみ共有してください。
- Burp を信頼できる唯一の情報源として維持し、モデルは**分析とレポート作成**に使用し、スキャンには使用しないでください。

## Burp AI Agent（AI支援のtriage + MCPツール）

**Burp AI Agent**は、ローカル／クラウドLLMとパッシブ／アクティブ分析（62の脆弱性クラス）を組み合わせ、外部のMCPクライアントがBurpを操作できるように53以上のMCPツールを提供するBurp拡張機能です。<sup>[[5]](#references)</sup> 主な機能：

- **コンテキストメニューからのtriage**：Proxyでトラフィックを取得し、**Proxy > HTTP History**を開いてリクエストを右クリックし、**Extensions > Burp AI Agent > Analyze this request**を選択すると、そのリクエスト／レスポンスに紐付いたAIチャットが起動します。
- **バックエンド**（プロファイルごとに選択可能）：
  - ローカルHTTP：**Ollama**、**LM Studio**。
  - リモートHTTP：**OpenAI互換**エンドポイント（base URL + model name）。
  - クラウドCLI：**Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...`または`claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（プロバイダー固有のログイン）。
- **Agent profiles**：プロンプトテンプレートは`~/.burp-ai-agent/AGENTS/`に自動インストールされます。この場所に追加の`*.md`ファイルを配置すると、カスタムの分析／スキャン動作を追加できます。
- **MCP server**：**Settings > MCP Server**で有効にすると、任意のMCPクライアントにBurpの操作（53以上のツール）を公開できます。Claude Desktopをサーバーに接続するには、`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または`%APPDATA%\Claude\claude_desktop_config.json`（Windows）を編集します。
- **プライバシー制御**：STRICT / BALANCED / OFFにより、リモートモデルに送信する前に機密性の高いリクエストデータを redact します。機密情報を扱う場合は、ローカルバックエンドを優先してください。
- **監査ログ**：改ざんを検知できるAI/MCP操作の追跡のため、エントリーごとにSHA-256整合性ハッシュを付与したJSONLログを記録します。
- **ビルド／読み込み**：リリースJARをダウンロードするか、Java 21でビルドします：

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

運用上の注意: privacy mode が適用されていない場合、cloud backend から session cookie/PII が流出する可能性があります。MCP を公開すると Burp のリモート操作が可能になるため、アクセスを信頼できる agent に限定し、整合性ハッシュ付きの audit log を監視してください。



## References

- [1] [Burp MCP + Codex CLI の統合と Caddy handshake の修正](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server の厳格な Origin/header 検証に関する問題](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（workflow、launcher、prompt pack）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty 調査で Codex を使う方法: 幅広く探索し、厳密に検証する](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code と Codex 向けの Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server の tool 実装とパラメータ](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF の脆弱性](https://portswigger.net/web-security/ssrf/blind)
- [12] [PortSwigger - WebSockets の履歴](https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history)
- [13] [PortSwigger - Burp Repeater での WebSocket メッセージの操作](https://portswigger.net/burp/documentation/desktop/tools/repeater/websocket-messages)
{{#include ../banners/hacktricks-training.md}}
