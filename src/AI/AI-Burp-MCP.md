# Burp MCP: LLMを活用したトラフィックレビュー

{{#include ../banners/hacktricks-training.md}}

## 概要

Burpの**MCP Server**拡張機能を使うと、インターセプトしたHTTP(S)トラフィックをMCP対応のLLMクライアントに公開し、脆弱性の発見やレポートの下書き作成のために、実際のリクエストとレスポンスを分析できます。信頼できる情報源はBurpとし、無差別なスキャンではなく、パッシブ分析や、1つの変数だけを変更した意図的なリプレイを使用してください。<sup>[[8]](#references)</sup>

## アーキテクチャ

- **Burp MCP Server (BApp)** は、デフォルトで `127.0.0.1:9876` をリッスンし、インターセプトしたトラフィックをMCP経由で公開します。<sup>[[1]](#references)[[2]](#references)[[7]](#references)</sup>
- **MCP proxy JAR** は、stdio（クライアント側）とBurpのMCP SSEエンドポイントを橋渡しします。
- **オプションのローカルリバースプロキシ**（Caddy）は、厳格なMCPハンドシェイクチェックに対応するためにヘッダーを正規化します。
- **クライアント/バックエンド**: Codex CLI（cloud）、Gemini CLI（cloud）、またはOllama（local）。

## セットアップ

### 1) Burp MCP Serverをインストールする

Burp BApp Storeから**MCP Server**をインストールし、`127.0.0.1:9876` でリッスンしていることを確認します。<sup>[[1]](#references)[[2]](#references)</sup>

### 2) proxy JARを抽出する

MCP Serverタブで**Extract server proxy jar**をクリックし、`mcp-proxy-all.jar` を保存します。<sup>[[7]](#references)</sup>

### 3) MCPクライアントを設定する（Codexの例）

クライアントで、proxy JARとBurpの直接SSEエンドポイントを指定します。パッケージ化されたproxyはstdioからSSEへのブリッジであり、Burpのリスナーの代わりにはなりません。<sup>[[7]](#references)</sup>

```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
```

同等のCodexコマンドは次のとおりです:<sup>[[7]](#references)[[8]](#references)</sup>

```bash
codex mcp add burp -- /path/to/java -jar /path/to/mcp-proxy-all.jar \
  --sse-url http://127.0.0.1:9876
```

次にCodexを実行し、MCP toolsを一覧表示します:

```bash
codex
# inside Codex: /mcp
```

### 4) Caddyで厳格なOrigin/header検証を修正する（必要な場合）

厳格な`Origin`チェックや追加ヘッダーが原因でMCP handshakeに失敗する場合は、ローカルのreverse proxyを使ってヘッダーを正規化してください（これはBurp MCPの厳格な検証問題に対する回避策と同じです）。<sup>[[1]](#references)[[3]](#references)</sup>

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

プロキシとクライアントを起動し、この Caddy リスナーを使用している間だけ、設定済みの `--sse-url` を `http://127.0.0.1:19876` に変更します。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
caddy run --config ~/burp-mcp/Caddyfile &
codex
```

### 5) ブラウザーの状態をプロキシの証拠と紐付ける（Playwright MCP）

Playwright MCPを登録し、ブラウザーがBurpのプロキシを使用するようにします。これにより、エージェントはレンダリングされたDOM／アクセシビリティの状態を、それを生成した正確なHTTP履歴と関連付けられます。<sup>[[6]](#references)[[8]](#references)</sup>

```bash
codex mcp add playwright -- npx -y @playwright/mcp@latest \
  --proxy-server=http://127.0.0.1:8080 \
  --ignore-https-errors
```

リスナーアドレスを設定し、Codexを再起動して、`/mcp` を使って両方の連携を確認します。この例では、Burpがローカルで生成した証明書によってHTTPSのinterceptionが妨げられないよう、ブラウザーの証明書エラーを無効にしています。<sup>[[6]](#references)[[8]](#references)</sup>

## Proxy-aware browser automation (OpenBurp)

Burp MCP接続とinterceptされたブラウザーの通信経路は、別々のデータフローです。MCPサービスは`127.0.0.1:9876`でBurpのツールを提供し、一方、専用のChromiumインスタンスはHTTP(S)トラフィックをBurpのproxy（`127.0.0.1:8080`）経由で送信します。そのため、MCPツールから直接生成されたリクエストは**Proxy > HTTP history**に表示されないことがあります。リクエスト／レスポンスを確認、編集、または証拠として保存する必要がある場合は、proxy経由のブラウザーを使用してください。<sup>[[2]](#references)[[9]](#references)</sup>

SSEに対応したクライアントは、Burpを直接登録できます。stdioのみ対応するクライアントは、代わりにPortSwiggerのproxy JARを起動できます。どちらの場合も、2つ目のbrowser-control MCPを登録し、Burp内蔵のChromiumを指定します（`BURP_CHROMIUM`はローカルの実行ファイルパスです）。<sup>[[9]](#references)</sup>

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

TLS-bypass flagはinterception proxyが生成した証明書を許容し、`--isolated`はassessmentでオペレーターの通常のブラウザープロファイルが再利用されないようにします。分離によってプロファイルの状態は保護されますが、**security sandboxではありません**。controllerは、テスト用ブラウザーで開かれた認証済みセッションに引き続きアクセスでき、Burp MCPから機密性の高いリクエスト、レスポンス、設定情報が漏れる可能性があります。<sup>[[9]](#references)</sup>

client bridgeのデバッグに取りかかる前に、SSE listenerを個別にテストしてください。<sup>[[9]](#references)</sup>

```bash
curl -i --max-time 3 http://127.0.0.1:9876/
```

正常なリスナーは `Content-Type: text/event-stream` を返します。ヘッダーの送信後にタイムアウトするのは、SSE stream が今後のイベントを待つため開いたままになるので、想定どおりです。それでもクライアントが失敗する場合は、拡張機能で設定された route を確認してください。PortSwigger によると、クライアントと拡張機能の設定によって、endpoint はルートパスまたは `/sse` になることがあります。<sup>[[9]](#references)[[7]](#references)</sup>

## 異なるクライアントの使用

### Codex CLI

- 上記のとおり `~/.codex/config.toml` を設定します。
- `codex` を実行し、次に `/mcp` を実行して Burp tools の一覧を確認します。

### Gemini CLI

**burp-mcp-agents** repo には、起動用ヘルパーが用意されています。<sup>[[4]](#references)</sup>

```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```

### Ollama (local)

付属のランチャーヘルパーを使用して、ローカルモデルを選択します:

```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```

ローカルモデルの例とおおよそのVRAM要件:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## 証拠に基づく再現と検証

エージェントに、もっともらしい説明や中間応答を証拠として扱わせないでください。Burpのリクエスト/レスポンスと、ブラウザーで独立して観測した状態を使い、すべてのテストを反証可能にしてください。<sup>[[8]](#references)</sup>

1. ベースラインとなるリクエスト/レスポンスのペアを保存し、攻撃者が制御できる正確なコンポーネントを特定します。
2. 認可を比較する場合は、識別子、Cookie、トークンを変更する前に、両方のアカウントで同じワークフローをそれぞれ実行して記録します。
3. 変更を再現する前に、仮説、証拠の場所、予想されるシグナル、および仮説を否定する結果を記録します。
4. 一度に1つのコンポーネントだけを変更し、変更後のペアを保存して、直接観測した事実と推論を分けて記録します。
5. 各候補を `open`、`blocked`、`rejected`、`confirmed` のいずれかとして追跡し、メカニズムや前提条件を変える新たな証拠が得られた場合にのみ再検討します。
6. 攻撃者による制御、到達可能性、再現性、制約の回避、影響、および最終的なアプリケーション状態を確認します。リダイレクトやツール呼び出しの成功だけでは、主張された状態変更が後続処理に依存する場合、証拠にはなりません。

Exploitの詳細は、該当する手法のページに記載してください。たとえば、ブラウザーメッセージの候補は[PostMessage Vulnerabilities](../pentesting-web/postmessage-vulnerabilities/README.md)に、トークンの鍵選択動作は[JWT Vulnerabilities](../pentesting-web/hacking-jwt-json-web-tokens.md)に記載します。<sup>[[8]](#references)</sup>

簡潔な仮説の記録があれば、並行して作業するエージェントが、同じ魅力的な分岐を繰り返し調査するのを防げます。<sup>[[8]](#references)</sup>

```yaml
status: open
hypothesis: "cross-account object access ignores ownership"
evidence: ["requests/user-a.txt", "requests/user-b.txt"]
next_test: "change only the object ID in user A's request"
expected_signal: "user B's object is returned"
falsifier: "server rejects it or returns only user A's object"
```

## Burp MCP を使った対象を絞った out-of-band 検証

Burp Suite Professional は、公式 MCP extension を通じて `generate_collaborator_payload` と `get_collaborator_interactions` を公開しています。これらを `get_proxy_http_history_regex` および `send_http1_request` による1回のリプレイと組み合わせれば、対象全体をスキャンせずに、疑わしい server-side URL fetch をテストできます。Burp では、履歴の読み取りとリクエスト送信に個別の承認が必要な場合があります。<sup>[[2]](#references)[[10]](#references)</sup>

1. `url=`、`webhook`、`callback` などを含む候補リクエストを履歴から絞り込みます。元のリクエストとレスポンスを保存します。履歴ツールには `regex`、`count`、`offset` を指定します。モデルにすべてのエントリを確認させるのではなく、ページネーションを使ってください。<sup>[[10]](#references)</sup>
2. 新しい Collaborator payload を生成し、返された **payload ID** を保持します。キャプチャしたリクエストを同じホストとポートにリプレイし、候補 URL のみを、その payload domain 配下の HTTPS URL に変更します。`send_http1_request` には、完全な HTTP/1.1 リクエストを `content` として渡し、さらに `targetHostname`、`targetPort`、`usesHttps` を指定します。送信先フィールドが示すのは Collaborator host ではなく、**アプリケーション**です。<sup>[[10]](#references)</sup>
3. その payload ID を指定して `get_collaborator_interactions` をポーリングし、インタラクションの時刻をリプレイと照合します。HTTP インタラクションは fetch の裏付けになりますが、DNS のみの場合は名前解決を示すだけで、HTTP リクエストが完了したことは示しません。インタラクションの送信元とリクエストヘッダーを確認して、サーバーからの egress とブラウザー側での読み込みを区別し、無関係なトラフィックを除外するため、新しい payload でもう一度実行します。<sup>[[10]](#references)[[11]](#references)</sup>

MCP request tool はレスポンスを直接返すため、**Proxy > HTTP history** に記録されるとは限りません。リクエストとレスポンスの結果を保存するか、履歴に残る証跡が必要な場合は proxied browser または Repeater を使用してください。SSRF payload の選定と後続テストについては、out-of-band callback を内部ネットワークへの影響の証明と見なさず、[SSRF chapter](../pentesting-web/ssrf-server-side-request-forgery/) を参照してください。MCP server 自体をテストする場合は、[MCP server testing](AI-MCP-Servers.md#remote-mcp-server-testing-workflow) を参照してください。<sup>[[7]](#references)[[11]](#references)</sup>

## Passive review 用プロンプトパック

**burp-mcp-agents** repo には、Burp traffic を証拠に基づいて分析するためのプロンプトテンプレートが含まれています。<sup>[[4]](#references)</sup>

- `passive_hunter.md`: 幅広い passive vulnerability の検出。
- `idor_hunter.md`: IDOR/BOLA/object/tenant のずれや認証の不一致。
- `auth_flow_mapper.md`: 認証済みパスと未認証パスの比較。
- `ssrf_redirect_hunter.md`: URL fetch parameter や redirect chain に基づく SSRF/open-redirect 候補の検出。
- `logic_flaw_hunter.md`: 複数ステップにまたがる logic flaw。
- `session_scope_hunter.md`: token の audience/scope の不正使用。
- `rate_limit_abuse_hunter.md`: throttling/abuse の不備。
- `report_writer.md`: 証拠重視のレポート作成。

## 任意の attribution tagging

ログ内の Burp/LLM traffic にタグを付けるには、header rewrite を追加します（proxy または Burp Match/Replace）。<sup>[[1]](#references)</sup>

```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```

## 安全上の注意

- トラフィックに機密データが含まれる場合は、**ローカルモデル**を優先してください。
- 脆弱性の報告に必要な最小限の証拠のみを共有してください。
- Burpを信頼できる唯一の情報源として使用し、モデルはスキャンではなく、**分析とレポート作成**に使用してください。

## Burp AI Agent（AI支援トリアージ + MCP tools）

**Burp AI Agent**は、ローカル/クラウドLLMとパッシブ/アクティブ分析（62の脆弱性クラス）を連携させ、外部のMCPクライアントがBurpを操作できるよう、53以上のMCP toolsを公開するBurp extensionです。<sup>[[5]](#references)</sup> 主な機能:

- **コンテキストメニューでのトリアージ**: Proxyでトラフィックを取得し、**Proxy > HTTP History**を開いてリクエストを右クリック → **Extensions > Burp AI Agent > Analyze this request**を選択すると、そのリクエスト/レスポンスに紐付いたAIチャットが起動します。
- **バックエンド**（プロファイルごとに選択可能）:
  - ローカルHTTP: **Ollama**、**LM Studio**。
  - リモートHTTP: **OpenAI-compatible** endpoint（base URL + model name）。
  - Cloud CLI: **Gemini CLI**（`gemini auth login`）、**Claude CLI**（`export ANTHROPIC_API_KEY=...`または`claude login`）、**Codex CLI**（`export OPENAI_API_KEY=...`）、**OpenCode CLI**（プロバイダー固有のログイン）。
- **Agentプロファイル**: prompt templateは`~/.burp-ai-agent/AGENTS/`に自動インストールされます。追加の`*.md`ファイルを配置すると、独自の分析/スキャン動作を追加できます。
- **MCP server**: **Settings > MCP Server**で有効にすると、任意のMCPクライアントにBurp操作を公開できます（53以上のtools）。Claude Desktopを接続するには、`~/Library/Application Support/Claude/claude_desktop_config.json`（macOS）または`%APPDATA%\Claude\claude_desktop_config.json`（Windows）を編集します。
- **プライバシー制御**: STRICT / BALANCED / OFFにより、リモートモデルに送信する前に機密性の高いリクエストデータをマスキングします。シークレットを扱う場合はローカルバックエンドを優先してください。
- **監査ログ**: エントリーごとのSHA-256整合性ハッシュを含むJSONLログにより、AI/MCP操作を改ざん検知可能な形で追跡できます。
- **ビルド/読み込み**: リリースJARをダウンロードするか、Java 21でビルドします:

```bash
git clone https://github.com/six2dez/burp-ai-agent.git
cd burp-ai-agent
JAVA_HOME=/path/to/jdk-21 ./gradlew clean shadowJar
# load build/libs/Burp-AI-Agent-<version>.jar via Burp Extensions > Add (Java)
```

運用上の注意: privacy mode が適用されていない場合、cloud backend が session cookie/PII を外部に流出させる可能性があります。MCP を公開すると Burp のリモート操作が可能になるため、アクセスを信頼できる agent に限定し、整合性ハッシュ付きの audit log を監視してください。



## References

- [1] [Burp MCP + Codex CLI 統合と Caddy handshake の修正](https://pentestbook.six2dez.com/others/burp)
- [2] [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [3] [PortSwigger MCP server の strict Origin/header 検証に関する問題](https://github.com/PortSwigger/mcp-server/issues/34)
- [4] [Burp MCP Agents（workflow、launcher、prompt pack）](https://github.com/six2dez/burp-mcp-agents)
- [5] [Burp AI Agent](https://github.com/six2dez/burp-ai-agent)
- [6] [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [7] [PortSwigger Burp Suite MCP Server](https://github.com/PortSwigger/mcp-server)
- [8] [Bug Bounty 調査での Codex の使い方: 幅広く調査し、厳密に検証する](https://www.yeswehack.com/learn-bug-bounty/llm-series-codex)
- [9] [OpenBurp: Claude Code と Codex 向け Burp Suite orchestration](https://github.com/luispacheco22/OpenBurp)
- [10] [PortSwigger MCP Server の tool 実装と parameter](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt)
- [11] [PortSwigger Web Security Academy - Blind SSRF の脆弱性](https://portswigger.net/web-security/ssrf/blind)
{{#include ../banners/hacktricks-training.md}}
