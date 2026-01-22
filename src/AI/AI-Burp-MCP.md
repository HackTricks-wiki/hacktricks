# Burp MCP: LLM-assisted traffic review

{{#include ../banners/hacktricks-training.md}}

## Overview

Burpの**MCP Server**拡張は、インターセプトしたHTTP(S)トラフィックをMCP対応のLLMクライアントに公開し、実際のリクエスト/レスポンスを基に受動的な脆弱性発見やレポート作成のために推論させることができます。意図はエビデンス駆動のレビューであり（fuzzingやblind scanningは行わない）、Burpを唯一の信頼できる情報源として維持します。

## Architecture

- **Burp MCP Server (BApp)** は `127.0.0.1:9876` でリスニングし、MCP経由でインターセプトしたトラフィックを公開します。
- **MCP proxy JAR** は stdio（クライアント側）とBurpのMCP SSE endpointをブリッジします。
- **Optional local reverse proxy**（Caddy）は、厳格なMCPハンドシェイクチェックのためにヘッダを正規化します。
- **Clients/backends**: Codex CLI (cloud), Gemini CLI (cloud), または Ollama (local)。

## Setup

### 1) Install Burp MCP Server

Burp BApp Storeから**MCP Server**をインストールし、`127.0.0.1:9876` でリスニングしていることを確認します。

### 2) Extract the proxy JAR

MCP Serverタブで **Extract server proxy jar** をクリックし、`mcp-proxy.jar` を保存します。

### 3) Configure an MCP client (Codex example)

クライアントをproxy JARとBurpのSSE endpointに向けます：
```toml
# ~/.codex/config.toml
[mcp_servers.burp]
command = "java"
args = ["-jar", "/absolute/path/to/mcp-proxy.jar", "--sse-url", "http://127.0.0.1:19876"]
```
src/AI/AI-Burp-MCP.md の内容を送ってください。受け取ったら、英語テキストを日本語に翻訳して、マークダウン/HTML構文はそのまま保持します。

外部サービスやツール（Codexなど）をこちらで実行することはできません。Codexを「実行してほしい」とのことですが、具体的にどの処理（例: リポジトリ内ファイルの解析、既知ツールの照会、コード生成など）を期待していますか？

また、「MCP tools」が指す対象を教えてください（例: BurpのMCP、別製品のMCP、あるいは該当ファイル内のセクション）。その情報があれば、該当箇所を翻訳してMCP toolsの一覧を抽出します。
```bash
codex
# inside Codex: /mcp
```
### 4) Caddyで厳格な Origin/header 検証を修正する（必要なら）

MCP handshake が厳格な `Origin` チェックや追加ヘッダーのために失敗する場合は、ローカルの reverse proxy を使ってヘッダーを正規化してください（これは Burp の MCP 厳格検証問題に対する回避策と一致します）。
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

- `~/.codex/config.toml` を上記の通りに設定します。
- `codex` を実行し、`/mcp` で Burpツールの一覧を確認します。

### Gemini CLI

**burp-mcp-agents** リポジトリは起動用のヘルパーを提供します:
```bash
source /path/to/burp-mcp-agents/gemini-cli/burpgemini.sh
burpgemini
```
### Ollama (local)

提供されたランチャーヘルパーを使用して、ローカルモデルを選択してください:
```bash
source /path/to/burp-mcp-agents/ollama/burpollama.sh
burpollama deepseek-r1:14b
```
ローカルモデルの例と必要な VRAM の目安:

- `deepseek-r1:14b` (~16GB VRAM)
- `gpt-oss:20b` (~20GB VRAM)
- `llama3.1:70b` (48GB+ VRAM)

## パッシブレビュー向けプロンプトパック

The **burp-mcp-agents** リポジトリには、Burp トラフィックのエビデンス主導解析用のプロンプトテンプレートが含まれています:

- `passive_hunter.md`: 広範なパッシブ脆弱性の検出。
- `idor_hunter.md`: IDOR/BOLA、オブジェクト/テナントのドリフトや認証の不一致。
- `auth_flow_mapper.md`: 認証済みと未認証のパスを比較。
- `ssrf_redirect_hunter.md`: URL fetch パラメータやリダイレクトチェーンからの SSRF/open-redirect 候補。
- `logic_flaw_hunter.md`: 多段階のロジック欠陥。
- `session_scope_hunter.md`: トークンの audience/scope の誤用。
- `rate_limit_abuse_hunter.md`: レート制限の緩み／悪用の隙間。
- `report_writer.md`: エビデンス重視のレポート作成。

## 任意のアトリビューションタグ付け

ログ内の Burp/LLM トラフィックにタグを付けるには、ヘッダーを書き換える（proxy または Burp Match/Replace）を追加してください:
```text
Match:   ^User-Agent: (.*)$
Replace: User-Agent: $1 BugBounty-Username
```
## 安全上の注意

- トラフィックに機密データが含まれる場合は **local models** を優先してください。
- 検出結果に必要な最小限の証拠のみを共有してください。
- Burpを真の情報源として維持し、モデルは **analysis and reporting** に利用し、スキャンには使用しないでください。

## 参考

- [Burp MCP + Codex CLI integration and Caddy handshake fix](https://pentestbook.six2dez.com/others/burp)
- [Burp MCP Agents (workflows, launchers, prompt pack)](https://github.com/six2dez/burp-mcp-agents)
- [Burp MCP Server BApp](https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
- [PortSwigger MCP server strict Origin/header validation issue](https://github.com/PortSwigger/mcp-server/issues/34)

{{#include ../banners/hacktricks-training.md}}
