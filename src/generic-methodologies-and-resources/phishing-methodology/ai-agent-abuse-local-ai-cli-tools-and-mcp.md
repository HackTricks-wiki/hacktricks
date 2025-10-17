# AIエージェントの悪用: ローカルAI CLIツールとMCP (Claude/Gemini/Warp)

{{#include ../../banners/hacktricks-training.md}}

## 概要

Claude Code、Gemini CLI、WarpなどのローカルAIコマンドラインインターフェース（AI CLIs）は、ファイルシステムの読み書き、シェル実行、外向きネットワークアクセスといった強力な組み込み機能を備えていることが多い。多くはMCPクライアント（Model Context Protocol）として動作し、モデルがSTDIOやHTTP経由で外部ツールを呼び出せるようにする。LLMがツールチェーンを非決定論的に計画するため、同一のプロンプトでも実行やホストごとにプロセス、ファイル、ネットワークの挙動が異なることがある。

Key mechanics seen in common AI CLIs:
- Typically implemented in Node/TypeScript with a thin wrapper launching the model and exposing tools.
- Multiple modes: interactive chat, plan/execute, and single‑prompt run.
- MCP client support with STDIO and HTTP transports, enabling both local and remote capability extension.

悪用の影響：単一のプロンプトで資格情報のインベントリ取得やエクスフィルトレーション、ローカルファイルの変更、リモートMCPサーバーに接続して静かに機能を拡張することが可能（これらのサーバーがサードパーティの場合、可視性のギャップが生じる）。

---

## Adversary Playbook – Prompt‑Driven Secrets Inventory

エージェントに、静かに資格情報/シークレットを迅速にトリアージしてエクスフィルトレーションのためにステージングするよう指示する：

- Scope: recursively enumerate under $HOME and application/wallet dirs; avoid noisy/pseudo paths (`/proc`, `/sys`, `/dev`).
- Performance/stealth: cap recursion depth; avoid `sudo`/priv‑escalation; summarise results.
- Targets: `~/.ssh`, `~/.aws`, cloud CLI creds, `.env`, `*.key`, `id_rsa`, `keystore.json`, browser storage (LocalStorage/IndexedDB profiles), crypto‑wallet data.
- Output: write a concise list to `/tmp/inventory.txt`; if the file exists, create a timestamped backup before overwrite.

Example operator prompt to an AI CLI:
```
You can read/write local files and run shell commands.
Recursively scan my $HOME and common app/wallet dirs to find potential secrets.
Skip /proc, /sys, /dev; do not use sudo; limit recursion depth to 3.
Match files/dirs like: id_rsa, *.key, keystore.json, .env, ~/.ssh, ~/.aws,
Chrome/Firefox/Brave profile storage (LocalStorage/IndexedDB) and any cloud creds.
Summarize full paths you find into /tmp/inventory.txt.
If /tmp/inventory.txt already exists, back it up to /tmp/inventory.txt.bak-<epoch> first.
Return a short summary only; no file contents.
```
---

## Capability Extension via MCP (STDIO and HTTP)

AI CLIs は追加ツールに到達するためにしばしば MCP クライアントとして動作します:

- STDIO transport (local tools): クライアントはツールサーバを実行するヘルパーチェーンを生成します。典型的な系譜: `node → <ai-cli> → uv → python → file_write`。観測例: `uv run --with fastmcp fastmcp run ./server.py` は `python3.13` を起動し、エージェントの代わりにローカルファイル操作を行います。
- HTTP transport (remote tools): クライアントは outbound TCP（例: port 8000）をリモートの MCP サーバに開き、サーバ側で要求されたアクションを実行します（例: `/home/user/demo_http` に書き込み）。エンドポイント側ではクライアントのネットワーク活動のみが観測され、サーバ側のファイル操作はホスト外で発生します。

Notes:
- MCP tools はモデルに記述され、planning により自動選択される場合があります。挙動は実行ごとに変わります。
- Remote MCP servers は blast radius を増やし、ホスト側の可視性を低下させます。

---

## Local Artifacts and Logs (Forensics)

- Gemini CLI session logs: `~/.gemini/tmp/<uuid>/logs.json`
- Fields commonly seen: `sessionId`, `type`, `message`, `timestamp`.
- Example `message`: `"@.bashrc what is in this file?"` (user/agent intent captured).
- Claude Code history: `~/.claude/history.jsonl`
- JSONL entries with fields like `display`, `timestamp`, `project`.

これらのローカルログを LLM gateway/proxy（例: LiteLLM）で観測されるリクエストと相関させ、tampering/model‑hijacking を検出します: モデルが処理した内容がローカルのプロンプト/出力と乖離している場合は、注入された指示や改ざんされたツール記述子を調査してください。

---

## Endpoint Telemetry Patterns

Representative chains on Amazon Linux 2023 with Node v22.19.0 and Python 3.13:

1) Built‑in tools (local file access)
- Parent: `node .../bin/claude --model <model>` (or equivalent for the CLI)
- Immediate child action: create/modify a local file (e.g., `demo-claude`). ファイルイベントを parent→child の系譜で関連付けます。

2) MCP over STDIO (local tool server)
- Chain: `node → uv → python → file_write`
- Example spawn: `uv run --with fastmcp fastmcp run /home/ssm-user/tools/server.py`

3) MCP over HTTP (remote tool server)
- Client: `node/<ai-cli>` が outbound TCP を `remote_port: 8000`（または類似）に開く
- Server: リモートの Python プロセスがリクエストを処理し `/home/ssm-user/demo_http` に書き込む

エージェントの判断は実行ごとに異なるため、正確なプロセスや触れられるパスにはばらつきがあることを想定してください。

---

## Detection Strategy

Telemetry sources
- Linux EDR: process、file、network イベントのための eBPF/auditd を使用。
- Local AI‑CLI logs: プロンプト/意図の可視化。
- LLM gateway logs（例: LiteLLM）: クロスバリデーションと model‑tamper 検出。

Hunting heuristics
- 敏感なファイルアクセスを AI‑CLI の親系譜（例: `node → <ai-cli> → uv/python`）に紐付ける。
- 次のパス以下のアクセス/読み取り/書き込みをアラート: `~/.ssh`, `~/.aws`, ブラウザプロファイル保存領域、クラウド CLI の資格情報、`/etc/passwd`。
- AI‑CLI プロセスから未承認の MCP エンドポイント（HTTP/SSE、8000 等のポート）への予期しない outbound 接続をフラグ付けする。
- ローカルの `~/.gemini`/`~/.claude` アーティファクトを LLM gateway のプロンプト/出力と相関させる；差異は hijacking の可能性を示唆する。

Example pseudo‑rules (adapt to your EDR):

---
```yaml
- when: file_write AND path IN ["$HOME/.ssh/*","$HOME/.aws/*","/etc/passwd"]
and ancestor_chain CONTAINS ["node", "claude|gemini|warp", "python|uv"]
then: alert("AI-CLI secrets touch via tool chain")

- when: outbound_tcp FROM process_name =~ "node|python" AND parent =~ "claude|gemini|warp"
and dest_port IN [8000, 3333, 8787]
then: tag("possible MCP over HTTP")
```
ハードニングのアイデア
- ファイル/システムツールには明示的なユーザー承認を要求する。ツールの実行計画はログに記録して可視化する。
- AI‑CLI プロセスのネットワーク egress を承認済みの MCP サーバーに制限する。
- ローカルの AI‑CLI ログと LLM gateway ログを送信/取り込みし、一貫性があり改ざん耐性のある監査を行えるようにする。

---

## Blue‑Team 再現ノート

EDR や eBPF トレーサーを導入したクリーンな VM を使用して、以下のようなチェーンを再現する:
- `node → claude --model claude-sonnet-4-20250514` その後すぐにローカルファイルを書き込む。
- `node → uv run --with fastmcp ... → python3.13` `$HOME` 以下に書き込む。
- `node/<ai-cli>` が外部の MCP サーバー（port 8000）へ TCP を確立している一方で、リモートの Python プロセスがファイルを書き込む。

検知がファイル／ネットワークのイベントを起点となった AI‑CLI 親プロセスに紐づけていることを検証し、誤検知を避ける。

---

## 参考資料

- [Commanding attention: How adversaries are abusing AI CLI tools (Red Canary)](https://redcanary.com/blog/threat-detection/ai-cli-tools/)
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
- [LiteLLM – LLM Gateway/Proxy](https://docs.litellm.ai)

{{#include ../../banners/hacktricks-training.md}}
