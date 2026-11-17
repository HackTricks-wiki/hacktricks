# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## モデルをローカルで実行・トレーニングする

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformersは、テキスト、ビジョン、音声、動画、マルチモーダルのタスク向けに、事前学習済みモデルを読み込み、トレーニングし、提供するためのオープンソースライブラリです。モデルとデータセットのホスティングは、別途Hugging Face Hubが提供しています。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChainは、プロンプトの構築、会話履歴や状態の管理、ツール、検索、モデル、API、データベースとの連携機能を備えた、モデル駆動型アプリケーションやエージェントを構築するためのフレームワークです。<sup>[[2]](#references)</sup>

#### LangChainのシリアライズされたオブジェクトの復元をテストする

アプリケーションがユーザー入力やモデル出力を**構造化データ**として受け付ける場合、ネストされた辞書が `metadata`、`additional_kwargs`、`response_metadata`、保存されたチャット履歴、または実行ストリーム内に保持されるかを追跡してください。LangChainは、`lc`タグ付きの辞書をシリアライズされたオブジェクトとして扱います。影響を受ける `dumps()`/`dumpd()` → `load()`/`loads()` の往復処理では、攻撃者が制御する辞書がデータのままではなく、フレームワークオブジェクトとして復元される可能性があります。信頼できないマニフェストを直接読み込むことも危険です。一方、辞書として解析されない単なる文字列入力は、この前提条件を満たしません。<sup>[[10]](#references)[[11]](#references)</sup>

許可を得たテストでは、無害なコンストラクター形式のcanaryを文字列ではなく**ネストされたJSONオブジェクト**として送信し、後続の履歴またはストリームに元の辞書ではなく `AIMessage` オブジェクトが含まれるかを確認してください。<sup>[[11]](#references)</sup>

```json
{"lc":1,"type":"constructor","id":["langchain_core","messages","ai","AIMessage"],"kwargs":{"content":"serialization-canary"}}
```

`RunnableWithMessageHistory`、`astream_log()`、`astream_events(version="v1")` が実際に使用される場面を確認してください。オブジェクトの復元に成功すると、その後のチャット履歴が汚染される可能性があります。また、allowlistを広げると、コンストラクターに副作用のある別の信頼済みクラスがインスタンス化される可能性があります。これを無制限のpickle実行と同一視しないでください。元のエスケープの欠陥は `langchain-core` 0.3.81/1.2.5 で修正され、後の広範なallowlistとsecret-markerの修正は 0.3.85/1.3.3 で適用されました。信頼できないmanifestには、最新リリースを使用し、`allowed_objects` をメッセージクラスまたは明示的な安全リストに限定して、`secrets_from_env=False` を指定してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup> [agent trust-boundary mapping](AI-Agent-Security-Methodology.md)では、これを[model-file loading RCE](AI-Models-RCE.md)とは別のものとして扱ってください。

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPTは、対応する言語モデルの事前学習、fine-tuning、評価、デプロイに向けた、読みやすい実装とコマンドラインのワークフローを提供します。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**説明:**\
LitServeはLightning AIのモデルサービングフレームワークで、batching、streaming、高速化、スケーリング用のフックを備えた推論APIを公開できます。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotlは、YAML設定で動作するオープンソースのpost-trainingおよびfine-tuningフレームワークです。full fine-tuning、LoRA/QLoRA、preference optimization、multi-GPU trainingなどの手法に対応しています。クラウドデプロイプラットフォームそのものではありません。<sup>[[5]](#references)</sup>

## オンラインでモデルを試す

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**は、特に自然言語処理（NLP）分野で知られる、機械学習の主要なプラットフォーム兼コミュニティです。機械学習モデルの開発、共有、デプロイを容易にするツール、ライブラリ、リソースを提供しています。\
Hubには、次のような関連セクションがあります。<sup>[[6]](#references)</sup>

* **Models**: **学習済み機械学習モデル**の大規模なリポジトリです。ユーザーは、テキスト生成、翻訳、画像認識など、さまざまなタスク向けのモデルを閲覧、ダウンロード、統合できます。
* **Datasets:** モデルの学習や評価に使われる**データセットの包括的なコレクション**です。多様なデータソースに簡単にアクセスできるため、各自の機械学習プロジェクトに合ったデータを見つけて利用できます。
* **Spaces:** **インタラクティブな機械学習アプリケーション**やデモをホストして共有するためのプラットフォームです。開発者はモデルの動作を**紹介**し、使いやすいインターフェースを作成して、ライブデモを共有することで他のユーザーと共同作業できます。

#### 公開Spaceの実行時ログを調査する

公開Spaceのリポジトリコードから、アプリがどの入力や環境変数をログに記録するかが分かる場合があります。許可を得た調査では、アプリのUIとは別の調査対象として、**run**ログのストリームを確認してください。Hugging FaceはSpaceのログ用SSEエンドポイントをドキュメント化しています。調査によると、公開Spaceのログは他のHubユーザーから読み取れる場合があり、APIキー、ユーザープロンプト、リクエストURLに記録されたDev Modeアクセストークンが含まれていることもありました。ログ内のトークンが問題となるのは、対応する特権モードが引き続き有効で、トークンもまだ有効な場合に限られます。<sup>[[13]](#references)[[14]](#references)</sup>

```bash
SPACE='owner/space-name'
curl -NsS -H "Authorization: Bearer $HF_TOKEN" \
  "https://huggingface.co/api/spaces/$SPACE/logs/run?tail=100"
```

認証済みのHubアカウントのtokenを使用してください。これはSpace所有者のsecretを求めるものではありません。レスポンスはSSEストリーム（`data:`行）です。公開された値は、変数名だけで値がleakしたと判断せず、Spaceのコードと現在のruntimeに照らして確認してください。[self-hosted Gradioまたはmodel-runner endpoint](AI-Exposed-Self-Hosted-AI-Services.md)の場合は、代わりにそちらのページを参照してください。<sup>[[13]](#references)[[14]](#references)</sup>

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **と** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**は、再利用可能な学習済みモデルコンポーネントのリポジトリおよびライブラリであり、特にTensorFlow/Keras経由で利用するモジュールを扱います。**Kaggle**は、ノートブック、データセット、コンペティション、モデルを別途提供しています。<sup>[[7]](#references)[[9]](#references)</sup>

* **モジュール:** 事前学習済みモデルやモデルコンポーネントを幅広く集めたもので、ユーザーは画像分類、テキスト埋め込みなどのタスク向けモジュールを閲覧、ダウンロード、統合できます。
* **チュートリアル:** TensorFlow Hubを使ってモデルを実装、fine-tuneするための手順や例を紹介します。
* **ドキュメント:** 開発者がリポジトリのリソースを効果的に活用するための包括的なガイドやAPIリファレンスを提供します。

## [**Replicate**](https://replicate.com/home)

**Replicate**は、WebインターフェースまたはAPIを通じてパッケージ化された機械学習モデルを実行するホスト型プラットフォームです。<sup>[[8]](#references)</sup>

* **モデル:** コミュニティから提供された機械学習モデルのリポジトリです。ユーザーはモデルを閲覧、試用し、最小限の手間でアプリケーションに統合できます。
* **APIアクセス:** 基盤となる推論インフラストラクチャを運用せずに、アプリケーションからモデルを呼び出すためのAPIを提供します。

## 公開されたself-hosted AIサービスへの攻撃

self-hosted model runner、agent builder、MLデモUI、compute cluster、vector databaseのブラックボックスfingerprintingやテストについては、[公開されたSelf-Hosted AIサービス](AI-Exposed-Self-Hosted-AI-Services.md)を参照してください。



## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hubドキュメント](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicateドキュメント](https://replicate.com/docs)
- [9] [Kaggleドキュメント](https://www.kaggle.com/docs)
- [10] [LangChainのシリアライゼーションインジェクションに関する勧告](https://github.com/langchain-ai/langchain/security/advisories/GHSA-c67j-w6g6-q2cm)
- [11] [LangChainの安全でないオブジェクト復元に関する勧告](https://github.com/langchain-ai/langchain/security/advisories/GHSA-pjwx-r37v-7724)
- [12] [LangChainのload APIと脅威モデル](https://github.com/langchain-ai/langchain/blob/master/libs/core/langchain_core/load/load.py)
- [13] [Hugging Face SpacesのログAPI](https://huggingface.co/docs/hub/main/en/spaces-gpus#streaming-logs-events-and-metrics)
- [14] [Your Space is My Zone: モデルハブ上のAIアプリにおけるセキュリティリスク](https://arxiv.org/abs/2606.30373)
{{#include ../banners/hacktricks-training.md}}
