# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## ローカルでモデルを実行・トレーニングする

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformersは、テキスト、ビジョン、音声、動画、マルチモーダルの各タスク向けに、事前学習済みモデルの読み込み、トレーニング、提供を行うオープンソースライブラリです。モデルとデータセットのホスティングは、別途Hugging Face Hubが提供します。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChainは、プロンプトの構築、会話履歴や状態の管理、ツール、検索、モデル、API、データベースとの連携機能を備えた、モデル駆動型アプリケーションやエージェントを構築するためのフレームワークです。<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPTは、対応する言語モデルの事前学習、fine-tuning、評価、デプロイを行うための、読みやすい実装とコマンドラインのワークフローを提供します。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**説明:**\
LitServeはLightning AIのモデルサービングフレームワークです。バッチ処理、ストリーミング、高速化、スケーリングのためのフックを備えた推論APIを公開できます。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotlは、YAML設定で動作するオープンソースのpost-trainingおよびfine-tuningフレームワークです。full fine-tuning、LoRA/QLoRA、選好最適化、マルチGPUトレーニングなどの手法に対応しています。クラウドデプロイプラットフォームそのものではありません。<sup>[[5]](#references)</sup>

## オンラインでモデルを試す

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**は、機械学習分野を代表するプラットフォーム兼コミュニティであり、特に自然言語処理（NLP）への取り組みで知られています。機械学習モデルの開発、共有、デプロイを容易にするツール、ライブラリ、リソースを提供しています。\
Hubには、関連する次のセクションがあります。<sup>[[6]](#references)</sup>

* **Models**: さまざまなタスクに対応する**事前学習済み機械学習モデル**の大規模なリポジトリです。テキスト生成、翻訳、画像認識などに使えるモデルを検索、ダウンロードし、統合できます。
* **Datasets:** モデルのトレーニングや評価に使用する**データセットの包括的なコレクション**です。多様なデータソースに簡単にアクセスできるため、機械学習プロジェクトに必要なデータを見つけて利用できます。
* **Spaces:** **インタラクティブな機械学習アプリケーション**やデモをホスト、共有するためのプラットフォームです。開発者はモデルの動作を**紹介**し、使いやすいインターフェースを作成して、ライブデモを共有しながら他のユーザーと共同作業できます。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**は、再利用可能な学習済みモデルコンポーネントのリポジトリ兼ライブラリであり、特にTensorFlow/Keras経由で利用するモジュールを扱います。**Kaggle**は、ノートブック、データセット、コンペティション、モデルを別途提供しています。<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** 画像分類やテキスト埋め込みなどのタスクに利用できる、事前学習済みモデルとモデルコンポーネントの大規模なコレクションです。モジュールを検索、ダウンロードし、統合できます。
* **Tutorials:** TensorFlow Hubを使用してモデルを実装、fine-tuningするための、手順を追ったガイドと例です。
* **Documentation:** リポジトリのリソースを効果的に活用するための、包括的なガイドとAPIリファレンスです。

## [**Replicate**](https://replicate.com/home)

**Replicate**は、WebインターフェースまたはAPIを通じて、パッケージ化された機械学習モデルを実行できるホスト型プラットフォームです。<sup>[[8]](#references)</sup>

* **Models:** コミュニティから提供された機械学習モデルのリポジトリです。モデルを検索、試用でき、最小限の手間でアプリケーションに統合できます。
* **API access:** 基盤となる推論インフラストラクチャを運用せずに、アプリケーションからモデルを呼び出すためのAPIです。

## 公開されたセルフホストAIサービスへの攻撃

セルフホスト型のモデルランナー、エージェントビルダー、MLデモUI、コンピュートクラスター、ベクトルデータベースを対象としたブラックボックスのフィンガープリンティングとテストについては、[公開されたセルフホストAIサービス](AI-Exposed-Self-Hosted-AI-Services.md)を確認してください。

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
{{#include ../banners/hacktricks-training.md}}
