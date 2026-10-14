# AI Model Tools and Platforms

{{#include ../banners/hacktricks-training.md}}

## ローカルでモデルを実行・学習する

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformersは、テキスト、ビジョン、音声、動画、マルチモーダルのタスク向けに、事前学習済みモデルの読み込み、学習、提供を行うオープンソースライブラリです。モデルとデータセットのホスティングは、別途Hugging Face Hubが提供しています。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChainは、プロンプトの構築、会話履歴や状態の管理、ツール、検索、モデル、API、データベースとの統合機能を備えた、モデル駆動型アプリケーションやエージェントを構築するためのフレームワークです。<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPTは、対応する言語モデルの事前学習、ファインチューニング、評価、デプロイに使える、読みやすい実装とコマンドラインのワークフローを提供します。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**説明:**\
LitServeはLightning AIのモデルサービングフレームワークで、バッチ処理、ストリーミング、高速化、スケーリング用のフックを備えた推論APIを公開できます。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotlは、YAML設定で制御するオープンソースのポストトレーニングおよびファインチューニング用フレームワークです。フルファインチューニング、LoRA/QLoRA、選好最適化、マルチGPU学習などの手法をサポートしますが、それ自体はクラウドデプロイプラットフォームではありません。<sup>[[5]](#references)</sup>

## オンラインでモデルを試す

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**は、機械学習における主要なプラットフォームおよびコミュニティであり、特に自然言語処理（NLP）への取り組みで知られています。機械学習モデルの開発、共有、デプロイを容易にするツール、ライブラリ、リソースを提供しています。\
Hubには、関連するセクションがいくつかあります。<sup>[[6]](#references)</sup>

* **Models**: **事前学習済み機械学習モデル**の大規模なリポジトリです。テキスト生成、翻訳、画像認識など、さまざまなタスク向けのモデルを閲覧、ダウンロード、統合できます。
* **Datasets:** モデルの学習や評価に使用する**データセットの包括的なコレクション**です。多様なデータソースに簡単にアクセスできるため、ユーザーは各自の機械学習プロジェクトに適したデータを見つけて活用できます。
* **Spaces:** **インタラクティブな機械学習アプリケーション**やデモをホスティングし、共有するためのプラットフォームです。開発者はモデルの動作を**紹介**し、使いやすいインターフェースを作成して、ライブデモの共有を通じて他のユーザーと協力できます。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **と** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**は、再利用可能な学習済みモデルコンポーネントのリポジトリ兼ライブラリであり、特にTensorFlow/Keras経由で利用するモジュールを提供します。**Kaggle**は、ノートブック、データセット、コンペティション、モデルを別途提供しています。<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** 事前学習済みモデルおよびモデルコンポーネントの大規模なコレクションです。画像分類やテキスト埋め込みなどのタスク向けモジュールを閲覧、ダウンロード、統合できます。
* **Tutorials:** TensorFlow Hubを使用したモデルの実装やファインチューニングを支援する、段階的なガイドや例です。
* **Documentation:** 開発者がリポジトリのリソースを効果的に活用するための包括的なガイドとAPIリファレンスです。

## [**Replicate**](https://replicate.com/home)

**Replicate**は、パッケージ化された機械学習モデルをウェブインターフェースまたはAPI経由で実行するためのホスト型プラットフォームです。<sup>[[8]](#references)</sup>

* **Models:** コミュニティが提供する機械学習モデルのリポジトリです。モデルを閲覧、試用し、最小限の手間でアプリケーションに統合できます。
* **API access:** 基盤となる推論インフラストラクチャを運用せずに、アプリケーションからモデルを呼び出すためのAPIです。

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hub ドキュメント](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicate ドキュメント](https://replicate.com/docs)
- [9] [Kaggle ドキュメント](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
