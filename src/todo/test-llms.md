# LLMをテストする

{{#include ../banners/hacktricks-training.md}}

## モデルをローカルで実行・トレーニングする

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformersは、テキスト、ビジョン、音声、動画、マルチモーダルタスク向けの事前学習済みモデルを読み込み、トレーニングし、提供するためのオープンソースライブラリです。モデルとデータセットのホスティングは、Hugging Face Hubによって別途提供されています。<sup>[[1]](#references)</sup>

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChainは、promptの構築、会話履歴や状態の管理、tools、retrieval、model、API、データベースとの統合に対応した、model-drivenアプリケーションやagentを構築するためのframeworkです。<sup>[[2]](#references)</sup>

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPTは、対応するlanguage modelのpretraining、fine-tuning、評価、deployを行うための、読みやすい実装とcommand-line workflowを提供します。<sup>[[3]](#references)</sup>

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**説明:**\
LitServeはLightning AIのmodel-serving frameworkであり、batching、streaming、acceleration、scaling用のhooksを備えたinference APIを公開します。<sup>[[4]](#references)</sup>

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotlは、YAML設定によって動作するオープンソースのpost-trainingおよびfine-tuning frameworkです。full fine-tuning、LoRA/QLoRA、preference optimization、multi-GPU trainingなどのtechniqueをサポートします。ただし、それ自体はcloud deployment platformではありません。<sup>[[5]](#references)</sup>

## オンラインでモデルを試す

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**は、特に自然言語処理（NLP）分野で知られる、machine learning向けの主要なplatformおよびcommunityです。machine learning modelの開発、共有、deployを容易にするtools、libraries、resourcesを提供しています。\
Hubには、以下の関連セクションがあります。<sup>[[6]](#references)</sup>

* **Models**: **pre-trained machine learning models**の広大なrepositoryで、ユーザーはtext generation、translation、image recognitionなど、さまざまなtask向けのmodelを閲覧、download、統合できます。
* **Datasets:** modelのtrainingとevaluationに使用される**datasetの包括的なcollection**です。多様なdata sourceへ簡単にaccessでき、ユーザーは各自のmachine learning projectに適したdataを見つけて利用できます。
* **Spaces:** **interactive machine learning application**やdemoをhostingおよび共有するためのplatformです。developerはmodelの動作を**showcase**し、user-friendlyなinterfaceを作成し、live demoを共有して他のユーザーとcollaborateできます。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**は、再利用可能なtrained model componentのrepositoryおよびlibraryであり、特にTensorFlow/Keras経由で利用されるmoduleを扱います。**Kaggle**は別途、notebook、dataset、competition、modelを提供します。<sup>[[7]](#references)[[9]](#references)</sup>

* **Modules:** pre-trained modelおよびmodel componentの広大なcollectionで、ユーザーはimage classification、text embeddingなどのtask向けmoduleを閲覧、download、統合できます。
* **Tutorials:** TensorFlow Hubを使用してmodelを実装およびfine-tuningするためのstep-by-step guideとexampleです。
* **Documentation:** developerがrepositoryのresourceを効果的に利用するための包括的なguideとAPI referenceです。

## [**Replicate**](https://replicate.com/home)

**Replicate**は、web interfaceまたはAPIを通じてpackaged machine-learning modelを実行するためのhosted platformです。<sup>[[8]](#references)</sup>

* **Models:** communityから提供されたmachine learning modelのrepositoryで、ユーザーはmodelを閲覧、試用し、最小限の手間でapplicationに統合できます。
* **API access:** underlying inference infrastructureを運用せずに、applicationからmodelを呼び出すためのAPIです。

## References

- [1] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [2] [LangChain](https://github.com/langchain-ai/langchain)
- [3] [LitGPT](https://github.com/Lightning-AI/litgpt)
- [4] [LitServe](https://github.com/Lightning-AI/LitServe)
- [5] [Axolotl](https://github.com/axolotl-ai-cloud/axolotl)
- [6] [Hugging Face Hubのドキュメント](https://huggingface.co/docs/hub/index)
- [7] [TensorFlow Hub](https://www.tensorflow.org/hub)
- [8] [Replicateのドキュメント](https://replicate.com/docs)
- [9] [Kaggleのドキュメント](https://www.kaggle.com/docs)
{{#include ../banners/hacktricks-training.md}}
