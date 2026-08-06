# LLMsをテストする

{{#include ../banners/hacktricks-training.md}}

## モデルをローカルで実行・trainingする

### [**Hugging Face Transformers**](https://github.com/huggingface/transformers)

Hugging Face Transformersは、GPT、BERTなどのLLMを使用、training、deployするための、最も人気のあるopen-sourceライブラリの1つです。pre-trained models、datasets、fine-tuningやdeploymentのためのHugging Face Hubとのシームレスな統合を含む、包括的なecosystemを提供します。

### [**LangChain**](https://github.com/langchain-ai/langchain)

LangChainは、LLMを使用したapplication構築用に設計されたframeworkです。developerは、language modelを外部のdata source、API、databaseに接続できます。LangChainは、高度なprompt engineering、conversation historyの管理、複雑なworkflowへのLLMの統合のためのtoolsを提供します。

### [**LitGPT**](https://github.com/Lightning-AI/litgpt)

LitGPTはLightning AIが開発したprojectで、Lightning frameworkを活用し、GPT-based modelのtraining、fine-tuning、deploymentを容易にします。他のLightning AI toolsとシームレスに統合され、performanceとscalabilityを向上させながら、大規模language modelを扱うための最適化されたworkflowを提供します。

### [**LitServe**](https://github.com/Lightning-AI/LitServe)

**Description:**\
LitServeはLightning AIのdeployment toolで、AI modelを迅速かつ効率的にdeployするために設計されています。scalableかつ最適化されたserving機能を提供することで、LLMをreal-time applicationに統合する作業を簡素化します。

### [**Axolotl**](https://github.com/axolotl-ai-cloud/axolotl)

Axolotlは、LLMを含むAI modelのdeployment、scaling、管理を効率化するために設計されたcloud-based platformです。automated scaling、monitoring、さまざまなcloud serviceとの統合などの機能を提供し、大規模なinfrastructure管理を必要とせずにproduction環境へmodelをdeployしやすくします。

## オンラインでモデルを試す

### [**Hugging Face**](https://huggingface.co/)

**Hugging Face**は、特にnatural language processing (NLP)分野で知られる、machine learning向けの主要なplatformおよびcommunityです。machine learning modelの開発、共有、deployを容易にするtools、library、resourceを提供します。\
以下のような複数のsectionがあります。

* **Models**: **pre-trained machine learning model**の膨大なrepositoryで、text generation、translation、image recognitionなど、さまざまなtask向けのmodelをbrowse、download、統合できます。
* **Datasets:** modelのtrainingと評価に使用される**datasetの包括的なcollection**です。多様なdata sourceへ簡単にaccessでき、各自のmachine learning projectに適したdataを見つけて利用できます。
* **Spaces:** **interactive machine learning application**やdemoをhostおよび共有するためのplatformです。developerはmodelの動作を**showcase**し、user-friendlyなinterfaceを作成し、live demoを共有して他者とcollaborateできます。

## [**TensorFlow Hub**](https://www.tensorflow.org/hub) **&** [**Kaggle**](https://www.kaggle.com/)

**TensorFlow Hub**は、Googleが開発した再利用可能なmachine learning moduleの包括的なrepositoryです。machine learning model、特にTensorFlowで構築されたmodelの共有とdeploymentを容易にすることに重点を置いています。

* **Modules:** pre-trained modelとmodel componentの膨大なcollectionで、image classification、text embeddingなどのtask向けにmoduleをbrowse、download、統合できます。
* **Tutorials:** TensorFlow Hubを使用してmodelを実装およびfine-tuningする方法を理解するための、step-by-step guideとexampleです。
* **Documentation:** repositoryのresourceを効果的に利用するための、包括的なguideとAPI referenceです。

## [**Replicate**](https://replicate.com/home)

**Replicate**は、developerがシンプルなAPI経由でcloud上のmachine learning modelを実行できるplatformです。大規模なinfrastructure setupを必要とせず、ML modelへ簡単にaccessしてdeployできるようにすることに重点を置いています。

* **Models:** communityから提供されたmachine learning modelのrepositoryで、modelをbrowse、試用し、最小限の労力でapplicationに統合できます。
* **API Access:** developerが各自のapplication内でmodelを容易にdeployおよびscaleできる、シンプルなAPIです。

{{#include ../banners/hacktricks-training.md}}
