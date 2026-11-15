# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIについて学ぶには、まず主要な機械学習アルゴリズムの仕組みを理解するのが最適です。これにより、AIの仕組みや使い方、攻撃方法を理解しやすくなります。


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### モデルデータの準備と評価

データセットの分割、従来の評価指標、LLMベースの採点に対する回答側からの攻撃については、[モデルデータの準備と評価](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)を参照してください。

### LLMのアーキテクチャ

次のページでは、transformersを使って基本的なLLMを構築するために必要な各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AIセキュリティ

### LLM Gatewayの信頼境界

Gatewayのセキュリティについては、次を参照してください。

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agentセキュリティの方法論

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価に役立つ出発点として、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework（SAIF）があります。これらは相互に補完し合うものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 機械論的解釈可能性に基づく敵対的攻撃

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### 組み込みブラウザーの信頼境界

デスクトップアシスタントのブラウザーブリッジ、タブアドレスの偽装、ワーカーコンテキストからのローカルファイル読み取りについては、[AIアシスタントの組み込みブラウザーにおける信頼境界](AI-Embedded-Browser-Trust-Boundaries.md)を参照してください。

### AIプロンプトのセキュリティ

近年、LLMによってAIの利用は急速に広がりましたが、完璧ではなく、敵対的なプロンプトで欺くことができます。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

インターネットからダウンロードしたモデルを実行する開発者や企業は少なくありません。しかし、モデルを読み込むだけでシステム上で任意のコードが実行される可能性があります。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画は、仮想カメラの注入やカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス確認を回避できます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP（Model Context Protocol）は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作を公開する場合があるため、評価では認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent間（A2A）プロトコル

A2Aでは、AgentがAgent Cardを通じて互いを検出し、HTTP経由でタスクを送信できます。Agent Card、タスクの認可、プッシュ通知Webhook、拡張カードをテストしてください。

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 外部公開されたセルフホストAIサービス

認証なしで稼働している、外部公開されたモデルランナー、Agentビルダー、MLデモUI、コンピューティングクラスター、ベクトルデータベースのフィンガープリントとテストについて説明します。

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AIを活用したFuzzingと脆弱性の自動検出


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを活用したソースコードレビューと脆弱性の検証

ソースとシンクのレビュー、モバイルのエントリーポイントのタスクフロー、カーネルパターンの監査、証拠に基づく検証については、次を参照してください。

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを活用したリバースエンジニアリング

[部分的なリフティング、不変条件に基づくMBA検出、環境依存のデコード、自動抽出ツールの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLMを活用したAgentは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的な検証によって支援される場合、長時間にわたるブラックボックスWeb pentestingワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — はじめに](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
