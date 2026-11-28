# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learningアルゴリズム

AIについて学ぶには、まず主なmachine learningアルゴリズムの仕組みを理解するのが最適です。これにより、AIの仕組みや使い方、攻撃方法を理解しやすくなります。


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

データセットの分割、従来のmetrics、LLMベースの採点に対する回答側からの攻撃については、[モデルデータの準備と評価](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)を参照してください。

### LLMのアーキテクチャ

以下のページでは、transformersを使って基本的なLLMを構築するための各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AI Security

### LLM Gatewayの信頼境界

Gatewayのsecurityについては、以下を参照してください。

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Securityの手法

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価に役立つ出発点として、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)があります。これらは相互に補完するものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic-Interpretabilityに基づくAdversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### 埋め込みブラウザーの信頼境界

デスクトップアシスタントのブラウザーブリッジ、タブアドレスのなりすまし、workerコンテキストからのローカルファイル読み取りについては、[AIアシスタントの埋め込みブラウザーの信頼境界](AI-Embedded-Browser-Trust-Boundaries.md)を参照してください。

### AIプロンプトのSecurity

近年、LLMによってAIの利用が急増しましたが、完璧ではなく、敵対的なプロンプトで欺かれる可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、非常に重要なテーマです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

インターネットからダウンロードしたモデルを実行する開発者や企業は珍しくありません。しかし、モデルを読み込むだけでシステム上の任意コードが実行される可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、非常に重要なテーマです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Keras `.keras`/HDF5モデルの読み込みに伴うリスク、Lambda layers、修正後のgadget分析については、[Kerasモデルのデシリアライズとgadget hunting](keras-model-deserialization-rce-and-gadget-hunting.md)を参照してください。

### AIを利用したKYC Bypass

生成動画をvirtual-camera injectionやcamera APIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のliveness確認フローを回避できます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータやアクションを公開する可能性があるため、評価には認可、同意、ツール入力の検証、信頼境界のレビューを含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent間 (A2A) Protocol

A2Aでは、agent cardを通じてagent同士が互いを検出し、HTTP経由でタスクを送信できます。agent card、タスクの認可、push-notification webhook、拡張カードをテストしてください。

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 外部公開されたセルフホストAIサービス

認証なしで稼働するモデルランナー、agent builder、MLデモUI、計算クラスター、ベクトルデータベースをfingerprintingしてテストします。

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AIを利用したFuzzingと自動脆弱性検出


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したソースコードレビューと脆弱性検証

ソース/シンクのレビュー、モバイルのentry pointのtaskflow、kernelパターンの監査、証拠に基づく検証については、以下を参照してください。

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なlifting、不変条件に基づくMBAの検出、環境依存のデコード、自動抽出ツールの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLMを利用したagentは、観測可能性、オーケストレーション、認証済みセッションの処理、敵対的な検証によって支えられていれば、長時間にわたるblack-box Web pentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP 機械学習セキュリティ Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — セキュアAIフレームワーク (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — はじめに](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
