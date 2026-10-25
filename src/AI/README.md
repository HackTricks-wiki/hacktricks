# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIを学ぶには、まず主な機械学習アルゴリズムの仕組みを理解するのが最適です。AIの仕組みや使い方、攻撃方法を理解するのに役立ちます:


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

### LLMのアーキテクチャ

次のページでは、transformersを使って基本的なLLMを構築するための各コンポーネントの基礎を解説しています:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、試用には、[AI model tools and platforms guide](AI-Model-Tools-and-Platforms.md)を参照してください。

## AIセキュリティ

### LLM Gatewayの信頼境界

Gatewayのセキュリティについては、次を参照してください:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agentセキュリティの方法論

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価を始める際に役立つフレームワークとして、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework（SAIF）があります。これらは相互補完的なものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### メカニスティック解釈可能性に基づく敵対的攻撃

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

ここ数年でLLMの普及によりAIの利用は急増しましたが、LLMは完璧ではなく、敵対的プロンプトで騙される可能性があります。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行するのはよくあることですが、モデルを読み込むだけでシステム上で任意のコードが実行される可能性があります。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画は、仮想カメラのインジェクションやカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス判定をバイパスできます:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP（Model Context Protocol）は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作を公開できるため、評価では認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent間（A2A）プロトコル

A2Aでは、Agentがagent cardを通じて互いを検出し、HTTP経由でタスクを送信できます。agent card、タスクの認可、push通知webhook、拡張カードをテストしてください:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 外部公開されたセルフホスト型AIサービス

認証なしで稼働するモデルランナー、agent builder、MLデモUI、計算クラスター、ベクトルデータベースをフィンガープリントし、テストします:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AIを利用したFuzzingと脆弱性の自動発見


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したソースコードレビューと脆弱性の検証

source/sinkのレビュー、モバイルのエントリーポイントのタスクフロー、カーネルパターンの監査、証拠に基づく検証については、次を参照してください:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なリフティング、不変条件に基づくMBAの検出、環境依存のデコード、自動抽出ツールの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### WebブラックボックスAI Pentester Bot

LLMを活用したAgentは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的検証を備えることで、長時間にわたるブラックボックスWeb pentestingのワークフローを自動化できます:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP機械学習セキュリティTop 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — セキュアAIフレームワーク（SAIF）](https://saif.google/)
- [3] [Model Context Protocol — はじめに](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
