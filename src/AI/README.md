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

データセットの分割、従来の評価指標、LLMベースの採点に対する回答側からの攻撃については、[モデルデータの準備と評価](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)を参照してください。

### LLMのアーキテクチャ

次のページでは、transformersを使って基本的なLLMを構築するために必要な各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、または試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AIセキュリティ

### LLM Gatewayの信頼境界

Gatewayのセキュリティについては、次を参照してください。

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agentセキュリティの手法

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価を始めるうえで役立つフレームワークとして、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)があります。これらは相互に補完するものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretabilityに基づくAdversarial Attacks

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

ここ数年でLLMの普及によりAIの利用は急増しましたが、完璧ではなく、adversarial promptsによって騙される可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、これは非常に重要なテーマです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行することはよくあります。しかし、モデルをロードするだけでシステム上で任意のコードが実行される可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、これは非常に重要なテーマです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画は、仮想カメラの注入やカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス確認ワークフローをバイパスできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作を公開できるため、評価では認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2Aでは、agent cardを通じてagent同士が互いを検出し、HTTP経由でタスクを送信できます。agent card、タスクの認可、push-notification webhook、拡張カードをテストしてください。

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 外部公開されたセルフホストAIサービス

認証なしで稼働する、外部公開されたモデルランナー、agent builder、MLデモUI、コンピュートクラスター、vector databaseのフィンガープリントとテストについて説明します。

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AIを利用したFuzzingと自動脆弱性発見


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したソースコードレビューと脆弱性検証

ソースとsinkのレビュー、モバイルのエントリーポイントに関するtaskflow、kernelパターンの監査、証拠に基づく検証については、次を参照してください。

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なlifting、不変条件に基づくMBA検出、環境依存のデコード、自動extractorの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bot

LLMを活用したagentは、可観測性、オーケストレーション、認証済みセッションの処理、adversarial validationに対応している場合、長時間にわたるblack-box web pentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
