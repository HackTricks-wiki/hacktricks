# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIについて学ぶには、まず主な機械学習アルゴリズムの仕組みを理解するのが最適です。AIの仕組みや使い方、攻撃方法を理解するのに役立ちます。


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

以下のページでは、transformersを使って基本的なLLMを構築するための各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、serving、試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AI Security

### LLM Gatewayの信頼境界

Gatewayのセキュリティについては、以下を参照してください。

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent Securityの方法論

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価に役立つ出発点となるフレームワークは、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)です。これらは相互に補完するものであり、AIリスクフレームワークを網羅したリストではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretabilityに基づく敵対的攻撃

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

ここ数年でLLMの普及によりAIの利用が急増しましたが、完璧ではなく、敵対的なプロンプトでだまされる可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行するのはよくあることですが、モデルを読み込むだけでシステム上の任意コードが実行される可能性があります。AIを安全に使い、攻撃する方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画を仮想カメラの注入やカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス判定をバイパスできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作を公開できるため、評価では認可、同意、ツール入力の検証、信頼境界のレビューを含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AIを利用したFuzzingと自動脆弱性発見


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したソースコードレビューと脆弱性検証

source/sinkのレビュー、モバイルのエントリーポイントのタスクフロー、カーネルパターンの監査、証拠に基づく検証については、以下を参照してください。

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なリフティング、不変量に基づくMBA検出、環境依存のデコード、自動抽出ツールの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bot

LLMを活用したエージェントは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的検証によるサポートがあれば、長時間にわたるblack-box web pentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — はじめに](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
