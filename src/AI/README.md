# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIについて学ぶには、まず主な機械学習アルゴリズムの仕組みを理解するのが最適です。これにより、AIの仕組みや使い方、攻撃方法を理解しやすくなります。


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

以下のページでは、transformersを使用して基本的なLLMを構築するために必要な各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AIセキュリティ

### AI Agentセキュリティの方法論

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価に役立つ出発点となるフレームワークは、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)です。これらは相互に補完するものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretabilityに基づくAdversarial Attack

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

ここ数年でLLMの普及によりAIの利用が急増しましたが、LLMは完璧ではなく、adversarial promptによってだまされる可能性があります。これは、AIを安全に使う方法や攻撃方法を理解するうえで非常に重要なテーマです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行することはよくあります。しかし、モデルを読み込むだけでシステム上で任意のコードが実行される可能性があります。これは、AIを安全に使う方法や攻撃方法を理解するうえで非常に重要なテーマです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画に仮想カメラのインジェクションやカメラAPIの操作を組み合わせることで、脆弱なKYC、年齢確認、生体認証のlivenessチェックを回避できます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作へのアクセスを提供できるため、評価には認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AIを利用したFuzzingと脆弱性の自動発見


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したソースコードレビューと脆弱性の検証

ソースとsinkのレビュー、モバイルのエントリーポイントのtaskflow、kernelパターンの監査、証拠に基づく検証については、以下を参照してください。

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なlifting、不変量に基づくMBA検出、環境依存のデコード、自動extractorの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bot

LLMを利用したagentは、可観測性、オーケストレーション、認証済みセッションの処理、adversarial validationを備えることで、長時間にわたるblack-box web pentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
