# サイバーセキュリティにおける AI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIを学ぶには、まず主要な機械学習アルゴリズムの仕組みを理解するのが最適です。これにより、AIの仕組みや使い方、攻撃方法を理解しやすくなります。


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

以下のページでは、transformersを使って基本的なLLMを構築するために必要な各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AIセキュリティ

### AI Agent Security Methodology

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価を始める際に役立つフレームワークとして、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)があります。これらは相互に補完するものであり、AIリスクフレームワークを網羅するものではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### メカニスティック解釈可能性に基づく敵対的攻撃

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

LLMの登場により、ここ数年でAIの利用が急速に拡大しました。しかし、LLMは完璧ではなく、敵対的プロンプトによって欺かれることがあります。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行するのはよくあることですが、モデルを読み込むだけでシステム上で任意のコードが実行される可能性があります。AIを安全に使う方法や攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画は、仮想カメラのインジェクションやカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス判定をバイパスできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作を公開できるため、評価では認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AIを利用したファジングと脆弱性の自動検出


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[部分的なリフティング、不変条件に基づくMBA検出、環境依存のデコード、自動抽出ツールの検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### WebブラックボックスAI Pentester Bot

LLMを活用したエージェントは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的検証を備えることで、長時間にわたるWebブラックボックスpentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 概要](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
