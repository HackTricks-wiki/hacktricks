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

以下のページでは、transformersを使って基本的なLLMを構築するための各コンポーネントの基礎を解説します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## モデルのツールとプラットフォーム

モデルの実行、fine-tuning、提供、または試用には、[AIモデルのツールとプラットフォームのガイド](AI-Model-Tools-and-Platforms.md)を参照してください。

## AIセキュリティ

### AIエージェントのセキュリティ手法

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価を始めるうえで役立つフレームワークとして、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)があります。これらは相互に補完するものであり、AIリスクフレームワークを網羅したリストではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### メカニスティック解釈可能性に基づく敵対的攻撃

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AIプロンプトのセキュリティ

近年、LLMによってAIの利用が急速に広がりましたが、LLMは完璧ではなく、敵対的なプロンプトで騙されることがあります。AIを安全に使う方法と攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

インターネットからダウンロードしたモデルを実行する開発者や企業は珍しくありません。しかし、モデルを読み込むだけでシステム上で任意のコードが実行される可能性があります。AIを安全に使う方法と攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを活用したKYC Bypass

生成動画を仮想カメラの注入やカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス確認を回避できます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータやアクションを公開できるため、評価には認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AIを活用したファジングと脆弱性の自動発見


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを活用したリバースエンジニアリング

[部分的なリフティング、不変式に基づくMBA検出、環境依存のデコード、自動抽出器の検証](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### WebブラックボックスAI Pentester Bot

LLMを活用したエージェントは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的検証の仕組みが整っていれば、長時間にわたるWebブラックボックスpentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 機械学習セキュリティトップ10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — セキュアAIフレームワーク (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — はじめに](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
