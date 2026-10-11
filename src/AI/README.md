# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learningアルゴリズム

AIについて学ぶには、まず主要なMachine Learningアルゴリズムの仕組みを理解するのが最適です。これにより、AIの仕組みや使い方、攻撃方法を理解しやすくなります。


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

以下のページでは、transformersを使って基本的なLLMを構築するために必要な各コンポーネントの基礎を説明しています。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AIセキュリティ

### AI Agentセキュリティ手法

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AIリスクフレームワーク

AIシステムのリスク評価を始める際に役立つフレームワークとして、OWASP Machine Learning Security Top 10とGoogle's Secure AI Framework (SAIF)があります。これらは相互に補完し合うものであり、AIリスクフレームワークを網羅した一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AIプロンプトセキュリティ

ここ数年でLLMの普及によりAIの利用が急増しましたが、LLMは完璧ではなく、敵対的なプロンプトで欺かれることがあります。AIを安全に使う方法と攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

インターネットからダウンロードしたモデルを実行する開発者や企業は珍しくありません。しかし、モデルを読み込むだけでシステム上の任意コードが実行される可能性があります。AIを安全に使う方法と攻撃方法を理解するうえで、非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIを利用したKYCバイパス

生成動画を仮想カメラへのインジェクションやカメラAPIの操作と組み合わせることで、脆弱なKYC、年齢確認、生体認証のライブネス判定ワークフローをバイパスできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをツールやデータソースに接続するためのオープンプロトコルです。MCPサーバーはデータや操作機能を公開できるため、評価には認可、同意、ツール入力の検証、信頼境界の確認を含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AIを利用したFuzzingと脆弱性の自動検出


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AIを利用したリバースエンジニアリング

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLMを活用したagentは、可観測性、オーケストレーション、認証済みセッションの処理、敵対的検証を備えることで、長時間にわたるWeb black-box pentestingのワークフローを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — セキュアAIフレームワーク (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 概要](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
