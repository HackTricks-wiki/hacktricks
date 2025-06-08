# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主な機械学習アルゴリズム

AIについて学ぶための最良の出発点は、主な機械学習アルゴリズムがどのように機能するかを理解することです。これにより、AIがどのように機能し、どのように使用し、どのように攻撃するかを理解するのに役立ちます：

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

### LLMsアーキテクチャ

次のページでは、トランスフォーマーを使用して基本的なLLMを構築するための各コンポーネントの基本を見つけることができます：

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AIセキュリティ

### AIリスクフレームワーク

現在、AIシステムのリスクを評価するための主な2つのフレームワークは、OWASP ML Top 10とGoogle SAIFです：

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AIプロンプトのセキュリティ

LLMsは、近年AIの使用を爆発的に増加させましたが、完璧ではなく、敵対的なプロンプトによって騙される可能性があります。これは、AIを安全に使用し、どのように攻撃するかを理解するために非常に重要なトピックです：

{{#ref}}
AI-Prompts.md
{{#endref}}

### AIモデルのRCE

開発者や企業がインターネットからダウンロードしたモデルを実行することは非常に一般的ですが、モデルを読み込むだけでシステム上で任意のコードを実行するのに十分な場合があります。これは、AIを安全に使用し、どのように攻撃するかを理解するために非常に重要なトピックです：

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AIモデルコンテキストプロトコル

MCP（モデルコンテキストプロトコル）は、AIエージェントクライアントが外部ツールやデータソースにプラグアンドプレイ方式で接続できるプロトコルです。これにより、AIモデルと外部システム間の複雑なワークフローや相互作用が可能になります：

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
