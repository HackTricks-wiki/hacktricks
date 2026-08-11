# サイバーセキュリティにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learningアルゴリズム

AIについて学ぶ最適な出発点は、主要なMachine Learningアルゴリズムがどのように機能するかを理解することです。これにより、AIの仕組み、利用方法、攻撃方法を理解するのに役立ちます:


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

以下のページでは、transformersを使用して基本的なLLMを構築するための各コンポーネントの基礎を説明しています:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AIセキュリティ

### AI Risk Frameworks

AIシステムのリスクを評価するための有用な出発点となる2つのframeworksは、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)です。これらは相互に補完するものであり、AIリスクframeworksの網羅的な一覧ではありません。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMにより、ここ数年でAIの利用が爆発的に拡大しました。しかし、LLMは完全ではなく、adversarial promptsによって欺くことができます。これは、AIを安全に利用し、攻撃する方法を理解するうえで非常に重要なトピックです:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

開発者や企業がInternetからダウンロードしたmodelsを実行することは非常に一般的ですが、modelをloadするだけでシステム上で任意のcodeを実行するのに十分な場合があります。これは、AIを安全に利用し、攻撃する方法を理解するうえで非常に重要なトピックです:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative videoは、virtual-camera injectionやcamera API manipulationと組み合わせることで、脆弱なKYC、年齢確認、biometric livenessワークフローをbypassできます:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AIアプリケーションをtoolsやdata sourcesに接続するためのopen protocolです。MCP serversはdataやactionsを公開できるため、assessmentにはauthorization、consent、tool-input validation、trust-boundary reviewを含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agentsは、observability、orchestration、authenticated session handling、adversarial validationによって支援される場合、長時間にわたるblack-box web pentestingワークフローを自動化できます:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
