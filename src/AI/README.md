# CybersecurityにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learning Algorithms

AIについて学ぶ最良の出発点は、主なMachine Learning Algorithmsがどのように動作するかを理解することです。これにより、AIの仕組み、AIの使用方法、そしてAIへの攻撃方法を理解できます。


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

### LLMsのアーキテクチャ

以下のページでは、transformersを使用して基本的なLLMを構築するための各コンポーネントの基礎を説明しています。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

AIシステムのリスクを評価するための有用な出発点となるframeworksは、OWASP Machine Learning Security Top 10とGoogleのSecure AI Framework (SAIF)の2つです。これらはAI risk frameworksの網羅的な一覧ではなく、相互に補完するものです。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMsにより、ここ数年でAIの利用が急速に広がりました。しかし、LLMsは完全ではなく、adversarial promptsによってだますことができます。AIを安全に使用する方法と、AIへの攻撃方法を理解するうえで、これは非常に重要なトピックです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

開発者や企業がInternetからダウンロードしたmodelsを実行することは非常に一般的です。しかし、modelをロードするだけで、システム上でarbitrary codeを実行するのに十分な場合があります。AIを安全に使用する方法と、AIへの攻撃方法を理解するうえで、これは非常に重要なトピックです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative videoは、virtual-camera injectionおよびcamera API manipulationと組み合わせることで、脆弱なKYC、年齢確認、biometric liveness workflowをbypassできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AI applicationsをtoolsやdata sourcesに接続するためのopen protocolです。MCP serversはdataやactionsを公開できるため、評価にはauthorization、consent、tool-input validation、trust-boundary reviewを含める必要があります。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-Assisted Reverse Engineering

[Partial lifting、invariant MBA detection、environment-bound decoding、automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-powered agentsは、observability、orchestration、authenticated session handling、adversarial validationによって支援されることで、長時間にわたるblack-box web pentesting workflowを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
