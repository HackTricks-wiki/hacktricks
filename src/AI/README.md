# CybersecurityにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learning Algorithms

AIについて学ぶための最適な出発点は、主要なMachine Learning Algorithmsの仕組みを理解することです。これにより、AIの仕組み、使用方法、攻撃方法を理解できます:


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

### LLMsのArchitecture

以下のページでは、transformersを使用して基本的なLLMを構築するために必要な各コンポーネントの基礎を説明しています:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

現在、AIシステムのリスクを評価するための主要な2つのframeworksは、OWASP ML Top 10とGoogle SAIFです:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMsによって、ここ数年でAIの利用が急速に拡大しました。しかし、LLMsは完璧ではなく、adversarial promptsによってtrickされる可能性があります。AIを安全に使用する方法と、AIを攻撃する方法を理解するうえで、これは非常に重要なトピックです:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

開発者や企業がInternetからdownloadしたmodelsを実行することは非常に一般的です。しかし、modelをloadするだけで、system上でarbitrary codeを実行するのに十分な場合があります。AIを安全に使用する方法と、AIを攻撃する方法を理解するうえで、これは非常に重要なトピックです:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AI agent clientsがexternal toolsやdata sourcesにplug-and-play方式で接続できるprotocolです。これにより、AI modelsとexternal systemsの間で複雑なworkflowsやinteractionsが可能になります:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI支援Fuzzingと自動Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agentsは、observability、orchestration、authenticated session handling、adversarial validationによってサポートされる場合、長時間実行されるblack-box web pentesting workflowsを自動化できます:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
