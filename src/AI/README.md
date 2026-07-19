# CybersecurityにおけるAI

{{#include ../banners/hacktricks-training.md}}

## 主なMachine Learning Algorithms

AIについて学ぶ最良の出発点は、主なmachine learning algorithmsの仕組みを理解することです。これにより、AIの仕組み、利用方法、攻撃方法を理解できます。


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

### LLMs Architecture

以下のページでは、transformersを使用して基本的なLLMを構築するための各コンポーネントの基礎を説明します。


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

現在、AI systemsのリスクを評価するための主な2つのframeworksは、OWASP ML Top 10とGoogle SAIFです。


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMsにより、ここ数年でAIの利用は急速に拡大しました。しかし、LLMsは完全ではなく、adversarial promptsによってtrickされる可能性があります。AIを安全に利用する方法と攻撃方法を理解するうえで、これは非常に重要なtopicです。


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

developersやcompaniesがInternetからdownloadしたmodelsを実行することは非常に一般的です。しかし、modelをloadするだけで、system上でarbitrary codeをexecuteするのに十分な場合があります。AIを安全に利用する方法と攻撃方法を理解するうえで、これは非常に重要なtopicです。


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative videoは、virtual-camera injectionおよびcamera API manipulationと組み合わせることで、脆弱なKYC、age-verification、biometric liveness workflowsをbypassできます。


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)は、AI agent clientsがexternal toolsやdata sourcesにplug-and-play方式で接続できるprotocolです。これにより、AI modelsとexternal systemsの間で、複雑なworkflowsやinteractionsが可能になります。


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agentsは、observability、orchestration、authenticated session handling、adversarial validationによってsupportされる場合、長時間実行されるblack-box web pentesting workflowsを自動化できます。


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
