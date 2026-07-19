# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要 Machine Learning 算法

学习 AI 的最佳起点是了解主要 Machine Learning 算法的工作原理。这将帮助你理解 AI 的工作方式、如何使用 AI 以及如何攻击 AI：


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

### LLM 架构

在以下页面中，你将找到使用 transformers 构建基础 LLM 所需的各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

目前，用于评估 AI 系统风险的两个主要框架是 OWASP ML Top 10 和 Google SAIF：


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLM 让 AI 在过去几年中的使用量大幅增加，但它们并不完美，可能会被 adversarial prompts 欺骗。这是理解如何安全使用 AI 以及如何攻击 AI 的重要主题：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

开发者和公司运行从 Internet 下载的模型非常普遍，然而，仅加载模型就可能足以在系统上执行 arbitrary code。这是理解如何安全使用 AI 以及如何攻击 AI 的重要主题：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video 可以与 virtual-camera injection 和 camera API manipulation 结合使用，以绕过防护较弱的 KYC、年龄验证和 biometric liveness 流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP（Model Context Protocol）是一种允许 AI agent 客户端以 plug-and-play 方式连接外部工具和数据源的协议。这使 AI 模型与外部系统之间能够进行复杂的工作流和交互：


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

由 LLM 驱动的 agents 可以自动化长期运行的 black-box Web pentesting 工作流，但前提是这些工作流具备 observability、orchestration、authenticated session handling 和 adversarial validation 支持：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
