# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 的最佳起点是了解主要机器学习算法的工作原理。这将帮助你理解 AI 的工作方式、如何使用 AI，以及如何攻击 AI：


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

在下面的页面中，你将了解使用 transformers 构建基础 LLM 所需的各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI 安全

### AI 风险框架

目前，用于评估 AI 系统风险的两个主要框架是 OWASP ML Top 10 和 Google SAIF：


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts 安全

近年来，LLM 推动了 AI 的爆发式应用，但它们并不完美，可能会被对抗性 prompts 欺骗。这是一个非常重要的主题，有助于理解如何安全地使用 AI 以及如何攻击 AI：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

开发者和公司运行从 Internet 下载的 models 是非常常见的，然而，仅加载一个 model 就可能足以在系统上执行任意代码。这是一个非常重要的主题，有助于理解如何安全地使用 AI 以及如何攻击 AI：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种协议，允许 AI agent 客户端以即插即用的方式连接外部工具和数据源。这使 AI models 与外部系统之间能够实现复杂的工作流和交互：


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

由 LLM 驱动的 agents 可以自动化执行长时间运行的 black-box Web pentesting 工作流，前提是它们具备 observability、orchestration、authenticated session handling 和 adversarial validation 支持：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
