# AI在网络安全中的应用

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习AI的最佳起点是理解主要机器学习算法的工作原理。这将帮助你理解AI是如何工作的，如何使用它以及如何攻击它：

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

### LLM架构

在以下页面中，你将找到构建基本LLM所需的每个组件的基础知识，使用transformers：

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI安全

### AI风险框架

目前，评估AI系统风险的主要两个框架是OWASP ML Top 10和Google SAIF：

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI提示安全

LLMs在过去几年中使AI的使用激增，但它们并不完美，可能会被对抗性提示欺骗。这是一个非常重要的话题，理解如何安全地使用AI以及如何攻击它：

{{#ref}}
AI-Prompts.md
{{#endref}}

### AI模型RCE

开发人员和公司从互联网下载模型是非常常见的，然而，仅仅加载一个模型可能就足以在系统上执行任意代码。这是一个非常重要的话题，理解如何安全地使用AI以及如何攻击它：

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI模型上下文协议

MCP（模型上下文协议）是一种协议，允许AI代理客户端以即插即用的方式连接外部工具和数据源。这使得AI模型与外部系统之间的复杂工作流程和交互成为可能：

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
