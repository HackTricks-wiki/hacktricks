# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 最好的起点是了解主要机器学习算法的工作原理。这将帮助你理解 AI 的工作方式、如何使用它以及如何攻击它：


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

### LLMs 架构

在以下页面中，你将了解使用 transformers 构建基础 LLM 所需的各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI 安全

### AI Agent 安全方法论

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 风险框架

OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF) 是评估 AI 系统风险的两个实用入门框架。它们相辅相成，并非全面罗列所有 AI 风险框架。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts 安全

近年来，LLMs 的出现极大地推动了 AI 的应用，但它们并不完美，可能会被对抗性 prompts 欺骗。了解这一主题对于安全地使用 AI 以及攻击 AI 都非常重要：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

开发者和公司从互联网下载模型并运行的情况非常普遍，但仅加载模型就可能足以在系统上执行任意代码。了解这一主题对于安全地使用 AI 以及攻击 AI 都非常重要：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 辅助 KYC 绕过

生成式视频可以结合虚拟摄像头注入和摄像头 API 操纵，绕过安全性较弱的 KYC、年龄验证和生物特征活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种开放协议，用于将 AI 应用连接到工具和数据源。由于 MCP servers 可以暴露数据和操作，安全评估必须涵盖授权、用户同意、工具输入验证以及信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 辅助 Fuzzing 与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助逆向工程

[局部提升、invariant MBA 检测、环境绑定解码和自动提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

由 LLM 驱动的 agents 在具备可观测性、编排、经过身份验证的会话处理和对抗性验证的支持时，可以自动执行长时间运行的 Black-Box Web pentesting 工作流：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
