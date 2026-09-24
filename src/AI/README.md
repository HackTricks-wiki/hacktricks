# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 的最佳起点是了解主要机器学习算法的工作原理。这将帮助你理解 AI 的工作方式、如何使用 AI 以及如何攻击 AI：


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

在以下页面中，你将了解使用 transformers 构建基础 LLM 所需的各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI 安全

### AI 风险框架

用于评估 AI 系统风险的两个实用起点框架是 OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF)。它们相互补充，而不是一份详尽的 AI 风险框架清单。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompt 安全

LLM 让 AI 在近几年得到大规模应用，但它们并不完美，可能会受到对抗性 prompt 的诱导。这是理解如何安全使用 AI 以及如何攻击 AI 的重要主题：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

开发者和公司从 Internet 下载并运行模型是非常常见的，但仅加载模型就可能足以在系统上执行任意代码。这是理解如何安全使用 AI 以及如何攻击 AI 的重要主题：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 辅助 KYC 绕过

生成式视频可以与虚拟摄像头注入和摄像头 API 操作结合，用于绕过安全性较弱的 KYC、年龄验证和生物特征活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能暴露数据和操作，评估必须包括授权、同意、工具输入验证以及信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 辅助 Fuzzing 与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助逆向工程

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bots

由 LLM 驱动的 agents 可以自动化执行长时间运行的黑盒 Web pentesting 工作流，但前提是具备可观测性、编排能力、已认证会话处理和对抗性验证：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
