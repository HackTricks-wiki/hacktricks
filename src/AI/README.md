# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 的最佳起点是了解主要机器学习算法的工作原理。这有助于你理解 AI 如何工作、如何使用它以及如何攻击它：


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

以下页面介绍了使用 transformers 构建基础 LLM 所需的各组件基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 模型工具与平台

如需运行、微调、部署或试用模型，请参阅 [AI 模型工具与平台指南](AI-Model-Tools-and-Platforms.md)。

## AI 安全

### LLM Gateway 信任边界

有关 gateway 安全，请参阅：

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent 安全方法论

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 风险框架

评估 AI 系统风险时，两个实用的入门框架是 OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF)。它们相辅相成，但并非详尽涵盖所有 AI 风险框架。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 由机制可解释性指导的对抗性攻击

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI 提示词安全

近年来，LLM 的出现让 AI 的应用迅速普及，但它们并不完美，可能会被对抗性提示词诱骗。这是一个非常重要的主题，有助于理解如何安全地使用 AI 以及如何攻击它：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 模型 RCE

开发者和公司从互联网下载并运行模型的情况非常普遍，但仅加载模型就可能足以在系统上执行任意代码。这是一个非常重要的主题，有助于理解如何安全地使用 AI 以及如何攻击它：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 辅助 KYC 绕过

生成式视频可以与虚拟摄像头注入和摄像头 API 操纵结合使用，以绕过薄弱的 KYC、年龄验证和生物识别活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能会暴露数据和操作，评估必须涵盖授权、同意、工具输入验证和信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A 允许 agent 通过 agent card 发现彼此，并通过 HTTP 相互发送任务。测试 agent card、任务授权、推送通知 webhook 和扩展卡片：

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 暴露在外的自托管 AI 服务

对未启用身份验证的模型运行器、agent 构建器、ML 演示 UI、计算集群和向量数据库进行指纹识别与测试：

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI 辅助模糊测试与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助源代码审查与漏洞验证

用于 source/sink 审查、移动端入口点任务流、内核模式审计和基于证据的验证：

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 辅助逆向工程

[部分提升、Invariant MBA 检测、环境绑定解码和自动化提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bot

由 LLM 驱动的 agent 可以自动执行长时间运行的 Web 黑盒 pentesting 工作流，前提是具备可观测性、编排、经过身份验证的会话处理和对抗性验证：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
