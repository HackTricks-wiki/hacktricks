# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 的最佳起点是了解主要机器学习算法的工作原理。这有助于你理解 AI 的工作方式、如何使用 AI，以及如何攻击 AI：


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

以下页面介绍了使用 transformers 构建基础 LLM 所需的各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 模型工具和平台

如需运行、微调、提供服务或试用模型，请参阅 [AI 模型工具和平台指南](AI-Model-Tools-and-Platforms.md)。

## AI 安全

### AI Agent 安全方法论

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 风险框架

评估 AI 系统风险时，OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF) 是两个实用的入门框架。它们相辅相成，但并未涵盖所有 AI 风险框架。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 由 Mechanistic Interpretability 指导的对抗性攻击

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI 提示词安全

近年来，LLM 的出现极大推动了 AI 的应用，但它们并不完美，可能会被对抗性提示词欺骗。理解这一主题对于安全使用 AI 和攻击 AI 都非常重要：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 模型 RCE

开发者和公司经常运行从 Internet 下载的模型，但仅仅加载模型就可能足以在系统上执行任意代码。理解这一主题对于安全使用 AI 和攻击 AI 都非常重要：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### 借助 AI 绕过 KYC

生成式视频可以与虚拟摄像头注入和摄像头 API 操纵结合使用，以绕过安全性较弱的 KYC、年龄验证和生物识别活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI 模型上下文协议

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能会开放数据和操作权限，评估时必须审查授权、同意、工具输入验证和信任边界。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 辅助 Fuzzing 与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助逆向工程

[部分提升、invariant MBA 检测、环境绑定解码和自动提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bot

由 LLM 驱动的 Agent 可以自动执行长时间运行的 Web 黑盒 pentesting 工作流，前提是具备可观测性、编排能力、经过身份验证的会话处理能力和对抗性验证：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
