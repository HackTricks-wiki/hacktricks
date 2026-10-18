# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

学习 AI 的最佳起点，是了解主要机器学习算法的工作原理。这有助于你理解 AI 如何工作、如何使用它以及如何攻击它：


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

## 模型工具和平台

如需运行、微调、托管或试用模型，请参阅 [AI 模型工具和平台指南](AI-Model-Tools-and-Platforms.md)。

## AI 安全

### AI Agent 安全方法论

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 风险框架

OWASP Machine Learning Security Top 10 和 Google Secure AI Framework (SAIF) 是评估 AI 系统风险的两个实用入门框架。两者互为补充，并非 AI 风险框架的完整清单。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 由 Mechanistic Interpretability 指导的对抗性攻击

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI Prompt 安全

近年来，LLM 让 AI 的应用迅速普及，但它们并不完美，可能会被对抗性 prompts 欺骗。了解如何安全地使用和攻击 AI，这是一个非常重要的主题：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 模型 RCE

开发者和公司从 Internet 下载模型并运行的情况非常普遍，然而，仅加载模型就可能足以在系统上执行任意代码。了解如何安全地使用和攻击 AI，这是一个非常重要的主题：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### 借助 AI 绕过 KYC

生成式视频可以结合虚拟摄像头注入和摄像头 API 操纵，绕过防护薄弱的 KYC、年龄验证和生物特征活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能会暴露数据和操作，评估时必须涵盖授权、同意、工具输入验证以及信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 辅助 Fuzzing 与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助源码审查与漏洞验证

适用于源码/污点源审查、移动端入口任务流、内核模式审计以及基于证据的验证：

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 辅助逆向工程

[局部提升、invariant MBA 检测、环境绑定解码以及自动化提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bot

在具备可观测性、编排、已认证会话处理和对抗性验证的支持下，由 LLM 驱动的 Agent 可以自动执行长时间运行的黑盒 Web pentesting 工作流：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
