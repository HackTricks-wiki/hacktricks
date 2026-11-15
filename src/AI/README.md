# 网络安全中的 AI

{{#include ../banners/hacktricks-training.md}}

## 主要机器学习算法

了解 AI 的最佳起点是掌握主要机器学习算法的工作原理。这有助于你了解 AI 如何工作、如何使用它以及如何攻击它：


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

### 模型数据准备与评估

有关数据集划分、经典指标以及针对基于 LLM 的评分的答案侧攻击，请参阅[模型数据准备与评估](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)。

### LLM 架构

在以下页面中，你将了解使用 transformers 构建基础 LLM 时各个组件的基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 模型工具与平台

如需运行、微调、部署或试用模型，请使用 [AI 模型工具与平台指南](AI-Model-Tools-and-Platforms.md)。

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

评估 AI 系统风险时，有两个实用的入门框架：OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF)。它们相辅相成，但并非 AI 风险框架的完整清单。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 由 Mechanistic Interpretability 指导的对抗性攻击

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### 嵌入式浏览器信任边界

有关桌面助手的浏览器桥接、标签页地址欺骗以及 worker 上下文中的本地文件读取，请参阅 [AI 助手嵌入式浏览器信任边界](AI-Embedded-Browser-Trust-Boundaries.md)。

### AI Prompt 安全

近年来，LLM 推动 AI 的应用迅速普及，但它们并不完美，可能会被对抗性 prompt 欺骗。了解这一主题对于安全地使用和攻击 AI 非常重要：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 模型 RCE

开发者和公司从 Internet 下载模型并运行的情况很常见，但仅加载模型就可能足以在系统上执行任意代码。了解这一主题对于安全地使用和攻击 AI 非常重要：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 辅助 KYC 绕过

生成式视频可以结合虚拟摄像头注入和摄像头 API 操纵，绕过安全性较弱的 KYC、年龄验证和生物特征活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能会暴露数据和操作，评估时必须涵盖授权、用户同意、工具输入验证和信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) 协议

A2A 允许 agent 通过 agent card 发现彼此，并通过 HTTP 相互发送任务。测试 agent card、任务授权、推送通知 webhook 和扩展卡片：

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 暴露的自托管 AI 服务

对未启用身份验证的暴露模型运行器、agent 构建器、ML 演示 UI、计算集群和向量数据库进行指纹识别与测试：

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI 辅助模糊测试与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助源码审查与漏洞验证

有关 source/sink 审查、移动端入口 taskflow、内核模式审计以及基于证据的验证，请参阅：

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 辅助逆向工程

[部分提升、invariant MBA 检测、环境绑定解码和自动化提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bot

在可观测性、编排、已认证会话处理和对抗性验证的支持下，由 LLM 驱动的 agent 可以自动执行长时间运行的黑盒 Web pentesting 工作流：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
