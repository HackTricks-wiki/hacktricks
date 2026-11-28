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

### 模型数据准备与评估

关于数据集拆分、经典指标，以及针对基于 LLM 的评分的答案侧攻击，请参阅[模型数据准备与评估](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)。

### LLM 架构

以下页面介绍了使用 transformers 构建基础 LLM 所需的各组件基础知识：


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 模型工具与平台

如需运行、微调、部署或试用模型，请参阅 [AI 模型工具与平台指南](AI-Model-Tools-and-Platforms.md)。

## AI 安全

### LLM Gateway 信任边界

关于 Gateway 安全，请参阅：

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent 安全方法论

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 风险框架

评估 AI 系统风险时，可以从 OWASP Machine Learning Security Top 10 和 Google 的 Secure AI Framework (SAIF) 这两个框架入手。它们相辅相成，但并未涵盖所有 AI 风险框架。<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 机制可解释性指导的对抗性攻击

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### 嵌入式浏览器信任边界

关于桌面助手的浏览器桥接、标签页地址欺骗，以及在 worker 上下文中读取本地文件，请参阅 [AI 助手嵌入式浏览器信任边界](AI-Embedded-Browser-Trust-Boundaries.md)。

### AI Prompt 安全

过去几年，LLM 让 AI 的使用迅速普及，但它们并不完美，可能被对抗性 prompt 欺骗。了解这一主题对于安全地使用和攻击 AI 都非常重要：


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 模型 RCE

开发者和公司从互联网上下载模型并运行的情况非常普遍，但仅仅加载模型就可能足以在系统上执行任意代码。了解这一主题对于安全地使用和攻击 AI 都非常重要：


{{#ref}}
AI-Models-RCE.md
{{#endref}}

关于 Keras `.keras`/HDF5 模型加载风险、Lambda 层和修复后的 gadget 分析，请参阅 [Keras 模型反序列化与 gadget 搜寻](keras-model-deserialization-rce-and-gadget-hunting.md)。

### AI 辅助 KYC 绕过

生成式视频可以结合虚拟摄像头注入和摄像头 API 操纵，绕过安全性薄弱的 KYC、年龄验证和生物特征活体检测流程：


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) 是一种用于将 AI 应用连接到工具和数据源的开放协议。由于 MCP 服务器可能会暴露数据和操作，因此评估必须涵盖授权、同意、工具输入验证和信任边界审查。<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A 允许 Agent 通过 agent card 发现彼此，并通过 HTTP 相互发送任务。测试 agent card、任务授权、推送通知 webhook 和扩展卡片：

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 暴露在外的自托管 AI 服务

对未启用身份验证的模型运行器、Agent 构建器、ML 演示 UI、计算集群和向量数据库进行指纹识别与测试：

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI 辅助模糊测试与自动化漏洞发现


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 辅助源码审查与漏洞验证

关于 source/sink 审查、移动端入口点任务流、内核模式审计，以及证据门控验证，请参阅：

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 辅助逆向工程

[部分提升、invariant MBA 检测、环境绑定解码，以及自动化提取器验证](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web 黑盒 AI Pentester Bot

在具备可观测性、编排、经过身份验证的会话处理和对抗性验证的支持下，LLM 驱动的 Agent 可以自动执行长期运行的黑盒 Web pentesting 工作流：


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP 机器学习安全十大风险](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 安全 AI 框架 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 简介](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
