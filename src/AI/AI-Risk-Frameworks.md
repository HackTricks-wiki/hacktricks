# AI 风险

{{#include ../banners/hacktricks-training.md}}

## OWASP 机器学习十大漏洞

Owasp 已识别出可能影响 AI 系统的机器学习十大漏洞。这些漏洞可能导致各种安全问题，包括 data poisoning、model inversion 和 adversarial attacks。理解这些漏洞对于构建安全的 AI 系统至关重要。

有关最新和详细的十大机器学习漏洞列表，请参阅 [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/) 项目。

- **Input Manipulation Attack**: 攻击者对**输入数据**做出微小、通常不可见的修改，使模型做出错误判断。\
*示例*: 在 stop‑sign 上涂几点油漆，会让自驾车“看到”一个 speed‑limit sign。

- **Data Poisoning Attack**: 故意污染**训练集**，加入有害样本以教会模型错误规则。\
*示例*: 在防病毒训练语料中将 malware binaries 错误标注为 "benign"，使得相似的 malware 在后续检测中漏检。

- **Model Inversion Attack**: 通过探测输出，攻击者构建一个**反向模型**来重构原始输入的敏感特征。\
*示例*: 从癌症检测模型的预测中重建患者的 MRI 图像。

- **Membership Inference Attack**: 对手通过观察置信度差异来测试某个**特定记录**是否被用于训练。\
*示例*: 确认某人的银行交易是否出现在一个 fraud‑detection model 的训练数据中。

- **Model Theft**: 反复查询使攻击者学会决策边界并**克隆模型行为**（以及知识产权）。\
*示例*: 从 ML‑as‑a‑Service API 收集足够多的问答对，以构建一个近似等效的本地模型。

- **AI Supply‑Chain Attack**: 在 **ML pipeline** 的任一组件（数据、libraries、pre‑trained weights、CI/CD）被入侵，从而污染下游模型。\
*示例*: model‑hub 上的被植入毒化的依赖在许多应用中安装了带后门的 sentiment‑analysis 模型。

- **Transfer Learning Attack**: 在 **pre‑trained model** 中植入恶意逻辑，即使在受害者的任务上进行 fine‑tuning 也会存活。\
*示例*: 一个含有隐藏触发器的 vision backbone 在被用于医疗成像后仍然会使标签翻转。

- **Model Skewing**: 通过微妙偏置或错误标注的数据**改变模型输出**，使其倾向于攻击者的目的。\
*示例*: 注入被标为 ham 的“干净”spam 邮件，使 spam filter 在未来放过相似邮件。

- **Output Integrity Attack**: 攻击者**在传输过程中更改模型预测**，而不是模型本身，从而欺骗下游系统。\
*示例*: 在文件被隔离前，将 malware classifier 的 "malicious" 判定篡改为 "benign"。

- **Model Poisoning** --- 直接、有针对性地修改**模型参数**本身，通常是在获得写入权限之后，以改变行为。\
*示例*: 在生产环境中调整 fraud‑detection model 的权重，使某些卡号的交易总是被批准。


## Google SAIF 风险

Google 的 [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) 概述了与 AI 系统相关的各种风险：

- **Data Poisoning**: 恶意行为者篡改或注入训练/微调数据以降低准确性、植入后门或偏斜结果，从而破坏模型在整个数据生命周期内的完整性。

- **Unauthorized Training Data**: 摄取受版权保护、敏感或未授权的数据集会带来法律、道德和性能方面的负债，因为模型从未被许可使用这些数据进行学习。

- **Model Source Tampering**: 在训练前或训练过程中通过供应链或内部人员篡改 model code、dependencies 或 weights，可能嵌入隐藏逻辑，即使重新训练也会保留。

- **Excessive Data Handling**: 弱的数据保留和治理控制导致系统存储或处理超出必要的个人数据，增加暴露面和合规风险。

- **Model Exfiltration**: 攻击者窃取模型文件/weights，导致知识产权流失并支持山寨服务或后续攻击。

- **Model Deployment Tampering**: 对模型工件或 serving 基础设施的篡改使运行中的模型与审核版本不一致，可能改变行为。

- **Denial of ML Service**: 通过淹没 API 或发送“sponge”输入耗尽计算/能量，使模型离线，类似传统的 DoS 攻击。

- **Model Reverse Engineering**: 通过收集大量输入-输出对，攻击者可以克隆或提取模型，促生模仿产品和定制化对抗攻击。

- **Insecure Integrated Component**: 易受攻击的插件、agents 或上游服务允许攻击者注入代码或在 AI 流水线中提升权限。

- **Prompt Injection**: 精心构造的 prompts（直接或间接）走私指令以覆盖系统意图，使模型执行非预期命令。

- **Model Evasion**: 经过精心设计的输入触发模型误判、出现 hallucinate，或输出被禁止的内容，侵蚀安全性和信任。

- **Sensitive Data Disclosure**: 模型泄露其训练数据或用户上下文中的私人或机密信息，违反隐私和法规。

- **Inferred Sensitive Data**: 模型推断出从未提供的个人属性，通过推断创造新的隐私伤害。

- **Insecure Model Output**: 未经消毒的响应向用户或下游系统传递有害代码、错误信息或不当内容。

- **Rogue Actions**: 自主集成的 agents 在缺乏足够用户监督的情况下执行非预期的真实世界操作（文件写入、API 调用、购买等）。

## Mitre AI ATLAS Matrix

[MITRE AI ATLAS Matrix](https://atlas.mitre.org/matrices/ATLAS) 提供了一个全面的框架，用于理解和缓解与 AI 系统相关的风险。它对攻击者可能采用的各种攻击技术和策略进行了分类，以及如何利用 AI 系统执行不同攻击的方式。

## LLMJacking (Token Theft & Resale of Cloud-hosted LLM Access)

攻击者窃取活动会话 tokens 或 cloud API credentials，未经授权调用付费的 cloud‑hosted LLMs。访问通常通过面向受害者账号的反向代理转售，例如 "oai-reverse-proxy" 部署。后果包括财务损失、model misuse 超出策略范围，以及将行为归因到受害租户。

TTPs:
- 从被感染的开发者机器或浏览器 harvest tokens；窃取 CI/CD secrets；购买 leaked cookies。
- 搭建一个将请求转发到真实提供商的 reverse proxy，隐藏上游 key 并对多名客户进行复用。
- 滥用直接的 base‑model endpoints，以绕过企业 guardrails 和速率限制。

Mitigations:
- 将 tokens 绑定到设备指纹、IP 范围和 client attestation；强制短期过期并通过 MFA 刷新。
- 最小化 key 的权限范围（无工具访问、尽可能只读）；在异常时轮换。
- 在策略网关后端终止所有流量，实施安全过滤、按路由配额和租户隔离。
- 监控异常使用模式（突增消费、非典型地区、UA 字符串）并自动撤销可疑会话。
- 优先使用 mTLS 或由你的 IdP 签发的 signed JWTs，而不是长期存在的静态 API keys。

## References
- [Unit 42 – The Risks of Code Assistant LLMs: Harmful Content, Misuse and Deception](https://unit42.paloaltonetworks.com/code-assistant-llms/)
- [LLMJacking scheme overview – The Hacker News](https://thehackernews.com/2024/05/researchers-uncover-llmjacking-scheme.html)
- [oai-reverse-proxy (reselling stolen LLM access)](https://gitgud.io/khanon/oai-reverse-proxy)

{{#include ../banners/hacktricks-training.md}}
