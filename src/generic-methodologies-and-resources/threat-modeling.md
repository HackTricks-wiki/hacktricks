# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

欢迎阅读 HackTricks 的 Threat Modeling 综合指南！让我们一起探索这一关键的 cybersecurity 领域：识别、理解并制定应对系统潜在漏洞的策略。本主题将通过真实案例、实用 software 和易于理解的说明，为你提供循序渐进的指南。无论是新手，还是希望强化 cybersecurity 防御的资深从业者，都能从中受益。

### 常见使用场景

1. **Software Development**：作为 Secure Software Development Life Cycle (SSDLC) 的一部分，Threat Modeling 有助于在开发早期**识别潜在的漏洞来源**。<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**：Penetration Testing Execution Standard (PTES) 将 Threat Modeling 视为正确执行测试的必要环节，并要求记录业务资产、业务流程、威胁社区及其能力。<sup>[[2]](#references)</sup>

### Threat Model 简介

Threat Model 通常以图表、图像或其他可视化形式表示计划中的架构或现有应用程序。Data-flow diagrams (DFDs) 是对系统及其交互进行建模的常见方式，而 Threat Modeling 则在此基础上增加面向 security 的分析。<sup>[[1]](#references)</sup>

在 Microsoft 的 Threat Modeling Tool 中，红色虚线表示信任边界；其他工具可能使用不同的可视化约定。<sup>[[4]](#references)</sup> 为了简化风险识别，团队可以使用 CIA (Confidentiality, Integrity, Availability) triad 或 STRIDE threat categories，但合适的方法取决于项目的背景和需求。<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad 是广泛认可的信息安全模型，代表 Confidentiality、Integrity 和 Availability。这些属性通常用于描述数据和系统的安全目标。<sup>[[3]](#references)</sup>

1. **Confidentiality**：确保未经授权的人员无法访问数据或系统。这是 security 的核心方面，需要使用适当的访问控制、加密和其他措施来防止数据泄露。
2. **Integrity**：指数据在其生命周期内的准确性、一致性和可信度。该原则确保未经授权的实体无法修改或篡改数据，通常涉及校验和、hashing 及其他数据验证方法。
3. **Availability**：确保授权用户在需要时可以访问数据和服务。这通常需要使用冗余、容错和高可用配置，使系统即使在遭遇中断时仍能持续运行。

### Threat Modeling 方法

1. **STRIDE**：Microsoft 的 STRIDE 方法将 software threats 分为 **Spoofing、Tampering、Repudiation、Information Disclosure、Denial of Service 和 Elevation of Privilege**。这些类别有助于分析人员识别设计中每个易受攻击位置可能存在的威胁。<sup>[[5]](#references)</sup>
2. **DREAD**：这一 Microsoft assessment 方法使用 **Damage、Reproducibility、Exploitability、Affected users 和 Discoverability** 对威胁进行评分。所得分数有助于确定威胁缓解的优先级。<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis)：这是一种以**风险为中心**的七阶段方法，涵盖目标、技术范围、应用程序分解、威胁分析、漏洞和弱点分析、攻击建模以及风险/影响分析。<sup>[[8]](#references)</sup>
4. **Trike**：这一 security-audit framework 从**风险管理**和防御的角度处理 Threat Modeling。<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling)：该方法强调为应用程序视图和运营视图创建可扩展且易于使用的 Threat Models，并可与 development 和 DevOps 生命周期集成。<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation)：OCTAVE 由 Carnegie Mellon 的 Software Engineering Institute 下属 CERT Division 创建，是一种基于风险的战略评估和规划方法，重点关注组织风险，而不仅仅是 technology。<sup>[[10]](#references)</sup>

## Tools

有多种工具和 software solutions 可用于**协助**创建和管理 Threat Models。以下是一些可以考虑的选项。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite 是一款面向 security professionals 的跨平台 web crawler，支持 attack-surface mapping、endpoint discovery 和 web-application analysis。<sup>[[6]](#references)</sup>

**使用方法**

1. 选择 URL 并进行 Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看 Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon 是一款免费、开源、跨平台的 Threat Modeling 应用程序，用于绘制图表、提出威胁并记录缓解措施。它提供 web 和 desktop applications。<sup>[[7]](#references)</sup>

**使用方法**

1. 创建 New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时它可能看起来像这样：

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动 New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存 New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建你的 model

你可以使用 SpiderSuite Crawler 等工具获取灵感，一个基本的 model 可能如下所示：

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

下面对各个实体进行简单说明：

- Process（实体本身，例如 Webserver 或 web functionality）
- Actor（人员，例如 Website Visitor、User 或 Administrator）
- Data Flow Line（交互指示器）
- Trust Boundary（不同的 network segments 或 scopes。）
- Store（用于存储数据的对象，例如 Databases）

5. 创建 Threat（步骤 1）

首先，你需要选择要添加 threat 的 layer

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在你可以创建 threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请注意 Actor Threats 和 Process Threats 之间存在差异。如果你要向 Actor 添加 threat，那么只能选择 "Spoofing" 和 "Repudiation"。但是，在本例中，我们向 Process entity 添加 threat，因此会在 threat creation box 中看到以下选项：

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在，完成后的 model 应该类似于下图。这就是如何使用 OWASP Threat Dragon 创建一个简单的 Threat Model。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft 的 Threat Modeling Tool 是一款可免费下载、用于 software design analysis 的工具。它的工作流程会创建图表、识别威胁，并使用 STRIDE 方法支持 mitigation 和 validation。<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling 速查表](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security 基础 - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Microsoft Threat Modeling Tool 入门](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Drivers 的 Threat Modeling - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling：七个阶段详解](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 方法文档](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling：可用方法总结](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
