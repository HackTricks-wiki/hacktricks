# 威胁建模

欢迎阅读 HackTricks 的综合威胁建模指南！开始探索这一网络安全关键领域，在这里我们识别、理解并针对系统中的潜在漏洞制定策略。本主题提供了循序渐进的指南，包含真实案例、实用软件和易于理解的说明。无论是新手还是希望强化网络安全防御的经验丰富的从业者，都能从中受益。

### 常见使用场景

1. **软件开发**：作为 Secure Software Development Life Cycle (SSDLC) 的一部分，威胁建模有助于在开发早期**识别潜在的漏洞来源**。<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**：Penetration Testing Execution Standard (PTES) 将威胁建模视为正确执行所必需的环节，并要求记录业务资产、业务流程、威胁群体及其能力。<sup>[[2]](#references)</sup>

### 威胁模型概述

威胁模型通常以规划中的架构或现有应用程序的图表、图像或其他可视化形式表示。数据流图 (DFD) 是对系统及其交互进行建模的常见方式，而威胁建模则会增加以安全为重点的分析。<sup>[[1]](#references)</sup>

在 Microsoft 的 Threat Modeling Tool 中，红色虚线表示信任边界；其他工具可能使用不同的视觉约定。<sup>[[4]](#references)</sup> 为简化风险识别，团队可以使用 CIA (Confidentiality, Integrity, Availability) 三元组或 STRIDE 威胁类别，但适用的方法取决于项目的背景和需求。<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA 三元组

CIA 三元组是一种广泛认可的信息安全模型，代表 Confidentiality、Integrity 和 Availability。这些属性通常用于描述数据和系统的安全目标。<sup>[[3]](#references)</sup>

1. **Confidentiality**：确保数据或系统不会被未经授权的人员访问。这是安全性的核心方面之一，需要适当的访问控制、加密和其他措施来防止数据泄露。
2. **Integrity**：数据在其生命周期内的准确性、一致性和可信赖性。该原则确保数据不会被未经授权的实体修改或篡改。通常涉及校验和、哈希以及其他数据验证方法。
3. **Availability**：确保授权用户在需要时能够访问数据和服务。这通常涉及冗余、容错和高可用配置，以便系统即使遭遇中断也能持续运行。

### 威胁建模方法

1. **STRIDE**：Microsoft 的 STRIDE 方法将软件威胁划分为 **Spoofing、Tampering、Repudiation、Information Disclosure、Denial of Service 和 Elevation of Privilege**。这些类别有助于分析人员识别设计中每个易受攻击点可能存在的威胁。<sup>[[5]](#references)</sup>
2. **DREAD**：这种 Microsoft 评估方法使用 **Damage、Reproducibility、Exploitability、Affected users 和 Discoverability** 对威胁进行评分。所得分数有助于确定威胁缓解的优先级。<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis)：这是一种以**风险为中心**的七阶段方法，涵盖目标、技术范围、应用程序分解、威胁分析、漏洞和弱点分析、攻击建模以及风险/影响分析。<sup>[[8]](#references)</sup>
4. **Trike**：该安全审计框架从**风险管理**和防御角度处理威胁建模。<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling)：该方法强调为应用程序视图和运营视图构建可扩展且易用的威胁模型，并可与开发和 DevOps 生命周期集成。<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation)：OCTAVE 由 Carnegie Mellon 的 Software Engineering Institute 下属 CERT Division 创建，是一种基于风险的战略评估和规划方法，重点关注组织风险，而不仅仅是技术。<sup>[[10]](#references)</sup>

## 工具

有多种工具和软件解决方案可用于**辅助**创建和管理威胁模型。以下是一些可以考虑的工具。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite 是面向安全专业人员的跨平台 web crawler，支持攻击面映射、端点发现和 web 应用程序分析。<sup>[[6]](#references)</sup>

**用法**

1. 选择 URL 并 Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看 Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon 是一款免费的开源跨平台威胁建模应用程序，可用于绘制图表、提示威胁并记录缓解措施。它提供 web 和桌面应用程序。<sup>[[7]](#references)</sup>

**用法**

1. 创建新项目

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时它可能看起来像这样：

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动新项目

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存新项目

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建模型

你可以使用 SpiderSuite Crawler 等工具获取灵感，一个基本模型可能看起来像这样：

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

以下是对实体的简单说明：

- Process（实体本身，例如 Webserver 或 web 功能）
- Actor（人员，例如 Website Visitor、User 或 Administrator）
- Data Flow Line（交互指示器）
- Trust Boundary（不同的网络分段或范围。）
- Store（用于存储数据的对象，例如 Databases）

5. 创建威胁（步骤 1）

首先，你必须选择要添加威胁的层。

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在可以创建威胁。

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请注意，Actor Threats 和 Process Threats 之间存在差异。如果将威胁添加到 Actor，则只能选择 "Spoofing" 和 "Repudiation"。但是，在本例中，我们将威胁添加到 Process 实体，因此会在威胁创建框中看到以下选项：

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在，完成的模型应该看起来像这样。这就是如何使用 OWASP Threat Dragon 创建一个简单的威胁模型。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft 的 Threat Modeling Tool 是一款可免费下载的软件设计分析工具。其工作流会创建图表、识别威胁，并使用 STRIDE 方法支持缓解和验证。<sup>[[4]](#references)</sup>

## References

- [1] [威胁建模备忘单](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [威胁建模 - Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [安全基础 - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Microsoft Threat Modeling Tool 入门](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [驱动程序的威胁建模 - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA 威胁建模：七个阶段详解](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 方法文档](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [威胁建模：可用方法概述](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
