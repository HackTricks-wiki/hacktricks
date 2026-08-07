# 威胁建模

{{#include ../banners/hacktricks-training.md}}

## 威胁建模

欢迎阅读 HackTricks 的全面威胁建模指南！让我们一起探索这一网络安全关键领域，识别、理解并制定策略来应对系统中的潜在漏洞。本节提供循序渐进的指南，其中包含真实案例、实用软件和易于理解的解释。无论是新手还是希望强化网络安全防御的经验丰富的从业者，都能从中受益。

### 常见使用场景

1. **软件开发**：作为安全软件开发生命周期（SSDLC）的一部分，威胁建模有助于在开发早期**识别潜在的漏洞来源**。
2. **Penetration Testing**：Penetration Testing Execution Standard（PTES）框架要求在执行测试前，通过**威胁建模了解系统中的漏洞**。

### 威胁模型概述

威胁模型通常以图表、图像或其他可视化形式呈现，用于描述应用程序的计划架构或现有构建。它与**数据流图**相似，但关键区别在于其以安全性为导向的设计。

威胁模型通常会使用红色标记元素，以表示潜在漏洞、风险或边界。为了简化风险识别流程，通常会采用 CIA（Confidentiality、Integrity、Availability）三元组。它是许多威胁建模方法的基础，其中 STRIDE 是最常见的方法之一。不过，具体选择的方法可能因场景和需求而异。

### CIA 三元组

CIA 三元组是信息安全领域广泛认可的模型，代表 Confidentiality、Integrity 和 Availability。这三大支柱构成了许多安全措施和策略的基础，其中也包括威胁建模方法。

1. **Confidentiality**：确保数据或系统不会被未经授权的人员访问。这是安全性的核心组成部分，需要适当的访问控制、加密和其他措施来防止数据泄露。
2. **Integrity**：数据在其生命周期内的准确性、一致性和可信度。该原则确保数据不会被未经授权的实体更改或篡改。通常涉及校验和、哈希以及其他数据验证方法。
3. **Availability**：确保授权用户在需要时能够访问数据和服务。通常会采用冗余、容错和高可用配置，使系统即使面临中断也能持续运行。

### 威胁建模方法论

1. **STRIDE**：由 Microsoft 开发，STRIDE 是 **Spoofing、Tampering、Repudiation、Information Disclosure、Denial of Service 和 Elevation of Privilege** 的首字母缩写。每个类别代表一种威胁。该方法通常用于程序或系统的设计阶段，以识别潜在威胁。
2. **DREAD**：这是 Microsoft 提出的另一种方法，用于评估已识别威胁的风险。DREAD 代表 **Damage potential、Reproducibility、Exploitability、Affected users 和 Discoverability**。每个因素都会获得评分，并根据结果确定已识别威胁的优先级。
3. **PASTA**（Process for Attack Simulation and Threat Analysis）：这是一种七步的、以**风险为中心**的方法。它包括定义和识别安全目标、创建技术范围、应用程序分解、威胁分析、漏洞分析以及风险/分类评估。
4. **Trike**：这是一种基于风险、专注于保护资产的方法。它从**风险管理**角度出发，并在这一背景下分析威胁和漏洞。
5. **VAST**（Visual、Agile 和 Simple Threat modeling）：该方法旨在提高可访问性，并融入 Agile 开发环境。它结合了其他方法的要素，并专注于**威胁的可视化表示**。
6. **OCTAVE**（Operationally Critical Threat、Asset 和 Vulnerability Evaluation）：该框架由 CERT Coordination Center 开发，主要面向**组织级风险评估，而非特定系统或软件**。

## 工具

目前有多种工具和软件解决方案可以**协助**创建和管理威胁模型。以下是一些可以考虑的工具。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

面向网络安全专业人员的先进跨平台、多功能 GUI web spider/crawler。Spider Suite 可用于攻击面映射和分析。

**使用方法**

1. 选择 URL 并进行 Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看 Graph

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

Threat Dragon 是 OWASP 的开源项目，同时提供 web 和桌面应用程序，包含系统绘图功能以及可自动生成 threats/mitigations 的规则引擎。

**使用方法**

1. 创建 New Project

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时它可能会显示为这样：

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动 New Project

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存 New Project

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建模型

你可以使用 SpiderSuite Crawler 等工具获取灵感。一个基本模型大致如下所示：

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

以下是对各实体的简要说明：

- Process（实体本身，例如 Webserver 或 web 功能）
- Actor（人员，例如 Website Visitor、User 或 Administrator）
- Data Flow Line（交互指示器）
- Trust Boundary（不同的网络 segment 或 scope。）
- Store（存储数据的对象，例如 Databases）

5. 创建 Threat（步骤 1）

首先，你需要选择要添加 threat 的 layer

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在你可以创建 threat

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请注意，Actor Threats 与 Process Threats 之间存在差异。如果将 threat 添加到 Actor，则只能选择 "Spoofing" 和 "Repudiation"。但是，在本例中，我们将 threat 添加到 Process entity，因此会在 threat creation box 中看到以下选项：

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在，完成后的模型应该类似于下面这样。这就是如何使用 OWASP Threat Dragon 创建一个简单的威胁模型。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

这是 Microsoft 提供的一款免费工具，有助于在软件项目的设计阶段发现威胁。它使用 STRIDE 方法，尤其适合在 Microsoft 技术栈上进行开发的人员。

{{#include ../banners/hacktricks-training.md}}
