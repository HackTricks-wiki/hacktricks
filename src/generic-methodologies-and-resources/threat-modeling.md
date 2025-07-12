# 威胁建模

{{#include ../banners/hacktricks-training.md}}

## 威胁建模

欢迎来到 HackTricks 关于威胁建模的综合指南！开始探索网络安全这一关键方面，我们识别、理解并制定针对系统潜在漏洞的策略。此线程作为逐步指南，包含真实案例、实用软件和易于理解的解释。非常适合希望加强网络安全防御的新手和经验丰富的从业者。

### 常用场景

1. **软件开发**：作为安全软件开发生命周期（SSDLC）的一部分，威胁建模有助于**在开发早期识别潜在漏洞来源**。
2. **渗透测试**：渗透测试执行标准（PTES）框架要求**进行威胁建模以了解系统的漏洞**，然后再进行测试。

### 威胁模型概述

威胁模型通常以图表、图像或其他形式的视觉插图表示，描绘应用程序的计划架构或现有构建。它与**数据流图**相似，但关键区别在于其安全导向的设计。

威胁模型通常包含用红色标记的元素，象征潜在的漏洞、风险或障碍。为了简化风险识别过程，采用CIA（机密性、完整性、可用性）三元组，构成许多威胁建模方法的基础，其中STRIDE是最常见的之一。然而，所选方法可能会根据具体上下文和要求而有所不同。

### CIA三元组

CIA三元组是信息安全领域广泛认可的模型，代表机密性、完整性和可用性。这三大支柱构成了许多安全措施和政策的基础，包括威胁建模方法。

1. **机密性**：确保数据或系统不被未经授权的个人访问。这是安全的核心方面，需要适当的访问控制、加密和其他措施以防止数据泄露。
2. **完整性**：数据在其生命周期内的准确性、一致性和可信度。该原则确保数据未被未经授权的方更改或篡改。通常涉及校验和、哈希和其他数据验证方法。
3. **可用性**：确保数据和服务在需要时可供授权用户访问。这通常涉及冗余、容错和高可用性配置，以保持系统在中断情况下仍能运行。

### 威胁建模方法

1. **STRIDE**：由微软开发，STRIDE是**欺骗、篡改、否认、信息泄露、服务拒绝和特权提升**的首字母缩略词。每个类别代表一种威胁，这种方法通常用于程序或系统的设计阶段，以识别潜在威胁。
2. **DREAD**：这是微软用于已识别威胁风险评估的另一种方法。DREAD代表**损害潜力、可重现性、可利用性、受影响用户和可发现性**。每个因素都被评分，结果用于优先排序已识别的威胁。
3. **PASTA**（攻击模拟和威胁分析过程）：这是一种七步的**风险中心**方法。它包括定义和识别安全目标、创建技术范围、应用程序分解、威胁分析、漏洞分析和风险/分流评估。
4. **Trike**：这是一种基于风险的方法，专注于保护资产。它从**风险管理**的角度出发，关注威胁和漏洞。
5. **VAST**（可视化、敏捷和简单的威胁建模）：这种方法旨在更易于访问，并集成到敏捷开发环境中。它结合了其他方法的元素，专注于**威胁的可视化表示**。
6. **OCTAVE**（操作关键威胁、资产和漏洞评估）：由CERT协调中心开发，该框架旨在**进行组织风险评估，而不是特定系统或软件**。

## 工具

有几种工具和软件解决方案可用于**协助**创建和管理威胁模型。以下是您可能考虑的一些工具。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

一个先进的跨平台多功能GUI网络爬虫/蜘蛛，适用于网络安全专业人员。Spider Suite可用于攻击面映射和分析。

**使用方法**

1. 选择一个URL并爬取

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 查看图表

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP的一个开源项目，Threat Dragon是一个包含系统图示和规则引擎以自动生成威胁/缓解措施的Web和桌面应用程序。

**使用方法**

1. 创建新项目

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

有时它可能看起来像这样：

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 启动新项目

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 保存新项目

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 创建您的模型

您可以使用像SpiderSuite Crawler这样的工具来获得灵感，基本模型可能看起来像这样

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

关于实体的简单解释：

- 过程（实体本身，如Web服务器或Web功能）
- 参与者（如网站访客、用户或管理员的人）
- 数据流线（交互的指示）
- 信任边界（不同的网络段或范围）
- 存储（数据存储的地方，如数据库）

5. 创建威胁（步骤1）

首先，您必须选择要添加威胁的层

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

现在您可以创建威胁

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

请记住，参与者威胁和过程威胁之间是有区别的。如果您要向参与者添加威胁，则只能选择“欺骗”和“否认”。然而在我们的示例中，我们将威胁添加到过程实体，因此我们将在威胁创建框中看到：

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完成

现在您完成的模型应该看起来像这样。这就是如何使用OWASP Threat Dragon制作简单威胁模型。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

这是微软提供的免费工具，帮助在软件项目的设计阶段发现威胁。它使用STRIDE方法，特别适合在微软技术栈上开发的人员。

{{#include ../banners/hacktricks-training.md}}
