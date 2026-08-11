# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

HackTricksのThreat Modeling総合ガイドへようこそ！ここでは、システムに存在する可能性のある脆弱性を特定、理解し、対策を立案するという、cybersecurityの重要な分野について解説します。この章では、実際の例、役立つsoftware、理解しやすい説明を含むstep-by-stepガイドを提供します。初心者からcybersecurity defensesの強化を目指す経験豊富な実務者までを対象としています。

### 一般的に使用されるシナリオ

1. **Software Development**: Secure Software Development Life Cycle (SSDLC)の一環として、threat modelingは開発の初期段階で**脆弱性の潜在的な原因を特定する**のに役立ちます。<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES)では、正しい実行のためにthreat modelingを必須とし、business assets、business processes、threat communities、およびそれらのcapabilitiesを文書化するよう求めています。<sup>[[2]](#references)</sup>

### Threat Modelの概要

Threat modelは通常、計画されたarchitectureまたは既存のapplicationを図、画像、その他の視覚的な形式で表現したものです。Data-flow diagrams (DFDs)は、システムとそのinteractionsをmodel化する一般的な方法であり、threat modelingではこれにsecurityに重点を置いた分析を加えます。<sup>[[1]](#references)</sup>

Microsoft's Threat Modeling Toolでは、赤い点線がtrust boundariesを示しますが、他のtoolsでは異なる視覚的な表現が使用される場合があります。<sup>[[4]](#references)</sup> risk identificationを効率化するため、teamはCIA (Confidentiality, Integrity, Availability) triadまたはSTRIDE threat categoriesを使用できます。ただし、適切なmethodologyはprojectのcontextとrequirementsによって異なります。<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triadは、Confidentiality、Integrity、Availabilityを表す、広く認知されたinformation-security modelです。これらの特性は、dataとsystemsのsecurity goalsを説明するためによく使用されます。<sup>[[3]](#references)</sup>

1. **Confidentiality**: unauthorized individualsがdataまたはsystemにaccessできないようにすること。これはsecurityの中心的な側面であり、data breachesを防ぐために、適切なaccess controls、encryption、その他の対策が必要です。
2. **Integrity**: lifecycle全体を通じたdataの正確性、一貫性、信頼性。この原則により、dataがunauthorized partiesによって変更または改ざんされていないことを保証します。多くの場合、checksums、hashing、その他のdata verification methodsが使用されます。
3. **Availability**: 必要なときにauthorized usersがdataとservicesへaccessできることを保証します。disruptionsが発生してもsystemsを稼働させ続けるため、redundancy、fault tolerance、high-availability configurationsなどが使用されます。

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft's STRIDE approachは、software threatsを**Spoofing、Tampering、Repudiation、Information Disclosure、Denial of Service、Elevation of Privilege**に分類します。これらのcategoriesは、design上の各脆弱なpointで発生する可能性のあるthreatsをanalystsが特定するのに役立ちます。<sup>[[5]](#references)</sup>
2. **DREAD**: このMicrosoft assessment approachは、**Damage、Reproducibility、Exploitability、Affected users、Discoverability**を使用してthreatsをscoringします。結果のscoreは、mitigationのためにthreatsの優先順位を決めるのに役立ちます。<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): objectives、technical scope、application decomposition、threat analysis、vulnerability and weakness analysis、attack modeling、risk/impact analysisを対象とする、7段階の**risk-centric** methodologyです。<sup>[[8]](#references)</sup>
4. **Trike**: このsecurity-audit frameworkは、**risk-management**とdefensiveな観点からthreat modelingに取り組みます。<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): application viewとoperational view向けに、scalableでusableなthreat modelsを重視するmethodです。developmentおよびDevOps lifecyclesとintegrateすることもできます。<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering InstituteのCERT Divisionによって作成されたOCTAVEは、technologyだけでなくorganizational riskに重点を置く、risk-basedのstrategic assessmentおよびplanning methodです。<sup>[[10]](#references)</sup>

## Tools

threat modelsの作成と管理を**支援**するために利用できるtoolsやsoftware solutionsはいくつかあります。ここでは、検討できるものをいくつか紹介します。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuiteは、security professionals向けのcross-platform web crawlerで、attack-surface mapping、endpoint discovery、web-application analysisをサポートします。<sup>[[6]](#references)</sup>

**使用方法**

1. URLを選択してCrawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graphを表示

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragonは、diagramの作成、threatsの提案、mitigationsの記録を行うためのfree、open-source、cross-platform threat-modeling applicationです。web applicationとdesktop applicationとして利用できます。<sup>[[7]](#references)</sup>

**使用方法**

1. New Projectを作成

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

次のように表示される場合もあります。

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Projectを起動

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Projectを保存

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. modelを作成

SpiderSuite Crawlerなどのtoolsを使用してinspirationを得ることができます。basic modelは次のようになります。

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

entitiesについて簡単に説明します。

- Process (Webserverやweb functionalityなどのentityそのもの)
- Actor (Website Visitor、User、AdministratorなどのPerson)
- Data Flow Line (InteractionのIndicator)
- Trust Boundary (異なるnetwork segmentsまたはscopes)
- Store (Databasesなど、dataが保存される場所)

5. Threatを作成 (Step 1)

まず、threatを追加するlayerを選択します。

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

次に、threatを作成できます。

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor ThreatsとProcess Threatsには違いがあることに注意してください。Actorにthreatを追加した場合、"Spoofing"と"Repudiation"のみを選択できます。一方、この例ではProcess entityにthreatを追加するため、threat creation boxには次のように表示されます。

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完了

完成したmodelは次のようになります。これが、OWASP Threat Dragonでsimple threat modelを作成する方法です。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Toolは、software design analysis向けのfree downloadable toolです。このworkflowではdiagramを作成し、threatsを特定し、STRIDE approachを使用してmitigationとvalidationをサポートします。<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Microsoft Threat Modeling Toolの使用を開始する](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Drivers向けThreat Modeling - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: 7つのStagesの解説](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: 利用可能なMethodsの概要](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
