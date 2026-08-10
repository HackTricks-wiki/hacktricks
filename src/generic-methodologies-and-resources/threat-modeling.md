# Threat Modeling

HackTricks の Threat Modeling 総合ガイドへようこそ！サイバーセキュリティにおけるこの重要な側面を探究し、システム内の潜在的な脆弱性を特定、理解し、対策を立案していきます。本稿では、実環境の例、役立つ software、理解しやすい説明を盛り込んだステップごとのガイドを提供します。サイバーセキュリティ防御を強化したい初心者と経験豊富な実務者の双方に適しています。

### よく使用されるシナリオ

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) の一環として、Threat Modeling は開発の初期段階で**脆弱性の潜在的な原因を特定する**のに役立ちます。<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) では、Threat Modeling を正しく実行するために必要なものとして扱い、business assets、business processes、threat communities、およびそれらの capabilities を文書化するよう求めています。<sup>[[2]](#references)</sup>

### Threat Model の概要

Threat model は通常、計画された architecture または既存の application を図、画像、その他の視覚的な形式で表現したものです。Data-flow diagrams (DFDs) はシステムとその相互作用を model 化する一般的な方法であり、Threat Modeling ではこれに security に重点を置いた分析を加えます。<sup>[[1]](#references)</sup>

Microsoft's Threat Modeling Tool では、赤い点線が trust boundaries を示します。他の tools では異なる視覚的表現が使用される場合があります。<sup>[[4]](#references)</sup> リスクの特定を効率化するために、チームは CIA (Confidentiality, Integrity, Availability) triad または STRIDE threat categories を使用できますが、適切な methodology はプロジェクトの context と requirements によって異なります。<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad は、Confidentiality、Integrity、Availability を表す、広く認識された information-security model です。これらの特性は、data と systems の security goals を説明するためによく使用されます。<sup>[[3]](#references)</sup>

1. **Confidentiality**: unauthorized individuals が data または system に access できないようにすること。これは security の中心的な側面であり、data breaches を防ぐために、適切な access controls、encryption、その他の対策が必要です。
2. **Integrity**: lifecycle 全体にわたる data の正確性、一貫性、信頼性。これは unauthorized parties によって data が変更または tamper されないことを保証する原則です。通常、checksums、hashing、その他の data verification methods が使用されます。
3. **Availability**: authorized users が必要なときに data と services に access できることを保証します。これは多くの場合、redundancy、fault tolerance、high-availability configurations によって実現され、障害が発生しても systems を稼働し続けられるようにします。

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft's STRIDE approach は、software threats を **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege** に分類します。これらの categories は、design 内の各 vulnerable point における可能な threats を analysts が特定するのに役立ちます。<sup>[[5]](#references)</sup>
2. **DREAD**: この Microsoft assessment approach は、**Damage, Reproducibility, Exploitability, Affected users, and Discoverability** を使用して threats を score 化します。算出された score は、mitigation のために threats の優先順位を決めるのに役立ちます。<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): これは objectives、technical scope、application decomposition、threat analysis、vulnerability and weakness analysis、attack modeling、risk/impact analysis を対象とする、7段階の **risk-centric** methodology です。<sup>[[8]](#references)</sup>
4. **Trike**: この security-audit framework は、**risk-management** と defensive perspective から Threat Modeling に取り組みます。<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): この method は、application と operational views 向けの scalable で usable な threat models を重視し、development および DevOps lifecycles と統合できます。<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering Institute の CERT Division によって作成された OCTAVE は、technology だけでなく organizational risk に焦点を当てた、risk-based の strategic assessment and planning method です。<sup>[[10]](#references)</sup>

## Tools

Threat models の作成と管理を**支援**できる tools や software solutions がいくつか提供されています。ここでは検討できるものをいくつか紹介します。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite は security professionals 向けの cross-platform web crawler で、attack-surface mapping、endpoint discovery、web-application analysis をサポートします。<sup>[[6]](#references)</sup>

**使用方法**

1. URL を選択して Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph を表示

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon は、diagrams の作成、threats の提案、mitigations の記録を行うための free、open-source、cross-platform threat-modeling application です。web application と desktop application として利用できます。<sup>[[7]](#references)</sup>

**使用方法**

1. New Project を作成

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

次のように表示される場合もあります。

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project を起動

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project を保存

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. model を作成

SpiderSuite Crawler のような tools を使用して inspiration を得られます。basic model は次のようになります。

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

entities について簡単に説明します。

- Process (Webserver や web functionality などの entity 自体)
- Actor (Website Visitor、User、Administrator などの Person)
- Data Flow Line (Interaction の indicator)
- Trust Boundary (異なる network segments または scopes)
- Store (Databases など、data が stored される場所)

5. Threat を作成 (Step 1)

まず、threat を追加する layer を選択します。

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

次に threat を作成できます。

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats と Process Threats には違いがあることに注意してください。Actor に threat を追加する場合、選択できるのは "Spoofing" と "Repudiation" のみです。一方、この例では Process entity に threat を追加するため、threat creation box には次の項目が表示されます。

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完了

完成した model は次のようになります。これが OWASP Threat Dragon で simple threat model を作成する方法です。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool は、software design analysis 用の free downloadable tool です。その workflow では diagram を作成し、threats を特定し、STRIDE approach を使用して mitigation と validation をサポートします。<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Microsoft Threat Modeling Tool の使用開始](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Drivers 向け Threat Modeling - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: 7 Stages の解説](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: 利用可能な Methods の概要](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
