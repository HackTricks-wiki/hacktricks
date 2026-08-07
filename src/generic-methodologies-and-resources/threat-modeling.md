# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

## Threat Modeling

HackTricks の Threat Modeling 総合ガイドへようこそ！ここでは、cybersecurity の重要な側面である、システム内の潜在的な脆弱性を特定、理解し、対策を立てる方法について説明します。このスレッドは、実際の例、役立つ software、理解しやすい解説を含むステップバイステップのガイドです。cybersecurity の防御を強化したい初心者にも経験豊富な実務者にも適しています。

### 一般的に使用されるシナリオ

1. **Software Development**: Secure Software Development Life Cycle (SSDLC) の一環として、threat modeling は開発の初期段階で **脆弱性の潜在的な原因を特定する** のに役立ちます。
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework では、test を実施する前に **システムの脆弱性を理解するための threat modeling** が必要です。

### Threat Model の概要

Threat Model は通常、application の計画された architecture または既存の build を示す diagram、image、その他の visual illustration として表現されます。これは **data flow diagram** に似ていますが、主な違いは security を重視して設計されている点です。

Threat model では、潜在的な脆弱性、risk、または障壁を示すために、要素が赤色で表示されることがよくあります。risk の特定を効率化するために、CIA (Confidentiality, Integrity, Availability) triad が使用されます。これは多くの threat modeling methodology の基礎となっており、STRIDE は最も一般的なものの一つです。ただし、選択する methodology は、具体的な状況や要件によって異なります。

### CIA Triad

CIA Triad は information security 分野で広く認識されている model で、Confidentiality、Integrity、Availability を表します。この3つの柱は、threat modeling methodology を含む、多くの security 対策や policy の基盤となっています。

1. **Confidentiality**: unauthorized な個人が data または system に access できないようにすること。これは security の中心的な要素であり、data breach を防ぐために適切な access control、encryption、その他の対策が必要です。
2. **Integrity**: lifecycle 全体を通じた data の正確性、一貫性、信頼性。この原則により、unauthorized な party によって data が変更または改ざんされないことが保証されます。通常、checksum、hashing、その他の data 検証手法が使用されます。
3. **Availability**: 必要なときに、authorized な user が data と service に access できるようにすること。system を障害発生時にも稼働させ続けるため、redundancy、fault tolerance、high-availability configuration などが使用されます。

### Threat Modeling の方法論

1. **STRIDE**: Microsoft によって開発された STRIDE は、**Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege** の頭字語です。各 category は threat の種類を表しており、program または system の design phase で潜在的な threat を特定するために一般的に使用されます。
2. **DREAD**: これは Microsoft の別の methodology で、特定された threat の risk assessment に使用されます。DREAD は **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability** を表します。これらの各要素に score を付け、その結果を使用して特定された threat の優先順位を決定します。
3. **PASTA** (Process for Attack Simulation and Threat Analysis): これは7段階の **risk-centric** methodology です。security objective の定義と特定、technical scope の作成、application decomposition、threat analysis、vulnerability analysis、risk/triage assessment が含まれます。
4. **Trike**: これは asset の防御に重点を置く risk-based methodology です。**risk management** の観点から開始し、その context における threat と vulnerability を分析します。
5. **VAST** (Visual, Agile, and Simple Threat modeling): この approach はより利用しやすく、Agile development environment に統合できることを目指しています。他の methodology の要素を組み合わせ、**threat の visual representation** に重点を置いています。
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): CERT Coordination Center によって開発されたこの framework は、**特定の system や software ではなく、organizational risk assessment** を対象としています。

## Tools

threat model の作成と管理を **支援** できるさまざまな tool や software solution が存在します。ここでは、検討できるものをいくつか紹介します。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

cyber security professional 向けの、高度な cross-platform 対応かつ多機能な GUI web spider/crawler です。Spider Suite は attack surface mapping と analysis に使用できます。

**使用方法**

1. URL を選択して Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph を表示

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP の open-source project である Threat Dragon は、system diagramming と、threat/mitigation を自動生成する rule engine の両方を備えた web および desktop application です。

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

SpiderSuite Crawler のような tool を使用して inspiration を得ることができます。基本的な model は次のようになります。

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

各 entity について簡単に説明します。

- Process (Webserver や web functionality などの entity 自体)
- Actor (Website Visitor、User、Administrator などの Person)
- Data Flow Line (Interaction の indicator)
- Trust Boundary (異なる network segment または scope)
- Store (Database など、data が保存される場所)

5. Threat を作成 (Step 1)

まず、threat を追加する layer を選択します。

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

次に threat を作成できます。

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats と Process Threats には違いがあることに注意してください。Actor に threat を追加した場合、選択できるのは "Spoofing" と "Repudiation" だけです。一方、この例では Process entity に threat を追加しているため、threat creation box に次のように表示されます。

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完了

これで完成した model は次のようになります。これが OWASP Threat Dragon を使用して簡単な threat model を作成する方法です。

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

これは Microsoft が提供する free tool で、software project の design phase における threat の発見を支援します。STRIDE methodology を使用しており、Microsoft stack 上で開発する人に特に適しています。

{{#include ../banners/hacktricks-training.md}}
