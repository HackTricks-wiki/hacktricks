# 위협 모델링

{{#include ../banners/hacktricks-training.md}}

## 위협 모델링

HackTricks의 종합적인 위협 모델링 가이드에 오신 것을 환영합니다! 시스템의 잠재적인 취약점을 식별하고, 이해하며, 이에 대응하기 위한 전략을 수립하는 사이버 보안의 중요한 영역을 살펴보겠습니다. 이 글은 실제 사례, 유용한 software, 이해하기 쉬운 설명을 포함한 단계별 가이드입니다. 사이버 보안 방어를 강화하려는 초보자와 숙련된 실무자 모두에게 적합합니다.

### 일반적으로 사용되는 시나리오

1. **Software Development**: Secure Software Development Life Cycle (SSDLC)의 일부로서, 위협 모델링은 개발 초기 단계에서 **잠재적인 취약점의 원인을 식별**하는 데 도움을 줍니다.
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES) framework에서는 test를 수행하기 전에 **시스템의 취약점을 이해하기 위한 위협 모델링**을 요구합니다.

### 위협 모델 한눈에 보기

위협 모델은 일반적으로 application의 계획된 architecture 또는 기존 build를 나타내는 diagram, image 또는 기타 형태의 시각적 illustration로 표현됩니다. 위협 모델은 **data flow diagram**과 유사하지만, 핵심적인 차이점은 security 중심으로 설계된다는 점입니다.

위협 모델에는 잠재적인 취약점, risks 또는 barriers를 상징하는 빨간색 요소가 자주 포함됩니다. risk 식별 과정을 간소화하기 위해 CIA (Confidentiality, Integrity, Availability) triad가 사용되며, 이는 STRIDE를 비롯한 많은 threat modeling methodologies의 기반이 됩니다. 그러나 선택하는 methodology는 구체적인 context와 requirements에 따라 달라질 수 있습니다.

### CIA Triad

CIA Triad는 information security 분야에서 널리 알려진 model로, Confidentiality, Integrity, Availability를 의미합니다. 이 세 가지 pillar는 threat modeling methodologies를 포함한 많은 security measures와 policies가 구축되는 기반을 형성합니다.

1. **Confidentiality**: unauthorized individuals가 data 또는 system에 접근하지 못하도록 보장하는 것입니다. 이는 적절한 access controls, encryption 및 data breaches를 방지하기 위한 기타 measures가 필요한 security의 핵심적인 측면입니다.
2. **Integrity**: lifecycle 전반에 걸친 data의 정확성, 일관성 및 신뢰성입니다. 이 원칙은 unauthorized parties가 data를 변경하거나 tamper하지 못하도록 보장합니다. 일반적으로 checksums, hashing 및 기타 data verification methods가 사용됩니다.
3. **Availability**: 필요할 때 authorized users가 data와 services에 접근할 수 있도록 보장합니다. 이는 disruptions가 발생하더라도 systems가 계속 실행되도록 redundancy, fault tolerance 및 high-availability configurations를 사용하는 경우가 많습니다.

### Threat Modeling Methodlogies

1. **STRIDE**: Microsoft에서 개발한 STRIDE는 **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege**의 약어입니다. 각 category는 threat의 한 유형을 나타내며, 이 methodology는 program 또는 system의 design phase에서 잠재적인 threats를 식별하는 데 일반적으로 사용됩니다.
2. **DREAD**: 식별된 threats의 risk assessment에 사용되는 Microsoft의 또 다른 methodology입니다. DREAD는 **Damage potential, Reproducibility, Exploitability, Affected users, and Discoverability**를 의미합니다. 각 factor에 score를 부여하고, 그 결과를 사용하여 식별된 threats의 우선순위를 정합니다.
3. **PASTA** (Process for Attack Simulation and Threat Analysis): 이는 7단계의 **risk-centric** methodology입니다. security objectives의 정의 및 식별, technical scope 생성, application decomposition, threat analysis, vulnerability analysis 및 risk/triage assessment가 포함됩니다.
4. **Trike**: assets를 방어하는 데 중점을 둔 risk-based methodology입니다. **risk management** 관점에서 시작하여 해당 context에서 threats와 vulnerabilities를 살펴봅니다.
5. **VAST** (Visual, Agile, and Simple Threat modeling): 이 approach는 더 쉽게 접근할 수 있도록 하며 Agile development environments에 통합됩니다. 다른 methodologies의 요소를 결합하고 **threats의 visual representations**에 중점을 둡니다.
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): CERT Coordination Center에서 개발한 이 framework는 **특정 systems 또는 software가 아닌 organizational risk assessment**를 목표로 합니다.

## Tools

threat models의 생성과 관리를 **지원**할 수 있는 여러 tools와 software solutions가 있습니다. 고려해 볼 만한 몇 가지를 소개합니다.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

cyber security professionals를 위한 advanced cross-platform 및 multi-feature GUI web spider/crawler입니다. Spider Suite는 attack surface mapping 및 analysis에 사용할 수 있습니다.

**Usage**

1. URL을 선택하고 Crawl

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph 보기

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP의 open-source project인 Threat Dragon은 system diagramming과 rule engine을 모두 포함하는 web 및 desktop application으로, threats/mitigations를 자동으로 생성할 수 있습니다.

**Usage**

1. 새 Project 생성

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

다음과 같이 표시될 수도 있습니다.

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 새 Project 실행

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 새 Project 저장

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. model 생성

SpiderSuite Crawler와 같은 tools를 사용하여 inspiration을 얻을 수 있습니다. 기본 model은 다음과 같은 형태입니다.

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

entities에 대해 간단히 설명하면 다음과 같습니다.

- Process (Webserver 또는 web functionality와 같은 entity 자체)
- Actor (Website Visitor, User 또는 Administrator와 같은 Person)
- Data Flow Line (Interaction의 Indicator)
- Trust Boundary (서로 다른 network segments 또는 scopes.)
- Store (Databases와 같이 data가 저장되는 곳)

5. Threat 생성 (Step 1)

먼저 threat를 추가할 layer를 선택해야 합니다.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

이제 threat를 생성할 수 있습니다.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats와 Process Threats에는 차이가 있다는 점을 기억하세요. Actor에 threat를 추가하면 "Spoofing"과 "Repudiation만 선택할 수 있습니다. 그러나 이 example에서는 Process entity에 threat를 추가하므로 threat creation box에 다음과 같이 표시됩니다.

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 완료

이제 완성된 model은 다음과 같은 형태입니다. 이것이 OWASP Threat Dragon을 사용하여 간단한 threat model을 만드는 방법입니다.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft에서 제공하는 무료 tool로, software projects의 design phase에서 threats를 찾는 데 도움을 줍니다. STRIDE methodology를 사용하며 Microsoft stack에서 개발하는 사람들에게 특히 적합합니다.

{{#include ../banners/hacktricks-training.md}}
