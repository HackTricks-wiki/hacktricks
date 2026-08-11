# Threat Modeling

{{#include ../banners/hacktricks-training.md}}

HackTricks의 포괄적인 Threat Modeling 가이드에 오신 것을 환영합니다! 시스템에서 발생할 수 있는 잠재적 취약점을 식별하고, 이해하며, 이에 대응하기 위한 전략을 수립하는 cybersecurity의 핵심 영역을 탐구해 보세요. 이 글은 실제 사례, 유용한 software, 이해하기 쉬운 설명을 포함한 단계별 가이드입니다. cybersecurity 방어를 강화하려는 초보자와 숙련된 실무자 모두에게 적합합니다.

### 일반적으로 사용되는 시나리오

1. **Software Development**: Secure Software Development Life Cycle (SSDLC)의 일부로서, threat modeling은 개발 초기 단계에서 **잠재적인 취약점의 원인을 식별**하는 데 도움이 됩니다.<sup>[[1]](#references)[[4]](#references)</sup>
2. **Penetration Testing**: Penetration Testing Execution Standard (PTES)은 올바른 실행을 위해 threat modeling을 필수 사항으로 다루며, business assets, business processes, threat communities 및 그들의 capabilities를 문서화하도록 요구합니다.<sup>[[2]](#references)</sup>

### Threat Model 한눈에 보기

Threat model은 일반적으로 계획된 architecture 또는 기존 application을 다이어그램, 이미지 또는 기타 시각적 표현으로 나타냅니다. Data-flow diagrams (DFDs)은 시스템과 시스템의 상호작용을 모델링하는 일반적인 방법이며, threat modeling은 여기에 security 중심의 분석을 추가합니다.<sup>[[1]](#references)</sup>

Microsoft's Threat Modeling Tool에서는 빨간색 점선이 trust boundaries를 나타내며, 다른 tools에서는 다른 시각적 규칙을 사용할 수 있습니다.<sup>[[4]](#references)</sup> 위험 식별을 간소화하기 위해 팀은 CIA (Confidentiality, Integrity, Availability) triad 또는 STRIDE threat categories를 사용할 수 있지만, 적절한 methodology는 project의 context와 requirements에 따라 달라집니다.<sup>[[1]](#references)[[3]](#references)[[10]](#references)</sup>

### CIA Triad

CIA Triad는 Confidentiality, Integrity, Availability를 의미하는 널리 알려진 information-security model입니다. 이러한 속성은 data와 systems의 security goals를 설명하는 데 일반적으로 사용됩니다.<sup>[[3]](#references)</sup>

1. **Confidentiality**: 권한이 없는 사용자가 data 또는 system에 접근하지 못하도록 보장합니다. 이는 data breaches를 방지하기 위해 적절한 access controls, encryption 및 기타 조치를 요구하는 security의 핵심 요소입니다.
2. **Integrity**: lifecycle 전반에 걸친 data의 정확성, 일관성 및 신뢰성입니다. 이 원칙은 권한이 없는 주체가 data를 변경하거나 변조하지 못하도록 보장합니다. 일반적으로 checksums, hashing 및 기타 data verification methods가 사용됩니다.
3. **Availability**: 필요한 경우 권한이 있는 사용자가 data와 services에 접근할 수 있도록 보장합니다. 시스템 중단 상황에서도 계속 작동하도록 redundancy, fault tolerance 및 high-availability configurations가 사용되는 경우가 많습니다.

### Threat Modeling Methodologies

1. **STRIDE**: Microsoft's STRIDE approach는 software threats를 **Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service 및 Elevation of Privilege**로 분류합니다. 이러한 categories는 analysts가 design의 각 취약 지점에서 발생할 수 있는 threats를 식별하는 데 도움을 줍니다.<sup>[[5]](#references)</sup>
2. **DREAD**: 이 Microsoft assessment approach는 **Damage, Reproducibility, Exploitability, Affected users 및 Discoverability**를 사용해 threats에 점수를 부여합니다. 결과 점수는 완화가 필요한 threats의 우선순위를 정하는 데 도움이 됩니다.<sup>[[5]](#references)</sup>
3. **PASTA** (Process for Attack Simulation and Threat Analysis): objectives, technical scope, application decomposition, threat analysis, vulnerability and weakness analysis, attack modeling 및 risk/impact analysis를 다루는 7단계의 **risk-centric** methodology입니다.<sup>[[8]](#references)</sup>
4. **Trike**: 이 security-audit framework는 **risk-management** 및 defensive 관점에서 threat modeling에 접근합니다.<sup>[[9]](#references)</sup>
5. **VAST** (Visual, Agile, and Simple Threat modeling): 이 method는 application 및 operational views를 위한 확장 가능하고 사용하기 쉬운 threat models를 강조하며, development 및 DevOps lifecycles와 통합할 수 있습니다.<sup>[[10]](#references)</sup>
6. **OCTAVE** (Operationally Critical Threat, Asset, and Vulnerability Evaluation): Carnegie Mellon's Software Engineering Institute의 CERT Division에서 만든 OCTAVE는 technology만이 아니라 organizational risk에 초점을 맞춘 risk-based strategic assessment 및 planning method입니다.<sup>[[10]](#references)</sup>

## Tools

Threat models의 생성과 관리를 **지원**할 수 있는 여러 tools 및 software solutions가 있습니다. 다음은 고려해 볼 만한 몇 가지 tools입니다.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

SpiderSuite는 security professionals를 위한 cross-platform web crawler로, attack-surface mapping, endpoint discovery 및 web-application analysis를 지원합니다.<sup>[[6]](#references)</sup>

**사용법**

1. URL을 선택하고 Crawl 실행

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. Graph 보기

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP Threat Dragon은 diagrams를 그리고, threats를 제안하며, mitigations를 기록할 수 있는 무료 open-source cross-platform threat-modeling application입니다. web application과 desktop application으로 제공됩니다.<sup>[[7]](#references)</sup>

**사용법**

1. New Project 생성

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

다음과 같은 형태로 표시될 수도 있습니다.

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. New Project 실행

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. New Project 저장

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. model 생성

SpiderSuite Crawler와 같은 tools를 사용해 영감을 얻을 수 있으며, 기본 model은 다음과 같은 형태입니다.

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

entities에 대한 간단한 설명은 다음과 같습니다.

- Process (Webserver 또는 web functionality와 같은 entity 자체)
- Actor (Website Visitor, User 또는 Administrator와 같은 사람)
- Data Flow Line (Interaction의 표시)
- Trust Boundary (서로 다른 network segments 또는 scopes)
- Store (Databases와 같이 data가 저장되는 곳)

5. Threat 생성 (Step 1)

먼저 threat를 추가할 layer를 선택해야 합니다.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

이제 threat를 생성할 수 있습니다.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

Actor Threats와 Process Threats 사이에는 차이가 있다는 점에 유의하세요. Actor에 threat를 추가하면 "Spoofing"과 "Repudiation"만 선택할 수 있습니다. 그러나 이 예제에서는 Process entity에 threat를 추가하므로 threat creation box에 다음과 같이 표시됩니다.

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 완료

이제 완성된 model은 다음과 같은 형태입니다. 이것이 OWASP Threat Dragon으로 간단한 threat model을 만드는 방법입니다.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

Microsoft's Threat Modeling Tool은 software design analysis를 위한 무료 downloadable tool입니다. 이 tool의 workflow는 diagram을 생성하고, threats를 식별하며, STRIDE approach를 사용해 mitigation과 validation을 지원합니다.<sup>[[4]](#references)</sup>

## References

- [1] [Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [2] [Threat Modeling - The Penetration Testing Execution Standard](https://www.pentest-standard.org/index.php/Threat_Modeling)
- [3] [Security fundamentals - OWASP Developer Guide](https://devguide.owasp.org/en/02-foundations/01-security-fundamentals/)
- [4] [Microsoft Threat Modeling Tool 시작하기](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-getting-started)
- [5] [Drivers를 위한 Threat Modeling - Windows drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/threat-modeling-for-drivers)
- [6] [SpiderSuite](https://spidersuite.io/)
- [7] [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon)
- [8] [PASTA Threat Modeling: 설명된 7단계](https://versprite.com/cybersecurity-listings/devsecops/pasta-threat-modeling/)
- [9] [Trike v1 Methodology Document](https://trike.sourceforge.net/papers/Trike_v1_Methodology_Document-draft.pdf)
- [10] [Threat Modeling: 사용 가능한 Methods 요약](https://www.sei.cmu.edu/documents/569/2018_019_001_524597.pdf)
{{#include ../banners/hacktricks-training.md}}
