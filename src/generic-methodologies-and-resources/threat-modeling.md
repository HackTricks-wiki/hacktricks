# 위협 모델링

## 위협 모델링

HackTricks의 포괄적인 위협 모델링 가이드에 오신 것을 환영합니다! 시스템의 잠재적 취약점을 식별하고 이해하며 전략을 세우는 사이버 보안의 이 중요한 측면을 탐구해 보세요. 이 스레드는 실제 사례, 유용한 소프트웨어 및 이해하기 쉬운 설명으로 가득 찬 단계별 가이드 역할을 합니다. 초보자와 경험이 풍부한 실무자 모두에게 사이버 보안 방어를 강화하는 데 이상적입니다.

### 일반적으로 사용되는 시나리오

1. **소프트웨어 개발**: 안전한 소프트웨어 개발 생명 주기(SSDLC)의 일환으로, 위협 모델링은 개발 초기 단계에서 **잠재적 취약점의 출처를 식별하는 데 도움**을 줍니다.
2. **침투 테스트**: 침투 테스트 실행 표준(PTES) 프레임워크는 테스트를 수행하기 전에 **시스템의 취약점을 이해하기 위한 위협 모델링**을 요구합니다.

### 위협 모델 요약

위협 모델은 일반적으로 애플리케이션의 계획된 아키텍처 또는 기존 빌드를 나타내는 다이어그램, 이미지 또는 기타 형태의 시각적 설명으로 표현됩니다. 이는 **데이터 흐름 다이어그램**과 유사하지만, 주요 차이점은 보안 지향적인 설계에 있습니다.

위협 모델은 종종 빨간색으로 표시된 요소를 특징으로 하며, 이는 잠재적 취약점, 위험 또는 장벽을 상징합니다. 위험 식별 프로세스를 간소화하기 위해 CIA(기밀성, 무결성, 가용성) 삼각형이 사용되며, 이는 많은 위협 모델링 방법론의 기초를 형성하고 STRIDE가 가장 일반적인 방법론 중 하나입니다. 그러나 선택된 방법론은 특정 맥락과 요구 사항에 따라 달라질 수 있습니다.

### CIA 삼각형

CIA 삼각형은 정보 보안 분야에서 널리 인정받는 모델로, 기밀성, 무결성 및 가용성을 나타냅니다. 이 세 가지 기둥은 많은 보안 조치 및 정책이 구축되는 기초를 형성하며, 위협 모델링 방법론도 포함됩니다.

1. **기밀성**: 데이터나 시스템이 무단 개인에 의해 접근되지 않도록 보장합니다. 이는 보안의 중심 측면으로, 데이터 유출을 방지하기 위해 적절한 접근 제어, 암호화 및 기타 조치를 요구합니다.
2. **무결성**: 데이터의 정확성, 일관성 및 신뢰성을 보장합니다. 이 원칙은 데이터가 무단 당사자에 의해 변경되거나 변조되지 않도록 합니다. 종종 체크섬, 해싱 및 기타 데이터 검증 방법이 포함됩니다.
3. **가용성**: 데이터와 서비스가 필요할 때 승인된 사용자에게 접근 가능하도록 보장합니다. 이는 종종 중복성, 내결함성 및 고가용성 구성을 포함하여 시스템이 중단 상황에서도 계속 작동하도록 합니다.

### 위협 모델링 방법론

1. **STRIDE**: Microsoft에서 개발한 STRIDE는 **스푸핑, 변조, 부인, 정보 공개, 서비스 거부 및 권한 상승**의 약어입니다. 각 카테고리는 위협의 유형을 나타내며, 이 방법론은 프로그램 또는 시스템의 설계 단계에서 잠재적 위협을 식별하는 데 일반적으로 사용됩니다.
2. **DREAD**: 이는 식별된 위협의 위험 평가에 사용되는 Microsoft의 또 다른 방법론입니다. DREAD는 **손상 가능성, 재현성, 악용 가능성, 영향을 받는 사용자 및 발견 가능성**의 약어입니다. 이러한 각 요소는 점수를 매기고, 결과는 식별된 위협의 우선 순위를 정하는 데 사용됩니다.
3. **PASTA** (공격 시뮬레이션 및 위협 분석 프로세스): 이는 **위험 중심**의 7단계 방법론입니다. 보안 목표 정의 및 식별, 기술 범위 생성, 애플리케이션 분해, 위협 분석, 취약점 분석 및 위험/분류 평가를 포함합니다.
4. **Trike**: 이는 자산 방어에 중점을 둔 위험 기반 방법론입니다. **위험 관리** 관점에서 시작하여 그 맥락에서 위협과 취약점을 살펴봅니다.
5. **VAST** (시각적, 민첩하고 간단한 위협 모델링): 이 접근 방식은 더 접근 가능하도록 하며 민첩한 개발 환경에 통합됩니다. 다른 방법론의 요소를 결합하고 **위협의 시각적 표현**에 중점을 둡니다.
6. **OCTAVE** (운영상 중요한 위협, 자산 및 취약점 평가): CERT 조정 센터에서 개발한 이 프레임워크는 **특정 시스템이나 소프트웨어보다는 조직의 위험 평가**에 중점을 둡니다.

## 도구

위협 모델의 생성 및 관리를 **지원**할 수 있는 여러 도구와 소프트웨어 솔루션이 있습니다. 고려해 볼 수 있는 몇 가지는 다음과 같습니다.

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

사이버 보안 전문가를 위한 고급 크로스 플랫폼 및 다기능 GUI 웹 스파이더/크롤러입니다. Spider Suite는 공격 표면 매핑 및 분석에 사용될 수 있습니다.

**사용법**

1. URL 선택 및 크롤링

<figure><img src="../images/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. 그래프 보기

<figure><img src="../images/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASP의 오픈 소스 프로젝트로, Threat Dragon은 시스템 다이어그램 작성과 위협/완화 자동 생성을 위한 규칙 엔진을 포함하는 웹 및 데스크톱 애플리케이션입니다.

**사용법**

1. 새 프로젝트 생성

<figure><img src="../images/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

때때로 이렇게 보일 수 있습니다:

<figure><img src="../images/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 새 프로젝트 시작

<figure><img src="../images/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 새 프로젝트 저장

<figure><img src="../images/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. 모델 생성

SpiderSuite Crawler와 같은 도구를 사용하여 영감을 얻을 수 있으며, 기본 모델은 다음과 같이 보일 수 있습니다.

<figure><img src="../images/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

엔터티에 대한 간단한 설명:

- 프로세스 (웹 서버 또는 웹 기능과 같은 엔터티 자체)
- 액터 (웹사이트 방문자, 사용자 또는 관리자와 같은 사람)
- 데이터 흐름 라인 (상호작용의 지표)
- 신뢰 경계 (다른 네트워크 세그먼트 또는 범위)
- 저장소 (데이터가 저장되는 장소, 예: 데이터베이스)

5. 위협 생성 (1단계)

먼저 위협을 추가할 레이어를 선택해야 합니다.

<figure><img src="../images/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

이제 위협을 생성할 수 있습니다.

<figure><img src="../images/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

액터 위협과 프로세스 위협 간에는 차이가 있다는 점을 기억하세요. 액터에 위협을 추가하면 "스푸핑"과 "부인"만 선택할 수 있습니다. 그러나 우리의 예에서는 프로세스 엔터티에 위협을 추가하므로 위협 생성 상자에서 다음과 같이 볼 수 있습니다:

<figure><img src="../images/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 완료

이제 완성된 모델은 다음과 같이 보일 것입니다. 이것이 OWASP Threat Dragon으로 간단한 위협 모델을 만드는 방법입니다.

<figure><img src="../images/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>

### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

이는 소프트웨어 프로젝트의 설계 단계에서 위협을 찾는 데 도움을 주는 Microsoft의 무료 도구입니다. STRIDE 방법론을 사용하며, Microsoft 스택에서 개발하는 사람들에게 특히 적합합니다.
