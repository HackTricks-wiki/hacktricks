# 사이버 보안에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 머신러닝 알고리즘

AI를 배우기 위한 가장 좋은 출발점은 주요 머신러닝 알고리즘의 작동 방식을 이해하는 것입니다. 이를 통해 AI의 작동 방식, 활용 방법, 공격 방법을 이해할 수 있습니다:


{{#ref}}
./AI-Supervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Unsupervised-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Reinforcement-Learning-Algorithms.md
{{#endref}}


{{#ref}}
./AI-Deep-Learning.md
{{#endref}}

### LLM 아키텍처

다음 페이지에서는 transformers를 사용해 기본적인 LLM을 구축하는 데 필요한 각 구성 요소의 기초를 확인할 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 모델 도구 및 플랫폼

모델을 실행하거나, fine-tuning하거나, serving하거나, 시험해 보려면 [AI 모델 도구 및 플랫폼 가이드](AI-Model-Tools-and-Platforms.md)를 참고하세요.

## AI 보안

### LLM Gateway 신뢰 경계

Gateway 보안에 대해서는 다음을 참고하세요:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent 보안 방법론

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 위험 프레임워크

AI 시스템 위험을 평가할 때 유용한 시작점이 되는 두 가지 프레임워크는 OWASP Machine Learning Security Top 10과 Google의 Secure AI Framework (SAIF)입니다. 두 프레임워크는 서로 보완적이며, AI 위험 프레임워크를 모두 포괄하는 목록은 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 기계론적 해석 가능성 기반 적대적 공격

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI 프롬프트 보안

최근 몇 년 사이 LLM의 등장으로 AI 사용이 급증했지만, LLM은 완벽하지 않으며 적대적 프롬프트로 속일 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하려면 이 주제를 알아두는 것이 매우 중요합니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 모델 RCE

개발자와 기업이 인터넷에서 다운로드한 모델을 실행하는 경우는 매우 흔합니다. 하지만 모델을 로드하는 것만으로 시스템에서 임의의 코드가 실행될 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하려면 이 주제를 알아두는 것이 매우 중요합니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 지원 KYC 우회

생성형 비디오는 가상 카메라 인젝션 및 카메라 API 조작과 결합해 취약한 KYC, 연령 확인, 생체 인식 라이브니스 검증 절차를 우회하는 데 사용될 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI 애플리케이션을 도구와 데이터 소스에 연결하기 위한 개방형 프로토콜입니다. MCP 서버는 데이터와 작업을 노출할 수 있으므로, 평가 시 권한 부여, 동의, 도구 입력 검증, 신뢰 경계 검토를 포함해야 합니다.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent 간 (A2A) 프로토콜

A2A를 사용하면 agent가 agent card를 통해 서로를 검색하고 HTTP로 작업을 주고받을 수 있습니다. agent card, 작업 권한 부여, 푸시 알림 webhook, 확장 card를 테스트하세요:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 노출된 자체 호스팅 AI 서비스

인증 없이 실행되는 노출된 모델 runner, agent builder, ML 데모 UI, 컴퓨팅 클러스터, 벡터 데이터베이스를 식별하고 테스트합니다:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI 지원 Fuzzing 및 자동화된 취약점 탐지


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 지원 소스 검토 및 취약점 검증

소스/sink 검토, 모바일 진입점 작업 흐름, 커널 패턴 감사, 증거 기반 검증에 대해서는 다음을 참고하세요:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 지원 리버스 엔지니어링

[부분 lifting, invariant MBA 탐지, 환경 종속 디코딩, 자동 extractor 검증](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### 웹 블랙박스 AI Pentester 봇

LLM 기반 agent는 관측 가능성, 오케스트레이션, 인증된 세션 처리, 적대적 검증이 지원될 경우 장시간 실행되는 블랙박스 웹 pentesting 작업 흐름을 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 머신러닝 보안 Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 보안 AI 프레임워크 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 소개](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
