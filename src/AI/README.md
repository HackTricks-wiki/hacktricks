# 사이버 보안에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 머신러닝 알고리즘

AI를 배우기 위한 가장 좋은 출발점은 주요 머신러닝 알고리즘의 작동 방식을 이해하는 것입니다. 이를 통해 AI의 작동 방식과 활용법, 공격 방법을 이해할 수 있습니다:


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

### 모델 데이터 준비 및 평가

데이터셋 분할, 기존 지표, LLM 기반 채점에 대한 답변 측 공격은 [모델 데이터 준비 및 평가](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection)를 참조하세요.

### LLM 아키텍처

다음 페이지에서는 transformers를 사용해 기본 LLM을 구축하는 각 구성 요소의 기초를 알아볼 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 모델 도구 및 플랫폼

모델 실행, fine-tuning, 제공 또는 테스트에는 [AI 모델 도구 및 플랫폼 가이드](AI-Model-Tools-and-Platforms.md)를 사용하세요.

## AI 보안

### LLM Gateway 신뢰 경계

Gateway 보안은 다음을 참조하세요:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### AI Agent 보안 방법론

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 위험 프레임워크

AI 시스템 위험을 평가할 때 유용한 시작점이 되는 두 가지 프레임워크는 OWASP Machine Learning Security Top 10과 Google's Secure AI Framework (SAIF)입니다. 두 프레임워크는 상호 보완적이며, AI 위험 프레임워크의 전체 목록은 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### 메커니즘 해석 가능성 기반 적대적 공격

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI 프롬프트 보안

최근 몇 년 동안 LLM의 등장으로 AI 활용이 급증했지만, LLM은 완벽하지 않으며 적대적 프롬프트로 속일 수 있습니다. AI를 안전하게 활용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 모델 RCE

개발자와 기업이 인터넷에서 다운로드한 모델을 실행하는 일은 매우 흔합니다. 하지만 모델을 로드하는 것만으로도 시스템에서 임의의 코드를 실행할 수 있습니다. AI를 안전하게 활용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 지원 KYC 우회

생성형 비디오를 가상 카메라 주입 및 카메라 API 조작과 결합하면 취약한 KYC, 연령 확인, 생체 인식 라이브니스 워크플로를 우회할 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI 애플리케이션을 도구 및 데이터 소스에 연결하기 위한 개방형 프로토콜입니다. MCP 서버는 데이터와 작업을 노출할 수 있으므로, 평가 시 권한 부여, 동의, 도구 입력 검증, 신뢰 경계 검토를 포함해야 합니다.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent 간(A2A) 프로토콜

A2A를 사용하면 에이전트가 agent card를 통해 서로를 검색하고 HTTP로 작업을 주고받을 수 있습니다. agent card, 작업 권한 부여, push-notification 웹훅, 확장 카드 등을 테스트하세요:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### 외부에 노출된 자체 호스팅 AI 서비스

인증 없이 실행되는 노출된 모델 러너, agent 빌더, ML 데모 UI, 컴퓨팅 클러스터, 벡터 데이터베이스의 핑거프린팅 및 테스트:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI 지원 퍼징 및 자동화된 취약점 탐지


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 지원 소스 코드 검토 및 취약점 검증

소스/싱크 검토, 모바일 진입점 taskflow, 커널 패턴 감사, 증거 기반 검증은 다음을 참조하세요:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 지원 리버스 엔지니어링

[부분 리프팅, 불변식 MBA 탐지, 환경 종속 디코딩, 자동 추출기 검증](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### 웹 블랙박스 AI Pentester 봇

LLM 기반 에이전트는 관측성, 오케스트레이션, 인증된 세션 처리, 적대적 검증이 뒷받침되면 장시간 실행되는 블랙박스 웹 pentesting 워크플로를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP 머신러닝 보안 상위 10개 항목](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 보안 AI 프레임워크 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 소개](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
