# AI in 사이버 보안

{{#include ../banners/hacktricks-training.md}}

## 주요 Machine Learning 알고리즘

AI를 배우기 위한 가장 좋은 출발점은 주요 machine learning 알고리즘의 작동 방식을 이해하는 것입니다. 이를 통해 AI의 작동 방식과 사용법, 공격 방법을 이해할 수 있습니다:


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

다음 페이지에서 transformers를 사용해 기본적인 LLM을 구축하는 데 필요한 각 구성 요소의 기본 사항을 확인할 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## 모델 도구 및 플랫폼

모델을 실행하거나 fine-tuning, serving 또는 테스트하려면 [AI 모델 도구 및 플랫폼 가이드](AI-Model-Tools-and-Platforms.md)를 참고하세요.

## AI 보안

### AI Agent 보안 방법론

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 위험 프레임워크

AI 시스템의 위험을 평가할 때 유용한 출발점이 되는 프레임워크로 OWASP Machine Learning Security Top 10과 Google's Secure AI Framework (SAIF)가 있습니다. 두 프레임워크는 상호 보완적이며, AI 위험 프레임워크의 전체 목록은 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Mechanistic Interpretability 기반 적대적 공격

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### AI 프롬프트 보안

최근 몇 년간 LLM으로 AI 사용이 급증했지만, LLM은 완벽하지 않으며 적대적 프롬프트에 속을 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 모델 RCE

개발자와 기업이 인터넷에서 다운로드한 모델을 실행하는 일은 흔하지만, 모델을 불러오는 것만으로도 시스템에서 임의 코드를 실행할 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 지원 KYC 우회

생성형 비디오는 가상 카메라 주입 및 카메라 API 조작과 결합해 보안이 취약한 KYC, 연령 확인 및 생체 인식 라이브니스 절차를 우회할 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI 애플리케이션을 도구 및 데이터 소스에 연결하기 위한 공개 프로토콜입니다. MCP 서버는 데이터와 작업을 노출할 수 있으므로, 보안 평가에는 권한 부여, 동의, 도구 입력 검증 및 신뢰 경계 검토가 포함되어야 합니다.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 지원 퍼징 및 자동화된 취약점 탐색


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 지원 소스 검토 및 취약점 검증

source/sink 검토, 모바일 진입점 taskflow, 커널 패턴 감사 및 증거 기반 검증:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI 지원 리버스 엔지니어링

[부분 lifting, 불변식 MBA 탐지, 환경에 종속된 디코딩 및 자동 추출기 검증](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### 웹 블랙박스 AI Pentester 봇

LLM 기반 agent는 관측 가능성, 오케스트레이션, 인증된 세션 처리 및 적대적 검증이 지원될 경우 장시간 실행되는 블랙박스 웹 pentesting 워크플로를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 소개](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
