# 사이버 보안에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 머신러닝 알고리즘

AI를 배우기 위한 가장 좋은 출발점은 주요 머신러닝 알고리즘의 작동 방식을 이해하는 것입니다. 이를 통해 AI의 작동 방식과 사용법, 공격 방법을 이해할 수 있습니다:


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

다음 페이지에서는 transformers를 사용해 기본 LLM을 구축하는 데 필요한 각 구성 요소의 기초를 알아볼 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI 보안

### AI Agent 보안 방법론

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI 위험 프레임워크

AI 시스템의 위험을 평가할 때 유용한 출발점이 되는 프레임워크로는 OWASP Machine Learning Security Top 10과 Google의 Secure AI Framework (SAIF)가 있습니다. 이 두 프레임워크는 서로 보완적이며, AI 위험 프레임워크를 모두 망라하지는 않습니다.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI 프롬프트 보안

지난 몇 년 동안 LLM의 등장으로 AI 사용이 급증했지만, LLM은 완벽하지 않으며 adversarial prompt에 속을 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI 모델 RCE

개발자와 기업이 인터넷에서 다운로드한 모델을 실행하는 일은 흔합니다. 하지만 모델을 로드하는 것만으로도 시스템에서 임의 코드를 실행할 수 있습니다. AI를 안전하게 사용하고 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 지원 KYC 우회

생성형 비디오는 virtual-camera injection 및 camera API 조작과 결합해 보안이 취약한 KYC, 연령 확인, 생체 인식 liveness 절차를 우회하는 데 사용될 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI 애플리케이션을 도구 및 데이터 소스에 연결하기 위한 개방형 프로토콜입니다. MCP 서버는 데이터와 작업 기능을 노출할 수 있으므로, 평가 시 권한 부여, 동의, 도구 입력 검증, trust boundary 검토를 포함해야 합니다.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 지원 Fuzzing 및 자동화된 취약점 탐지


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 지원 Reverse Engineering

[부분 lifting, invariant MBA 탐지, 환경 바인딩 디코딩, 자동 추출기 검증](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester 봇

LLM 기반 agent는 observability, orchestration, 인증된 세션 처리, adversarial validation을 지원받으면 장시간 실행되는 black-box 웹 pentesting 워크플로를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP 머신러닝 보안 Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — 보안 AI 프레임워크 (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — 소개](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
