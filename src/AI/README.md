# 사이버 보안에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 Machine Learning 알고리즘

AI를 학습하기 위한 가장 좋은 시작점은 주요 Machine Learning 알고리즘이 어떻게 작동하는지 이해하는 것입니다. 이를 통해 AI의 작동 방식, AI 사용 방법 및 AI 공격 방법을 이해할 수 있습니다:


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

### LLMs 아키텍처

다음 페이지에서는 transformers를 사용하여 기본 LLM을 구축하는 데 필요한 각 구성 요소의 기초를 확인할 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI 보안

### AI Risk Frameworks

AI 시스템 위험을 평가하기 위한 유용한 출발점이 되는 두 가지 framework는 OWASP Machine Learning Security Top 10과 Google의 Secure AI Framework (SAIF)입니다. 이들은 상호 보완적이며, AI 위험 framework의 전체 목록은 아닙니다.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts 보안

LLM은 최근 몇 년 동안 AI 사용을 폭발적으로 증가시켰지만, 완벽하지 않으며 adversarial prompts를 통해 속일 수 있습니다. AI를 안전하게 사용하는 방법과 AI를 공격하는 방법을 이해하기 위해 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

개발자와 기업이 Internet에서 다운로드한 models를 실행하는 경우는 매우 흔합니다. 그러나 model을 로드하는 것만으로도 시스템에서 임의의 code를 실행하기에 충분할 수 있습니다. AI를 안전하게 사용하는 방법과 AI를 공격하는 방법을 이해하기 위해 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI 지원 KYC 우회

Generative video는 virtual-camera injection 및 camera API manipulation과 결합하여 취약한 KYC, age-verification 및 biometric liveness workflow를 우회하는 데 사용될 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI 애플리케이션을 tools 및 data sources에 연결하기 위한 open protocol입니다. MCP servers는 data와 actions를 노출할 수 있으므로, assessment에는 authorization, consent, tool-input validation 및 trust-boundary review가 포함되어야 합니다.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI 지원 Fuzzing 및 자동화된 Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI 지원 Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding 및 automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM 기반 agents는 observability, orchestration, authenticated session handling 및 adversarial validation의 지원을 받을 경우 장시간 실행되는 black-box web pentesting workflow를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
