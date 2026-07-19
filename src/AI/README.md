# Cybersecurity에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 Machine Learning 알고리즘

AI를 배우기 위한 가장 좋은 출발점은 주요 machine learning 알고리즘이 어떻게 작동하는지 이해하는 것입니다. 이를 통해 AI의 작동 방식, 사용 방법 및 공격 방법을 이해할 수 있습니다:


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

### LLMs Architecture

다음 페이지에서는 transformers를 사용하여 기본 LLM을 구축하는 데 필요한 각 구성 요소의 기초를 확인할 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

현재 AI 시스템의 risks를 평가하기 위한 주요 framework는 OWASP ML Top 10과 Google SAIF입니다:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs로 인해 최근 몇 년 동안 AI 사용이 폭발적으로 증가했지만, LLMs는 완벽하지 않으며 adversarial prompts를 통해 속일 수 있습니다. AI를 안전하게 사용하는 방법과 AI를 공격하는 방법을 이해하기 위해 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

개발자와 기업이 Internet에서 다운로드한 models를 실행하는 것은 매우 일반적입니다. 그러나 model을 로드하는 것만으로도 시스템에서 arbitrary code를 실행하기에 충분할 수 있습니다. AI를 안전하게 사용하는 방법과 AI를 공격하는 방법을 이해하기 위해 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-Assisted KYC Bypass

Generative video는 virtual-camera injection 및 camera API manipulation과 결합하여 취약한 KYC, age-verification 및 biometric liveness workflow를 우회하는 데 사용될 수 있습니다:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI agent clients가 외부 tools 및 data sources에 plug-and-play 방식으로 연결할 수 있도록 하는 protocol입니다. 이를 통해 AI models와 외부 systems 간의 복잡한 workflows 및 interactions가 가능해집니다:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM-powered agents는 observability, orchestration, authenticated session handling 및 adversarial validation을 지원하는 경우 장시간 실행되는 black-box web pentesting workflows를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
