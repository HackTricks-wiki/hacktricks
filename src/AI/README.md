# 사이버 보안에서의 AI

{{#include ../banners/hacktricks-training.md}}

## 주요 Machine Learning 알고리즘

AI를 학습하기 위한 가장 좋은 시작점은 주요 Machine Learning 알고리즘이 어떻게 작동하는지 이해하는 것입니다. 이를 통해 AI의 작동 방식, 사용 방법 및 공격 방법을 이해할 수 있습니다:


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

다음 페이지에서는 transformers를 사용하여 기본 LLM을 구축하는 데 필요한 각 구성 요소의 기초를 확인할 수 있습니다:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

현재 AI 시스템의 위험을 평가하는 주요 2가지 프레임워크는 OWASP ML Top 10과 Google SAIF입니다:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLM은 지난 몇 년 동안 AI의 사용을 폭발적으로 증가시켰지만 완벽하지 않으며 adversarial prompts를 통해 속일 수 있습니다. AI를 안전하게 사용하는 방법과 이를 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

개발자와 회사가 Internet에서 다운로드한 모델을 실행하는 것은 매우 일반적입니다. 그러나 모델을 로드하는 것만으로도 시스템에서 arbitrary code를 실행하기에 충분할 수 있습니다. AI를 안전하게 사용하는 방법과 이를 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol)는 AI agent client가 외부 도구와 data source에 plug-and-play 방식으로 연결할 수 있도록 하는 protocol입니다. 이를 통해 AI model과 외부 system 간의 복잡한 workflow와 상호작용이 가능해집니다:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

LLM 기반 agent는 observability, orchestration, authenticated session handling 및 adversarial validation을 통해 지원될 때 장시간 실행되는 black-box web pentesting workflow를 자동화할 수 있습니다:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
