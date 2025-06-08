# AI in Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Main Machine Learning Algorithms

AI에 대해 배우기 위한 가장 좋은 출발점은 주요 머신 러닝 알고리즘이 어떻게 작동하는지를 이해하는 것입니다. 이는 AI가 어떻게 작동하는지, 어떻게 사용하는지, 그리고 어떻게 공격하는지를 이해하는 데 도움이 됩니다:

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

다음 페이지에서는 변환기를 사용하여 기본 LLM을 구축하는 각 구성 요소의 기초를 찾을 수 있습니다:

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI Security

### AI Risk Frameworks

현재 AI 시스템의 위험을 평가하기 위한 주요 2가지 프레임워크는 OWASP ML Top 10과 Google SAIF입니다:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### AI Prompts Security

LLMs는 지난 몇 년 동안 AI 사용을 폭발적으로 증가시켰지만, 완벽하지 않으며 적대적인 프롬프트에 의해 속일 수 있습니다. 이는 AI를 안전하게 사용하는 방법과 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:

{{#ref}}
AI-Prompts.md
{{#endref}}

### AI Models RCE

개발자와 기업이 인터넷에서 다운로드한 모델을 실행하는 것은 매우 일반적이지만, 모델을 로드하는 것만으로도 시스템에서 임의의 코드를 실행할 수 있습니다. 이는 AI를 안전하게 사용하는 방법과 공격하는 방법을 이해하는 데 매우 중요한 주제입니다:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (모델 컨텍스트 프로토콜)는 AI 에이전트 클라이언트가 플러그 앤 플레이 방식으로 외부 도구 및 데이터 소스에 연결할 수 있도록 하는 프로토콜입니다. 이는 AI 모델과 외부 시스템 간의 복잡한 워크플로우 및 상호작용을 가능하게 합니다:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
