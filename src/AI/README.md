# AI w Cybersecurity

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy Machine Learning

Najlepszym punktem wyjścia do nauki o AI jest zrozumienie działania głównych algorytmów machine learning. Pomoże Ci to zrozumieć, jak działa AI, jak go używać i jak je atakować:


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

### Architektura LLM

Na poniższej stronie znajdziesz podstawy każdego komponentu potrzebnego do zbudowania podstawowego LLM przy użyciu transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezpieczeństwo AI

### Frameworki ryzyka AI

Obecnie dwoma głównymi frameworkami służącymi do oceny ryzyka systemów AI są OWASP ML Top 10 i Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezpieczeństwo promptów AI

LLM spowodowały gwałtowny wzrost wykorzystania AI w ostatnich latach, ale nie są idealne i można je oszukać za pomocą adversarial prompts. Jest to bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie używać AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy bardzo często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. Jest to bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie używać AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) to protokół, który pozwala klientom agentów AI łączyć się z zewnętrznymi narzędziami i źródłami danych w sposób plug-and-play. Umożliwia to tworzenie złożonych workflow oraz interakcji między modelami AI a systemami zewnętrznymi:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Assisted Fuzzing & Automated Vulnerability Discovery


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web Black-Box AI Pentester Bots

Agenty oparte na LLM mogą automatyzować długotrwałe workflow black-box web pentestingu, gdy są wspierane przez observability, orkiestrację, obsługę uwierzytelnionych sesji i adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
