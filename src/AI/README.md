# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy machine learning

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

Dwa przydatne frameworki na początek do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 oraz Secure AI Framework (SAIF) firmy Google. Uzupełniają się one wzajemnie, ale nie stanowią wyczerpującej listy frameworków ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezpieczeństwo promptów AI

LLM spowodowały gwałtowny wzrost wykorzystania AI w ostatnich latach, ale nie są doskonałe i można je oszukać za pomocą adversarial prompts. Jest to bardzo ważny temat pozwalający zrozumieć, jak bezpiecznie używać AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE modeli AI

Deweloperzy i firmy bardzo często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. Jest to bardzo ważny temat pozwalający zrozumieć, jak bezpiecznie używać AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Omijanie KYC wspomagane przez AI

Generative video można połączyć z virtual-camera injection i manipulacją camera API, aby ominąć słabe procedury KYC, weryfikacji wieku i biometrycznego wykrywania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

MCP (Model Context Protocol) to otwarty protokół służący do łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i wykonywać działania, oceny muszą obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Webowe black-box AI pentester bots

Agenci wykorzystujący LLM mogą automatyzować długotrwałe procesy black-box web pentesting, gdy są wspierani przez obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji oraz adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
