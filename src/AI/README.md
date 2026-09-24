# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy uczenia maszynowego

Najlepszym punktem wyjścia do nauki o AI jest zrozumienie działania głównych algorytmów uczenia maszynowego. Pomoże Ci to zrozumieć, jak działa AI, jak go używać i jak je atakować:


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

Na poniższej stronie znajdziesz podstawy każdego komponentu potrzebnego do zbudowania podstawowego LLM z użyciem transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezpieczeństwo AI

### Frameworki ryzyka AI

Dwa przydatne frameworki na początek do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 oraz Google's Secure AI Framework (SAIF). Uzupełniają się one, zamiast stanowić wyczerpującą listę frameworków ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


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

Generative video można łączyć z virtual-camera injection i manipulacją camera API w celu ominięcia słabych mechanizmów KYC, weryfikacji wieku i biometrycznych procedur liveness:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

MCP (Model Context Protocol) to otwarty protokół służący do łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, oceny muszą obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing wspomagany przez AI i zautomatyzowane wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Częściowe lifting, wykrywanie niezmienniczego MBA, dekodowanie zależne od środowiska i walidacja automated-extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Webowe boty black-box AI pentester

Agenci zasilani przez LLM mogą automatyzować długotrwałe procesy black-box web pentesting, jeśli zapewni się im obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i adversarial validation:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
