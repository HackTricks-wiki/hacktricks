# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy machine learning

Najlepiej zacząć naukę o AI od poznania działania głównych algorytmów machine learning. Pomoże Ci to zrozumieć, jak działa AI, jak z niego korzystać i jak je atakować:


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

Na kolejnej stronie znajdziesz podstawowe informacje o każdym komponencie potrzebnym do zbudowania podstawowego LLM z użyciem transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezpieczeństwo AI

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne frameworki na początek do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 oraz Secure AI Framework (SAIF) firmy Google. Uzupełniają się, ale nie stanowią wyczerpującej listy frameworków oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM-y doprowadziły do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą adversarial prompts. To bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE modeli AI

Deweloperzy i firmy bardzo często uruchamiają modele pobrane z Internetu, jednak samo wczytanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Obejście KYC z pomocą AI

Generatywne wideo można połączyć z wstrzykiwaniem obrazu z wirtualnej kamery i manipulacją API kamery, aby ominąć słabo zabezpieczone procesy KYC, weryfikacji wieku i biometrycznego potwierdzania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) to otwarty protokół łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, ocena musi uwzględniać autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing z pomocą AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Reverse engineering z pomocą AI

[Partially lifting, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska oraz walidacja automatycznych extractorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do black-box pentestingu aplikacji webowych

Agenty oparte na LLM mogą automatyzować długotrwałe procesy black-box pentestingu aplikacji webowych, jeśli zapewni się im obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adversarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP: 10 najważniejszych zagadnień bezpieczeństwa machine learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — bezpieczny framework AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
