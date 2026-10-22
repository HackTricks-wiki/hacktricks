# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy uczenia maszynowego

Najlepiej zacząć naukę o AI od poznania działania głównych algorytmów uczenia maszynowego. Pomoże Ci to zrozumieć, jak działa AI, jak z niego korzystać i jak je atakować:


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

Na następnej stronie znajdziesz podstawowe informacje o każdym komponencie potrzebnym do zbudowania podstawowego LLM z użyciem transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Narzędzia i platformy do modeli

Aby uruchamiać, dostrajać, udostępniać lub testować modele, skorzystaj z [przewodnika po narzędziach i platformach do modeli AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Granice zaufania w bramach LLM

Informacje o bezpieczeństwie bram znajdziesz tutaj:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 i Secure AI Framework (SAIF) firmy Google. Uzupełniają się, ale nie stanowią wyczerpującego przeglądu ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne wspomagane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM-y znacznie upowszechniły wykorzystanie AI, ale nie są doskonałe i można je oszukać za pomocą adwersarialnych promptów. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Wspomagane przez AI obejście KYC

Generowanie wideo można połączyć z wstrzykiwaniem wirtualnej kamery i manipulacją API kamery, aby ominąć słabe procedury KYC, weryfikacji wieku i biometrycznego wykrywania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

MCP (Model Context Protocol) to otwarty protokół łączący aplikacje AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, ocena musi obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Wspomagane przez AI fuzzing i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Wspomagany przez AI przegląd kodu źródłowego i walidacja podatności

Informacje o przeglądzie source/sink, przepływach zadań dla mobilnych punktów wejścia, audytach wzorców jądra i walidacji opartej na dowodach znajdziesz tutaj:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Wspomniona przez AI inżynieria wsteczna

[Częściowe podnoszenie kodu, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska i walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do black-box pentestingu aplikacji webowych

Agenci oparte na LLM mogą automatyzować długotrwałe procesy black-box pentestingu aplikacji webowych, jeśli są wspierane przez obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 bezpieczeństwa uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezpieczne ramy AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
