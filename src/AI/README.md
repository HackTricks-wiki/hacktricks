# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy uczenia maszynowego

Najlepiej zacząć naukę o AI od zrozumienia działania głównych algorytmów uczenia maszynowego. Pomoże Ci to zrozumieć, jak działa AI, jak z niego korzystać i jak je atakować:


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

## Narzędzia i platformy modeli

Do uruchamiania, dostrajania, udostępniania lub testowania modeli skorzystaj z [przewodnika po narzędziach i platformach modeli AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 oraz Secure AI Framework (SAIF) firmy Google. Uzupełniają się one, ale nie stanowią wyczerpującego zestawu ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne wspomagane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM-y doprowadziły do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą adwersarialnych promptów. To bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, pozwalający zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Omijanie KYC wspomagane przez AI

Generowanie wideo można połączyć z wstrzykiwaniem obrazu z wirtualnej kamery i manipulacją API kamery, aby ominąć słabe mechanizmy KYC, weryfikacji wieku i biometrycznego wykrywania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol dla AI

MCP (Model Context Protocol) to otwarty protokół służący do łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i umożliwiać wykonywanie działań, ocena musi uwzględniać autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing i automatyczne wykrywanie podatności wspomagane przez AI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Częściowe podnoszenie kodu, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska oraz walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do black-box pentestingu aplikacji webowych

Agenci wykorzystujący LLM-y mogą automatyzować długotrwałe procesy black-box pentestingu aplikacji webowych, jeśli zapewni się im obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
