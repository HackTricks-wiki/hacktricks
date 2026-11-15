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

### Przygotowanie danych modelu i ewaluacja

Informacje o podziale zbiorów danych, klasycznych metrykach i atakach na etapie odpowiedzi w przypadku oceniania opartego na LLM znajdziesz w sekcji [przygotowanie danych modelu i ewaluacja](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architektura LLM

Na poniższej stronie znajdziesz podstawy dotyczące każdego komponentu potrzebnego do zbudowania podstawowego LLM z użyciem transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Narzędzia i platformy AI

Aby uruchamiać, dostrajać, udostępniać lub testować modele, skorzystaj z [przewodnika po narzędziach i platformach AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Granice zaufania w bramach LLM

Informacje o bezpieczeństwie bram znajdziesz tutaj:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodologia bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 i Secure AI Framework (SAIF) firmy Google. Uzupełniają się, ale nie stanowią wyczerpującego zestawu ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne ukierunkowane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Granice zaufania wbudowanej przeglądarki

Informacje o mostach przeglądarkowych asystentów desktopowych, podszywaniu się pod adres karty oraz odczycie plików lokalnych w kontekście workera znajdziesz w sekcji [granice zaufania wbudowanej przeglądarki asystenta AI](AI-Embedded-Browser-Trust-Boundaries.md).

### Bezpieczeństwo promptów AI

W ostatnich latach LLM przyczyniły się do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą promptów adwersarialnych. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Obejście KYC wspomagane przez AI

Generowanie wideo można połączyć z wstrzykiwaniem wirtualnej kamery i manipulacją API kamery, aby obejść słabe mechanizmy KYC, weryfikacji wieku i biometrycznej kontroli żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol dla AI

MCP (Model Context Protocol) to otwarty protokół łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, ocena bezpieczeństwa musi obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz przegląd granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokół AI Agent-to-Agent (A2A)

A2A umożliwia agentom wzajemne wykrywanie się za pomocą karty agenta i przesyłanie sobie zadań przez HTTP. Testuj karty agentów, autoryzację zadań, webhooki powiadomień push i karty rozszerzone:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Udostępnione samodzielnie hostowane usługi AI

Rozpoznawanie i testowanie udostępnionych runnerów modeli, narzędzi do tworzenia agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych działających bez uwierzytelniania:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Przegląd kodu źródłowego i walidacja podatności wspomagane przez AI

Informacje o przeglądzie źródeł i ujść, przepływach zadań dla mobilnych punktów wejścia, audytach wzorców jądra i walidacji opartej na dowodach znajdziesz tutaj:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Częściowe podnoszenie poziomu abstrakcji, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska i walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do web pentestów black-box

Agenci oparci na LLM mogą automatyzować długotrwałe przepływy pracy web pentestów black-box, jeśli są wspierani przez obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — 10 najważniejszych zagadnień bezpieczeństwa uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezpieczne ramy AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
