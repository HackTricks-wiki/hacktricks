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

### Przygotowanie i ewaluacja danych modelu

Informacje o podziale zbiorów danych, klasycznych metrykach i atakach na LLM-ową ocenę po stronie odpowiedzi znajdziesz w [przewodniku po przygotowaniu i ewaluacji danych modelu](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architektura LLM

Na poniższej stronie znajdziesz podstawowe informacje o każdym komponencie potrzebnym do zbudowania podstawowego LLM z użyciem transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Narzędzia i platformy AI

Aby uruchamiać, dostrajać, udostępniać lub wypróbowywać modele, skorzystaj z [przewodnika po narzędziach i platformach AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Granice zaufania w bramkach LLM

Informacje o bezpieczeństwie bramek znajdziesz tutaj:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 i Secure AI Framework (SAIF) Google. Uzupełniają się, ale nie stanowią wyczerpującej listy ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne sterowane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Granice zaufania w osadzonych przeglądarkach AI

Informacje o mostach przeglądarkowych asystentów desktopowych, spoofingu adresu karty i odczycie plików lokalnych w kontekście workera znajdziesz w [przewodniku po granicach zaufania w osadzonych przeglądarkach asystentów AI](AI-Embedded-Browser-Trust-Boundaries.md).

### Bezpieczeństwo promptów AI

W ostatnich latach LLM-y doprowadziły do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą promptów adwersarialnych. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Informacje o ryzyku ładowania modeli Keras `.keras`/HDF5, warstwach Lambda i analizie gadgetów po poprawkach znajdziesz w [przewodniku po deserializacji modeli Keras i wyszukiwaniu gadgetów](keras-model-deserialization-rce-and-gadget-hunting.md).

### AI-assisted KYC Bypass

Generowanie wideo można połączyć z wstrzykiwaniem wirtualnej kamery i manipulacją API kamery, aby ominąć słabe procesy KYC, weryfikacji wieku i biometrycznej weryfikacji żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

MCP (Model Context Protocol) to otwarty protokół łączenia aplikacji AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i funkcje, ocena bezpieczeństwa musi obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi i przegląd granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokół AI Agent-to-Agent (A2A)

A2A umożliwia agentom wzajemne odkrywanie się za pomocą karty agenta oraz przesyłanie sobie zadań przez HTTP. Testuj karty agentów, autoryzację zadań, webhooki powiadomień push i rozszerzone karty:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Udostępnione usługi AI hostowane samodzielnie

Fingerprinting i testowanie udostępnionych środowisk uruchomieniowych modeli, kreatorów agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych działających bez uwierzytelniania:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Przegląd kodu źródłowego i walidacja podatności wspomagane przez AI

Informacje o przeglądzie źródeł i sinków, przepływach zadań mobilnych punktów wejścia, audytach wzorców jądra i walidacji opartej na dowodach znajdziesz tutaj:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Częściowe lifting, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska i walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty pentesterskie AI do black-box testów aplikacji webowych

Agenci oparte na LLM-ach mogą automatyzować długotrwałe przepływy pracy związane z black-box pentestingiem aplikacji webowych, jeśli mają zapewnioną obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 bezpieczeństwa uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
