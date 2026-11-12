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

### Przygotowanie i ocena danych modelu

Informacje o podziale zbiorów danych, klasycznych metrykach i atakach po stronie odpowiedzi na ocenianie oparte na LLM znajdziesz w [przewodniku po przygotowaniu i ocenie danych modelu](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### Architektura LLM

Na poniższej stronie znajdziesz podstawowe informacje o każdym komponencie potrzebnym do zbudowania podstawowego LLM z użyciem transformerów:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Narzędzia i platformy do modeli

Aby uruchamiać, dostrajać, udostępniać lub testować modele, skorzystaj z [przewodnika po narzędziach i platformach do modeli AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Granice zaufania bramek LLM

Informacje o bezpieczeństwie bramek znajdziesz tutaj:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne zestawy ram do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 i Secure AI Framework (SAIF) Google. Uzupełniają się, ale nie stanowią wyczerpującej listy ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne ukierunkowane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM przyczyniły się do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą adwersarialnych promptów. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Obejście KYC wspomagane przez AI

Generowanie wideo można połączyć z wstrzykiwaniem wirtualnej kamery i manipulacją API kamery, aby ominąć słabe mechanizmy KYC, weryfikacji wieku i biometrycznego wykrywania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol w AI

MCP (Model Context Protocol) to otwarty protokół łączący aplikacje AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i akcje, oceny bezpieczeństwa muszą uwzględniać autoryzację, zgodę, walidację danych wejściowych narzędzi i analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokół agent-agent (A2A) AI

A2A umożliwia agentom odnajdywanie się za pomocą karty agenta i przesyłanie sobie zadań przez HTTP. Testuj karty agentów, autoryzację zadań, webhooki powiadomień push i rozszerzone karty:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Ujawnione samodzielnie hostowane usługi AI

Rozpoznawanie i testowanie ujawnionych narzędzi do uruchamiania modeli, kreatorów agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych działających bez uwierzytelniania:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Przegląd kodu źródłowego i weryfikacja podatności wspomagane przez AI

Informacje o analizie źródeł i miejsc docelowych, przepływach zadań dotyczących mobilnych punktów wejścia, audytach wzorców jądra i weryfikacji wymagającej dowodów znajdziesz tutaj:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Inżynieria odwrotna wspomagana przez AI

[Częściowe podnoszenie poziomu abstrakcji, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska i walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do web pentestów black-box

Agenci oparte na LLM mogą automatyzować długotrwałe przepływy pracy związane z web pentestami black-box, jeśli zapewniono im obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP — 10 najważniejszych zagadnień bezpieczeństwa uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — bezpieczne ramy dla AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
