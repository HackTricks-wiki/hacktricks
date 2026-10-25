# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy uczenia maszynowego

Najlepiej zacząć naukę o AI od zrozumienia, jak działają główne algorytmy uczenia maszynowego. Pomoże Ci to zrozumieć, jak działa AI, jak z niego korzystać i jak je atakować:


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

## Narzędzia i platformy modeli

Aby uruchamiać, dostrajać, udostępniać lub testować modele, skorzystaj z [przewodnika po narzędziach i platformach modeli AI](AI-Model-Tools-and-Platforms.md).

## Bezpieczeństwo AI

### Granice zaufania bram LLM

Informacje o bezpieczeństwie bram znajdziesz tutaj:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Metodyka bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 i Secure AI Framework (SAIF) firmy Google. Uzupełniają się, ale nie stanowią wyczerpującego zestawu ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne kierowane interpretowalnością mechanicystyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM doprowadziły do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą adwersarialnych promptów. To bardzo ważny temat, który pozwala zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Deweloperzy i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, który pozwala zrozumieć, jak bezpiecznie korzystać z AI i jak je atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Obejście KYC z użyciem AI

Generatywne wideo można połączyć z wstrzykiwaniem obrazu z wirtualnej kamery i manipulacją API kamery, aby omijać słabe mechanizmy KYC, weryfikacji wieku i biometrycznej kontroli żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol AI

MCP (Model Context Protocol) to otwarty protokół łączący aplikacje AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, ocena musi obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Protokół AI agent–agent (A2A)

A2A umożliwia agentom wzajemne odnajdywanie się za pomocą karty agenta i przesyłanie sobie zadań przez HTTP. Testuj karty agentów, autoryzację zadań, webhooki powiadomień push i rozszerzone karty:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Ujawnione, samodzielnie hostowane usługi AI

Rozpoznawanie i testowanie ujawnionych bez uwierzytelniania środowisk uruchomieniowych modeli, kreatorów agentów, interfejsów demonstracyjnych ML, klastrów obliczeniowych i baz danych wektorowych:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Analiza kodu źródłowego wspomagana przez AI i weryfikacja podatności

Informacje o analizie źródeł i ujść, przepływach zadań dla mobilnych punktów wejścia, audytach wzorców w jądrze oraz weryfikacji opartej na dowodach:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Częściowe podnoszenie poziomu abstrakcji, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska i walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty AI do black-box pentestingu aplikacji webowych

Agenci oparci na LLM mogą automatyzować długotrwałe przepływy pracy black-box pentestingu aplikacji webowych, jeśli zapewniono im obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [10 najważniejszych zagrożeń bezpieczeństwa uczenia maszynowego według OWASP](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezpieczne ramy AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
