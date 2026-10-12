# AI w cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne algorytmy uczenia maszynowego

Najlepiej zacząć naukę AI od zrozumienia działania głównych algorytmów uczenia maszynowego. Pomoże Ci to zrozumieć, jak działa AI, jak z niej korzystać i jak ją atakować:


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

Na poniższej stronie znajdziesz podstawy dotyczące poszczególnych komponentów potrzebnych do zbudowania podstawowego LLM z użyciem transformers:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezpieczeństwo AI

### Metodologia bezpieczeństwa agentów AI

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### Ramy oceny ryzyka AI

Dwa przydatne punkty wyjścia do oceny ryzyka systemów AI to OWASP Machine Learning Security Top 10 oraz Secure AI Framework (SAIF) firmy Google. Uzupełniają się one, ale nie stanowią wyczerpującej listy ram oceny ryzyka AI.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Ataki adwersarialne ukierunkowane interpretowalnością mechanistyczną

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Bezpieczeństwo promptów AI

W ostatnich latach LLM-y przyczyniły się do gwałtownego wzrostu wykorzystania AI, ale nie są doskonałe i można je oszukać za pomocą promptów adwersarialnych. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak ją atakować:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE w modelach AI

Programiści i firmy często uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może wystarczyć do wykonania dowolnego kodu w systemie. To bardzo ważny temat, jeśli chcesz zrozumieć, jak bezpiecznie korzystać z AI i jak ją atakować:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Obejście KYC wspomagane przez AI

Generowanie wideo można połączyć z wstrzykiwaniem obrazu z kamery wirtualnej i manipulowaniem API kamery, aby omijać słabe procedury KYC, weryfikacji wieku i biometrycznego wykrywania żywotności:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI i Model Context Protocol

MCP (Model Context Protocol) to otwarty protokół łączący aplikacje AI z narzędziami i źródłami danych. Ponieważ serwery MCP mogą udostępniać dane i działania, ocena bezpieczeństwa musi obejmować autoryzację, zgodę, walidację danych wejściowych narzędzi oraz analizę granic zaufania.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing wspomagany przez AI i automatyczne wykrywanie podatności


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Inżynieria wsteczna wspomagana przez AI

[Partiowe podnoszenie kodu, wykrywanie niezmienników MBA, dekodowanie zależne od środowiska oraz walidacja automatycznych ekstraktorów](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Boty pentesterskie AI typu black-box do testowania aplikacji webowych

Agenci oparci na LLM mogą automatyzować długotrwałe procesy pentestingu aplikacji webowych typu black-box, jeśli są wspierani przez obserwowalność, orkiestrację, obsługę uwierzytelnionych sesji i walidację adwersarialną:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 bezpieczeństwa uczenia maszynowego](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Bezpieczne ramy AI (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Wprowadzenie](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
