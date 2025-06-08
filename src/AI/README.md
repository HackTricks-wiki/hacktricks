# AI w Cyberbezpieczeństwie

{{#include ../banners/hacktricks-training.md}}

## Główne Algorytmy Uczenia Maszynowego

Najlepszym punktem wyjścia do nauki o AI jest zrozumienie, jak działają główne algorytmy uczenia maszynowego. Pomoże to zrozumieć, jak działa AI, jak go używać i jak je atakować:

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

Na następnej stronie znajdziesz podstawy każdego komponentu do zbudowania podstawowego LLM przy użyciu transformerów:

{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Bezpieczeństwo AI

### Ramy Ryzyka AI

W tej chwili główne 2 ramy do oceny ryzyk systemów AI to OWASP ML Top 10 i Google SAIF:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Bezpieczeństwo Podpowiedzi AI

LLM sprawiły, że użycie AI eksplodowało w ostatnich latach, ale nie są one doskonałe i mogą być oszukiwane przez wrogie podpowiedzi. To bardzo ważny temat, aby zrozumieć, jak używać AI bezpiecznie i jak je atakować:

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE Modeli AI

Bardzo powszechne jest, że deweloperzy i firmy uruchamiają modele pobrane z Internetu, jednak samo załadowanie modelu może być wystarczające do wykonania dowolnego kodu w systemie. To bardzo ważny temat, aby zrozumieć, jak używać AI bezpiecznie i jak je atakować:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protokół Kontekstowy Modelu AI

MCP (Model Context Protocol) to protokół, który pozwala klientom agentów AI łączyć się z zewnętrznymi narzędziami i źródłami danych w sposób plug-and-play. Umożliwia to złożone przepływy pracy i interakcje między modelami AI a systemami zewnętrznymi:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
