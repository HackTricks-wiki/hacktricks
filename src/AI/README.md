# AI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Hauptalgorithmen des Machine Learning

Der beste Ausgangspunkt, um etwas über AI zu lernen, ist, zu verstehen, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. Dies hilft dir zu verstehen, wie AI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

### Architektur von LLMs

Auf der folgenden Seite findest du die Grundlagen jeder Komponente, um ein grundlegendes LLM mit Transformers zu erstellen:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI-Sicherheit

### AI-Risk-Frameworks

Derzeit sind die beiden wichtigsten Frameworks zur Bewertung der Risiken von AI-Systemen OWASP ML Top 10 und Google SAIF:


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicherheit von AI-Prompts

LLMs haben die Nutzung von AI in den letzten Jahren stark ausgeweitet, sind jedoch nicht perfekt und können durch adversarial Prompts getäuscht werden. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man AI sicher verwendet und wie man sie angreift:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-Modellen

Für Entwickler und Unternehmen ist es sehr üblich, aus dem Internet heruntergeladene Modelle auszuführen. Das bloße Laden eines Modells kann jedoch bereits ausreichen, um beliebigen Code auf dem System auszuführen. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man AI sicher verwendet und wie man sie angreift:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein Protokoll, das es AI-Agent-Clients ermöglicht, sich auf Plug-and-Play-Art mit externen Tools und Datenquellen zu verbinden. Dies ermöglicht komplexe Workflows und Interaktionen zwischen AI-Modellen und externen Systemen:


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-gestütztes Fuzzing & automatisierte Schwachstellenerkennung


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Web-Black-Box-AI-Pentester-Bots

LLM-gestützte Agents können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, authentifizierte Session-Verwaltung und adversarial Validation unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
