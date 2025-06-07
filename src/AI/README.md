# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Haupt-Maschinenlernalgorithmen

Der beste Ausgangspunkt, um über KI zu lernen, ist zu verstehen, wie die Hauptmaschinenlernalgorithmen funktionieren. Dies wird Ihnen helfen, zu verstehen, wie KI funktioniert, wie man sie nutzt und wie man sie angreift:

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

### LLMs Architektur

Auf der folgenden Seite finden Sie die Grundlagen jedes Komponenten, um ein einfaches LLM mit Transformatoren zu erstellen:

{{#ref}}
llm-architecture/README.md
{{#endref}}

## KI-Sicherheit

### KI-Risiko-Rahmenwerke

Im Moment sind die beiden Hauptrahmenwerke zur Bewertung der Risiken von KI-Systemen die OWASP ML Top 10 und das Google SAIF:

{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben die Nutzung von KI in den letzten Jahren explodieren lassen, aber sie sind nicht perfekt und können durch adversarielle Prompts getäuscht werden. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man KI sicher nutzt und wie man sie angreift:

{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE von KI-Modellen

Es ist sehr verbreitet, dass Entwickler und Unternehmen Modelle aus dem Internet herunterladen und ausführen. Allerdings kann das bloße Laden eines Modells ausreichen, um beliebigen Code auf dem System auszuführen. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man KI sicher nutzt und wie man sie angreift:

{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Protokoll für den Kontext von KI-Modellen

MCP (Model Context Protocol) ist ein Protokoll, das es KI-Agenten-Clients ermöglicht, sich auf eine Plug-and-Play-Art und Weise mit externen Tools und Datenquellen zu verbinden. Dies ermöglicht komplexe Arbeitsabläufe und Interaktionen zwischen KI-Modellen und externen Systemen:

{{#ref}}
AI-MCP-Servers.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
