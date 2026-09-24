# AI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Der beste Ausgangspunkt, um etwas über AI zu lernen, besteht darin, zu verstehen, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. Dies hilft dir zu verstehen, wie AI funktioniert, wie du sie einsetzen und wie du sie angreifen kannst:


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

### LLM-Architektur

Auf der folgenden Seite findest du die Grundlagen jeder Komponente, um mithilfe von Transformern ein einfaches LLM zu erstellen:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## AI-Sicherheit

### AI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von AI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen sich, stellen jedoch keine vollständige Liste von AI-Risikoframeworks dar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicherheit von AI-Prompts

LLMs haben die Nutzung von AI in den letzten Jahren explosionsartig ausgeweitet, sind jedoch nicht perfekt und können durch adversariale Prompts ausgetrickst werden. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man AI sicher einsetzt und wie man sie angreift:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-Modellen

Für Entwickler und Unternehmen ist es sehr üblich, aus dem Internet heruntergeladene Modelle auszuführen. Das bloße Laden eines Modells kann jedoch bereits ausreichen, um beliebigen Code auf dem System auszuführen. Dies ist ein sehr wichtiges Thema, um zu verstehen, wie man AI sicher einsetzt und wie man sie angreift:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### AI-gestützter KYC-Bypass

Generative Videos können mit Virtual-Camera-Injection und der Manipulation von Kamera-APIs kombiniert werden, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Workflows zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll zur Verbindung von AI-Anwendungen mit Tools und Datenquellen. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Assessments Autorisierung, Einwilligung, Validierung von Tool-Eingaben und eine Überprüfung von Trust Boundaries umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-gestütztes Fuzzing & automatisierte Schwachstellenerkennung


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-gestützte Reverse Engineering

[Partial lifting, invariant MBA detection, environment-bound decoding, and automated-extractor validation](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-Black-Box-AI-Pentester-Bots

LLM-gestützte Agents können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, die Verarbeitung authentifizierter Sessions und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Introduction](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
