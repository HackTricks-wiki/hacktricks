# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtige Machine-Learning-Algorithmen

Am besten lernst du KI kennen, indem du verstehst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du nachvollziehen, wie KI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

Auf der folgenden Seite findest du die Grundlagen der einzelnen Komponenten, die du zum Aufbau eines einfachen LLM mit Transformers benötigst:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## KI-Sicherheit

### Methodik zur Sicherheit von KI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von KI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen einander und bilden keine vollständige Liste der KI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit gesteuerte adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Verbreitung von KI geführt. Sie sind jedoch nicht perfekt und lassen sich durch adversariale Prompts täuschen. Dieses Thema ist besonders wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE über KI-Modelle

Entwickler und Unternehmen führen häufig aus dem Internet heruntergeladene Modelle aus. Doch schon das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist besonders wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-gestützter KYC-Bypass

Generative Videos lassen sich mit virtueller Kameraeinspeisung und der Manipulation von Kamera-APIs kombinieren, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol für KI

MCP (Model Context Protocol) ist ein offenes Protokoll, über das sich KI-Anwendungen mit Tools und Datenquellen verbinden lassen. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Sicherheitsbewertungen Autorisierung, Einwilligung, die Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-gestütztes Fuzzing und automatisierte Schwachstellensuche


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gestützte Reverse-Engineering-Analyse

[Partielles Lifting, die Erkennung invariantenbasierter MBA-Ausdrücke, umgebungsgebundene Dekodierung und die Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### KI-Pentester-Bots für Black-Box-Webtests

LLM-gestützte Agenten können langwierige Black-Box-Web-Pentesting-Workflows automatisieren, sofern sie durch Observability, Orchestrierung, die Verwaltung authentifizierter Sitzungen und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 für Machine-Learning-Sicherheit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres KI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
