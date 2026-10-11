# AI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtige Machine-Learning-Algorithmen

Am besten beginnst du mit dem Thema AI, indem du lernst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du verstehen, wie AI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

## AI-Sicherheit

### Methodik zur Sicherheit von AI Agents

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von AI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen einander, bilden aber keine vollständige Liste der AI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Sicherheit von AI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Verbreitung von AI geführt, sind aber nicht perfekt und lassen sich durch adversarial Prompts täuschen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du AI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-Modellen

Entwickler und Unternehmen führen häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Das bloße Laden eines Modells kann jedoch ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du AI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Mit AI unterstützte KYC-Umgehung

Generative Videos können mit Virtual-Camera-Injection und der Manipulation von Kamera-APIs kombiniert werden, um schwache KYC-, Altersverifikations- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll, mit dem AI-Anwendungen mit Tools und Datenquellen verbunden werden können. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Prüfungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Mit AI unterstütztes Fuzzing und automatisierte Schwachstellensuche


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Mit AI unterstütztes Reverse Engineering

[Partielles Lifting, Erkennung invarianten MBAs, umgebungsgebundene Dekodierung und Validierung automatisierter Extractor](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-Black-Box-AI-Pentester-Bots

LLM-gestützte Agents können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, Verwaltung authentifizierter Sessions und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 für Machine-Learning-Sicherheit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
