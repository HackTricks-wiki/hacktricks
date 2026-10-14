# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Am besten lernst du KI kennen, indem du verstehst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. Das hilft dir zu verstehen, wie KI funktioniert, wie du sie verwendest und wie du sie angreifst:


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

Auf der folgenden Seite findest du die Grundlagen der einzelnen Komponenten, um mit Transformers ein einfaches LLM zu erstellen:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modell-Tools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen verwende den [Leitfaden zu KI-Modell-Tools und Plattformen](AI-Model-Tools-and-Platforms.md).

## KI-Sicherheit

### Methodik zur Sicherheit von KI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von KI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen einander, stellen aber keine vollständige Liste der KI-Risikoframeworks dar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit gesteuerte adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Verbreitung von KI geführt, sind jedoch nicht perfekt und können durch adversariale Prompts getäuscht werden. Dieses Thema ist sehr wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-Modellen

Entwickler und Unternehmen führen häufig aus dem Internet heruntergeladene Modelle aus. Das bloße Laden eines Modells kann jedoch ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-gestützte Umgehung von KYC

Generative Videos lassen sich mit der Einspeisung virtueller Kameras und der Manipulation von Kamera-APIs kombinieren, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Prozesse zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### KI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll, über das sich KI-Anwendungen mit Tools und Datenquellen verbinden lassen. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Sicherheitsbewertungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen berücksichtigen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-gestütztes Fuzzing und automatisierte Schwachstellensuche


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gestützte Reverse-Engineering-Analyse

[Partielles Lifting, Erkennung invarianten MBA-Codes, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### KI-Pentester-Bots für Web-Pentests in der Black Box

LLM-gestützte Agenten können langwierige Web-Pentesting-Workflows in der Black Box automatisieren, wenn sie durch Observability, Orchestrierung, authentifizierte Sitzungsverwaltung und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 für Machine-Learning-Sicherheit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres KI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
