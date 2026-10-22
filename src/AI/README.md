# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Am besten beginnst du mit dem Thema KI, indem du verstehst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du nachvollziehen, wie KI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

Auf der folgenden Seite findest du die Grundlagen zu jeder Komponente, die zum Aufbau eines einfachen LLM mit Transformers erforderlich ist:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modell-Tools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen findest du hier den [Leitfaden zu KI-Modell-Tools und -Plattformen](AI-Model-Tools-and-Platforms.md).

## KI-Sicherheit

### Vertrauensgrenzen von LLM-Gateways

Informationen zur Gateway-Sicherheit findest du hier:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Methodik zur Sicherheit von KI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-Risik frameworks

Zwei hilfreiche Frameworks für den Einstieg in die Bewertung von KI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen sich und bilden keine vollständige Liste der KI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit geleitete adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Zunahme der KI-Nutzung geführt. Sie sind jedoch nicht perfekt und können durch adversariale Prompts manipuliert werden. Das ist ein sehr wichtiges Thema, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE über KI-Modelle

Entwickler und Unternehmen führen sehr häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Das ist ein sehr wichtiges Thema, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KI-gestützter KYC-Bypass

Generierte Videos lassen sich mit der Einspeisung einer virtuellen Kamera und der Manipulation der Kamera-API kombinieren, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol für KI

MCP (Model Context Protocol) ist ein offenes Protokoll, über das KI-Anwendungen mit Tools und Datenquellen verbunden werden. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Sicherheitsanalysen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-gestütztes Fuzzing und automatisierte Schwachstellensuche


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gestützte Quellcodeprüfung und Schwachstellenvalidierung

Für die Prüfung von Quellen und Senken, Taskflows für mobile Einstiegspunkte, Audits von Kernel-Mustern und evidenzgestützte Validierung:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-gestütztes Reverse Engineering

[Partielle Hebung, Erkennung invarianten MBA-Codes, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Black-Box-KI-Pentester-Bots für Webanwendungen

LLM-gestützte Agenten können langwierige Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Beobachtbarkeit, Orchestrierung, authentifizierte Sitzungsverwaltung und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine-Learning-Security-Top-10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres KI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
