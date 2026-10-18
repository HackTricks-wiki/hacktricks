# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Zentrale Machine-Learning-Algorithmen

Am besten beginnst du mit dem Thema KI, indem du dich damit vertraut machst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. Das hilft dir zu verstehen, wie KI funktioniert, wie du sie einsetzt und wie du sie angreifen kannst:


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

Auf der folgenden Seite findest du die Grundlagen zu den einzelnen Komponenten, um mithilfe von Transformers ein einfaches LLM zu erstellen:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modell-Tools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen findest du hier den [Leitfaden zu KI-Modell-Tools und Plattformen](AI-Model-Tools-and-Platforms.md).

## KI-Sicherheit

### Methodik zur Sicherheit von KI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### KI-Risikoframeworks

Zwei nützliche Einstiegsframeworks zur Bewertung von Risiken in KI-Systemen sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen einander und stellen keine vollständige Liste von KI-Risikoframeworks dar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Adversarial Attacks mit Unterstützung durch mechanistische Interpretierbarkeit

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Zunahme der KI-Nutzung geführt. Sie sind jedoch nicht perfekt und lassen sich durch adversarial prompts täuschen. Dieses Thema ist besonders wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifen kannst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-Modellen

Entwickler und Unternehmen führen häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist besonders wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifen kannst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC-Umgehung mit Unterstützung durch KI

Generative Videos lassen sich mit virtueller Kamera-Injection und der Manipulation von Kamera-APIs kombinieren, um schwache KYC-, Altersverifikations- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol für KI

MCP (Model Context Protocol) ist ein offenes Protokoll, um KI-Anwendungen mit Tools und Datenquellen zu verbinden. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Sicherheitsbewertungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Fuzzing und automatisierte Schwachstellensuche mit Unterstützung durch KI


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Quellcodeanalyse und Schwachstellenvalidierung mit Unterstützung durch KI

Für die Analyse von Quellen und Senken, mobile Entry-Point-Taskflows, Kernel-Pattern-Audits und evidenzbasierte Validierung:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering mit Unterstützung durch KI

[Partielle Hebung, Erkennung invarianten MBA-Codes, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web-Black-Box-Pentester-Bots mit KI

LLM-gestützte Agenten können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, authentifizierte Sitzungsverwaltung und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres KI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
