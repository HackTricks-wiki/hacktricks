# AI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Zentrale Machine-Learning-Algorithmen

Am besten lernst du AI kennen, indem du verstehst, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du nachvollziehen, wie AI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

### Vorbereitung und Auswertung von Modelldaten

Informationen zu Dataset-Splits, klassischen Metriken und Answer-Side-Angriffen auf LLM-basiertes Grading findest du unter [Vorbereitung und Auswertung von Modelldaten](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-Architektur

Auf der folgenden Seite findest du die Grundlagen zu den einzelnen Komponenten, mit denen sich mithilfe von Transformers ein einfaches LLM erstellen lässt:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelltools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen findest du hier den [Leitfaden zu AI-Modelltools und Plattformen](AI-Model-Tools-and-Platforms.md).

## AI-Sicherheit

### Vertrauensgrenzen von LLM-Gateways

Informationen zur Gateway-Sicherheit findest du hier:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Methodik zur Sicherheit von AI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von Risiken bei AI-Systemen sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen sich, bilden aber keine vollständige Liste aller AI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit geleitete adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Vertrauensgrenzen eingebetteter Browser

Informationen zu Browser-Bridges von Desktop-Assistenten, Spoofing von Tab-Adressen und dem Auslesen lokaler Dateien aus Worker-Kontexten findest du unter [Vertrauensgrenzen eingebetteter Browser von AI-Assistenten](AI-Embedded-Browser-Trust-Boundaries.md).

### Sicherheit von AI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Zunahme des AI-Einsatzes geführt. Sie sind jedoch nicht perfekt und lassen sich durch adversariale Prompts täuschen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du AI sicher einsetzen und angreifen kannst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-Modellen

Entwickler und Unternehmen führen sehr häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du AI sicher einsetzen und angreifen kannst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Umgehung von KYC mithilfe von AI

Generative Videos lassen sich mit Virtual-Camera-Injection und der Manipulation von Camera-APIs kombinieren, um schwache KYC-, Altersverifikations- und biometrische Liveness-Prüfungen zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll, über das sich AI-Anwendungen mit Tools und Datenquellen verbinden lassen. Da MCP-Server Daten und Aktionen zugänglich machen können, müssen Prüfungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI Agent-to-Agent (A2A) Protocol

A2A ermöglicht es Agenten, sich über eine Agent Card gegenseitig zu entdecken und über HTTP Aufgaben zu senden. Prüfe Agent Cards, die Autorisierung von Aufgaben, Webhooks für Push-Benachrichtigungen und erweiterte Cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Offen zugängliche, selbst gehostete AI-Dienste

Fingerprinting und Tests exponierter Model-Runner, Agent-Builder, ML-Demo-UIs, Compute-Cluster und Vektordatenbanken, die ohne Authentifizierung betrieben werden:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### AI-gestütztes Fuzzing und automatisierte Schwachstellenerkennung


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### AI-gestützte Codeanalyse und Validierung von Schwachstellen

Informationen zur Prüfung von Quellen und Senken, Taskflows für mobile Einstiegspunkte, Audits von Kernel-Mustern und evidenzbasierter Validierung findest du hier:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### AI-gestütztes Reverse Engineering

[Partielles Lifting, Erkennung invarianten MBA-Codes, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Web Black-Box AI Pentester Bots

LLM-gestützte Agenten können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, die Verwaltung authentifizierter Sitzungen und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Machine-Learning-Security-Top-10](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres AI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
