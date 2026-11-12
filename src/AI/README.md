# AI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Der beste Einstieg in AI ist, zu verstehen, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So lernst du, wie AI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

### Aufbereitung und Auswertung von Modelldaten

Informationen zu Dataset-Splits, klassischen Metriken und Answer-Side-Angriffen auf LLM-basiertes Grading findest du unter [Aufbereitung und Auswertung von Modelldaten](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-Architektur

Auf der folgenden Seite findest du die Grundlagen zu jeder Komponente, die du zum Aufbau eines einfachen LLM mit Transformers benötigst:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Model-Tools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen kannst du den [Leitfaden zu AI-Model-Tools und -Plattformen](AI-Model-Tools-and-Platforms.md) verwenden.

## AI-Sicherheit

### Vertrauensgrenzen von LLM-Gateways

Informationen zur Sicherheit von Gateways findest du unter:

{{#ref}}
AI-LLM-Gateway-Security.md
{{#endref}}

### Methodik zur Sicherheit von AI-Agenten

{{#ref}}
AI-Agent-Security-Methodology.md
{{#endref}}

### AI-Risikoframeworks

Zwei nützliche Frameworks für den Einstieg in die Bewertung von Risiken bei AI-Systemen sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen sich, stellen aber keine vollständige Liste der AI-Risikoframeworks dar.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit geleitete adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von AI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Zunahme der AI-Nutzung geführt. Sie sind jedoch nicht perfekt und lassen sich durch adversariale Prompts austricksen. Dieses Thema ist wichtig, um zu verstehen, wie du AI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in AI-Modellen

Entwickler und Unternehmen führen häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist wichtig, um zu verstehen, wie du AI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### Umgehung von KYC mit AI-Unterstützung

Generative Videos lassen sich mit Virtual-Camera-Injection und der Manipulation von Kamera-APIs kombinieren, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll, über das AI-Anwendungen mit Tools und Datenquellen verbunden werden. Da MCP-Server Daten und Aktionen zugänglich machen können, müssen Assessments Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### AI-Agent-to-Agent-Protokoll (A2A)

Mit A2A können Agenten einander über eine Agent Card finden und Aufgaben über HTTP senden. Teste Agent Cards, die Autorisierung von Aufgaben, Webhooks für Push-Benachrichtigungen und erweiterte Cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Offen zugängliche, selbst gehostete AI-Dienste

Fingerprinting und Tests von offen zugänglichen Model Runnern, Agent-Buildern, ML-Demo-UIs, Compute-Clustern und Vektordatenbanken ohne Authentifizierung:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### Fuzzing und automatisierte Schwachstellensuche mit AI-Unterstützung


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### Quellcodeanalyse und Schwachstellenvalidierung mit AI-Unterstützung

Informationen zur Analyse von Quellen und Senken, Taskflows für mobile Einstiegspunkte, Audits von Kernel-Mustern und evidenzbasierte Validierung findest du unter:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### Reverse Engineering mit AI-Unterstützung

[Partielles Lifting, Erkennung invarianten MBAs, umgebungsgebundene Dekodierung und Validierung automatisierter Extractoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Black-Box-Web-Pentester-Bots mit AI

LLM-gestützte Agenten können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, die Verwaltung authentifizierter Sitzungen und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 zur Sicherheit von Machine Learning](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres AI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
