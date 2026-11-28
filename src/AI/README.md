# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Der beste Einstieg in das Thema KI ist, zu verstehen, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du nachvollziehen, wie KI funktioniert, wie man sie einsetzt und wie man sie angreift:


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

### Modelldatenaufbereitung und Evaluierung

Informationen zu Datensatzaufteilungen, klassischen Metriken und Angriffen über Antworten auf LLM-basierte Bewertung findest du unter [Modelldatenaufbereitung und Evaluierung](AI-Model-Data-Preparation-and-Evaluation.md#attacking-llm-based-evaluation-with-answer-side-injection).

### LLM-Architektur

Auf der folgenden Seite findest du die Grundlagen der einzelnen Komponenten, um ein einfaches LLM mit Transformers zu erstellen:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modelltools und Plattformen

Zum Ausführen, Fine-Tuning, Bereitstellen oder Ausprobieren von Modellen findest du hier den [Leitfaden zu KI-Modelltools und -plattformen](AI-Model-Tools-and-Platforms.md).

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

### KI-Risikoframeworks

Zwei hilfreiche Frameworks für den Einstieg in die Bewertung von KI-Systemrisiken sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen sich und bilden keine vollständige Liste aller KI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit geleitete adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Vertrauensgrenzen eingebetteter Browser

Informationen zu Browser-Bridges für Desktop-Assistenten, Tab-Adress-Spoofing und dem Lesen lokaler Dateien aus dem Worker-Kontext findest du unter [Vertrauensgrenzen eingebetteter Browser von KI-Assistenten](AI-Embedded-Browser-Trust-Boundaries.md).

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer starken Verbreitung von KI geführt. Sie sind jedoch nicht perfekt und können durch adversariale Prompts getäuscht werden. Dieses Thema ist wichtig, um zu verstehen, wie man KI sicher einsetzt und wie man sie angreift:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE durch KI-Modelle

Entwickler und Unternehmen führen häufig aus dem Internet heruntergeladene Modelle aus. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist wichtig, um zu verstehen, wie man KI sicher einsetzt und wie man sie angreift:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

Informationen zu Risiken beim Laden von Keras-Modellen im `.keras`-/HDF5-Format, Lambda-Layern und der Analyse von Gadgets nach einem Fix findest du unter [Deserialisierung von Keras-Modellen und Gadget-Jagd](keras-model-deserialization-rce-and-gadget-hunting.md).

### KI-gestützter KYC-Bypass

Generative Videos können mit Virtual-Camera-Injection und der Manipulation von Kamera-APIs kombiniert werden, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### AI Model Context Protocol

MCP (Model Context Protocol) ist ein offenes Protokoll, mit dem sich KI-Anwendungen mit Tools und Datenquellen verbinden lassen. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Sicherheitsprüfungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### KI-Agent-zu-Agent-(A2A)-Protokoll

Mit A2A können Agenten einander über eine Agent Card finden und Aufgaben per HTTP austauschen. Teste Agent Cards, die Autorisierung von Aufgaben, Webhooks für Push-Benachrichtigungen und erweiterte Cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Offen erreichbare, selbst gehostete KI-Dienste

Identifizierung und Prüfung offen erreichbarer Model Runner, Agent Builder, ML-Demo-Oberflächen, Compute-Cluster und Vektordatenbanken ohne Authentifizierung:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### KI-gestütztes Fuzzing und automatisierte Schwachstellenerkennung


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gestützte Quellcodeprüfung und Schwachstellenvalidierung

Informationen zur Prüfung von Quellen und Senken, zu Taskflows mobiler Einstiegspunkte, Audits von Kernel-Mustern und evidenzbasierter Validierung findest du hier:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-gestütztes Reverse Engineering

[Partielles Lifting, Erkennung invarianten MBA, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### KI-Pentesting-Bots für Webanwendungen im Black-Box-Verfahren

LLM-gestützte Agenten können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, sofern sie durch Observability, Orchestrierung, authentifizierte Sitzungsverwaltung und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}



## References

- [1] [OWASP Top 10 für Machine-Learning-Sicherheit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Sicheres KI-Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
