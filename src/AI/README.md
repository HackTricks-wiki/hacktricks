# KI in der Cybersicherheit

{{#include ../banners/hacktricks-training.md}}

## Wichtigste Machine-Learning-Algorithmen

Der beste Einstieg in KI ist, zu verstehen, wie die wichtigsten Machine-Learning-Algorithmen funktionieren. So kannst du nachvollziehen, wie KI funktioniert, wie du sie einsetzt und wie du sie angreifst:


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

### Architektur von LLMs

Auf der folgenden Seite findest du die Grundlagen der einzelnen Komponenten, die zum Aufbau eines einfachen LLM mit Transformers erforderlich sind:


{{#ref}}
AI-llm-architecture/README.md
{{#endref}}

## Modell-Tools und -Plattformen

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

### KI-Risikoframeworks

Zwei nützliche Einstiegsframeworks zur Bewertung von Risiken bei KI-Systemen sind die OWASP Machine Learning Security Top 10 und Googles Secure AI Framework (SAIF). Sie ergänzen einander, bilden aber keine vollständige Liste der KI-Risikoframeworks.<sup>[[1]](#references)[[2]](#references)</sup>


{{#ref}}
AI-Risk-Frameworks.md
{{#endref}}

### Durch mechanistische Interpretierbarkeit gesteuerte adversariale Angriffe

{{#ref}}
AI-Mechanistic-Interpretability-Adversarial-Attacks.md
{{#endref}}

### Sicherheit von KI-Prompts

LLMs haben in den letzten Jahren zu einer explosionsartigen Verbreitung von KI geführt. Sie sind jedoch nicht perfekt und lassen sich durch adversariale Prompts täuschen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Prompts.md
{{#endref}}

### RCE in KI-Modellen

Entwickler und Unternehmen führen häufig Modelle aus, die sie aus dem Internet heruntergeladen haben. Doch bereits das Laden eines Modells kann ausreichen, um beliebigen Code auf dem System auszuführen. Dieses Thema ist sehr wichtig, um zu verstehen, wie du KI sicher einsetzt und wie du sie angreifst:


{{#ref}}
AI-Models-RCE.md
{{#endref}}

### KYC-Umgehung mithilfe von KI

Generative Videos lassen sich mit der Einspeisung virtueller Kameras und der Manipulation von Kamera-APIs kombinieren, um schwache KYC-, Altersverifizierungs- und biometrische Liveness-Verfahren zu umgehen:


{{#ref}}
KYC-Bypass-Using-AI.md
{{#endref}}

### Model Context Protocol für KI

MCP (Model Context Protocol) ist ein offenes Protokoll, über das sich KI-Anwendungen mit Tools und Datenquellen verbinden lassen. Da MCP-Server Daten und Aktionen bereitstellen können, müssen Prüfungen Autorisierung, Einwilligung, Validierung von Tool-Eingaben und die Überprüfung von Vertrauensgrenzen umfassen.<sup>[[3]](#references)</sup>


{{#ref}}
AI-MCP-Servers.md
{{#endref}}

### Agent-zu-Agent-Protokoll (A2A) für KI

Mit A2A können Agenten einander über eine Agent Card finden und Aufgaben per HTTP austauschen. Teste Agent Cards, die Autorisierung von Aufgaben, Webhooks für Push-Benachrichtigungen und erweiterte Cards:

{{#ref}}
AI-A2A-Protocol.md
{{#endref}}

### Offen erreichbare, selbst gehostete KI-Dienste

Erkennen und testen von offen erreichbaren Model Runnern, Agent Buildern, ML-Demo-UIs, Rechenclustern und Vektordatenbanken, die ohne Authentifizierung betrieben werden:

{{#ref}}
AI-Exposed-Self-Hosted-AI-Services.md
{{#endref}}

### KI-gestütztes Fuzzing und automatisierte Schwachstellensuche


{{#ref}}
AI-Assisted-Fuzzing-and-Vulnerability-Discovery.md
{{#endref}}

### KI-gestützte Quellcodeprüfung und Schwachstellenvalidierung

Für die Prüfung von Quellen und Senken, Taskflows mobiler Einstiegspunkte, Audits von Kernel-Mustern und eine evidenzbasierte Validierung:

{{#ref}}
AI-Assisted-Source-Review-and-Vulnerability-Validation.md
{{#endref}}

### KI-gestütztes Reverse Engineering

[Partielles Lifting, Erkennung invarianten MBA-Verhaltens, umgebungsgebundene Dekodierung und Validierung automatisierter Extraktoren](../reversing/reversing-tools-basic-methods/README.md#bypass-flattened-control-flow-with-a-narrow-execution-slice)

### Black-Box-Pentester-Bots für Webanwendungen

LLM-gestützte Agenten können lang laufende Black-Box-Web-Pentesting-Workflows automatisieren, wenn sie durch Observability, Orchestrierung, die Verwaltung authentifizierter Sitzungen und adversariale Validierung unterstützt werden:


{{#ref}}
Web-Black-Box-AI-Pentester-Bots.md
{{#endref}}

## References

- [1] [OWASP Top 10 für Machine-Learning-Sicherheit](https://owasp.org/www-project-machine-learning-security-top-10/)
- [2] [Google — Secure AI Framework (SAIF)](https://saif.google/)
- [3] [Model Context Protocol — Einführung](https://modelcontextprotocol.io/docs/getting-started/intro)
{{#include ../banners/hacktricks-training.md}}
