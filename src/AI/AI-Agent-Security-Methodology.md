# AI-Agent-Sicherheitsmethodik

{{#include ../banners/hacktricks-training.md}}

Eine Agent-Bewertung sollte **bei angreifergesteuerten Eingaben ansetzen und bis zu einer extern beobachtbaren Auswirkung führen**. Jailbreaking, Änderungen des Charakters und die Offenlegung des System-Prompts belegen, dass ein Reasoning-Kanal beeinflussbar ist. Der Befund mit hoher Auswirkung ist jedoch die Kette hin zu Datenzugriff, einer nicht autorisierten Tool-Aktion, einem nachgelagerten Injection-Sink, Persistenz oder einem anderen Agenten.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ist nützlich, um die Abdeckung zu kennzeichnen (Ziel-Hijacking, Tool-Missbrauch, Rechteausweitung, Supply Chain, Codeausführung, Memory Poisoning, Vertrauen zwischen Agenten, kaskadierende Fehler, menschliches Vertrauen und Rogue Agents). Verwende diese Kennzeichnungen, nachdem du einen End-to-End-Angriffspfad erstellt hast, statt unerwarteten Text eines Modells als Ende des Tests zu betrachten.<sup>[[1]](#references)[[2]](#references)</sup>

## Die Zielumgebung kartieren

Erfasse vor dem Schreiben von Payloads für jeden Agenten-Workflow die folgenden fünf Dimensionen:<sup>[[2]](#references)</sup>

| Dimension | Was zu erfassen ist | Sicherheitsfrage |
|---|---|---|
| **Nicht vertrauenswürdige Eingaben** | Chat-/API-Parameter, URLs, Dokumente, E-Mails, Tickets, Kalendereinträge, abgerufene Textabschnitte, Memory, Tool-Ergebnisse und Nachrichten von Peer-Agenten | Wo kann ein Angreifer Inhalte platzieren, die später in den Modellkontext gelangen? |
| **Tools** | Tool-Namen und -Schemas, Nebenwirkungen, automatische Ausführung, Bestätigungsverhalten und dynamisch geladene Tools | Welche Aufrufe lesen Geheimnisse, schreiben Daten, senden Nachrichten, löschen Daten, führen Code aus oder übertragen Werte? |
| **Berechtigungen** | Delegation durch Benutzer, Servicekonten, API-Tokens, Gültigkeitsdauer von Zugangsdaten, Mandanten-/Ressourcenbereich und Netzwerkzugriff | Unter welcher Identität wird jeder Aufruf ausgeführt, und wird die Autorisierung an der Tool-Grenze erneut geprüft? |
| **Verarbeitung** | Query-Builder, Shells, URL-Abrufdienste, Template-Engines, Interpreter, Parser, Dateioperationen und Deserialisierer | Wo werden vom Modell erzeugte Daten zur Syntax für einen anderen Interpreter? |
| **Ausgabe** | Antworten, gerendertes Markdown/HTML, Links, Bildabrufe, Webhooks, E-Mails, Dateien, Logs, Berichte, Metriken und Peer-Agent-Verkehr | Welcher beobachtbare Kanal kann ein Geheimnis übertragen oder eine sekundäre Anfrage auslösen? |

Fasse dies nicht zu einer Liste der beworbenen Integrationen zusammen. Ein nützliches Artefakt ordnet jeder Quelle die genaue Kontextposition zu, die sie erreicht, die an dieser Stelle verfügbaren Tools, die von jedem Tool verwendeten Zugangsdaten, den nachgelagerten Interpreter und alle möglichen Egress-Routen. Dasselbe Tool kann mit einem benutzerspezifischen Lese-Token geringe Auswirkungen haben und mit gemeinsam genutzten Administrator-Zugangsdaten kritisch sein.<sup>[[2]](#references)</sup>

## Aufklärung

### Alle Übermittlungs- und Eingabepfade kartieren

Beginne mit der Übermittlungsoberfläche (Web, Mobilgerät, API, E-Mail, Chat-Plattform, Browser-Erweiterung) und proxye den Client-zu-Backend-Verkehr. Prüfe Felder, die in der UI verborgen sind, Such-/Autocomplete-/Filterparameter, Konversationsstatus-Objekte, Upload- und Indexierungsjobs, Tool-Antworten und Subagent-Verkehr. Bei reinen Mobile-Clients sind möglicherweise ein Emulator und Instrumentierung erforderlich, um Certificate Pinning zu umgehen, bevor das tatsächliche Request-Schema sichtbar wird.<sup>[[2]](#references)</sup>

Kartiere anschließend den Stack unterhalb des Modells: Orchestrierungs-Framework, Prompt-Zusammenstellung, Retrieval- und Memory-Speicher, Runtime (z. B. Python, Container oder WASM), eingebundene Volumes, Host-Dienste, interne APIs, Erreichbarkeit von Cloud-Metadaten und benachbarte Netzwerke. Framework-Standardeinstellungen sind wichtig, denn manche „Tool-Aufrufe“ werden durch das Generieren oder Auswerten von Code implementiert. Die Runtime-/Sandbox-Grenze bestimmt, ob das Ergebnis tatsächlich eingeschlossen bleibt.<sup>[[2]](#references)</sup>

### Routing mit nicht destruktiven Probes identifizieren

Vergleiche eine Anfrage innerhalb des Geltungsbereichs mit mehreren unabhängigen Anfragen und erfasse dabei die vollständige Antwort, den Statuscode, die Latenz und das Streaming-Verhalten. Eine stabile Ablehnung vor jeglichem aufgabenspezifischen Reasoning kann auf ein separates Gateway/einen separaten Classifier hindeuten; eine kontextabhängige Ablehnung lässt vermuten, dass die Anfrage das Modell erreicht hat; eine leere oder ausschließlich extraktive Antwort kann auf eine Schlüsselwortsuche oder eng begrenztes Retrieval hindeuten. Behandle dies als Hypothesen und bestätige sie, indem du dieselbe Probe über alternative API-Felder und Eingabepfade wiederholst.<sup>[[2]](#references)</sup>

Die Aufklärung ist abgeschlossen, wenn die Bewertung die früheste angreifergesteuerte Quelle benennen kann, die das Agentenverhalten verändert, **und** die von dieser Quelle erreichbaren Tools, Identitäten, Interpreter und Ausgaben.<sup>[[2]](#references)</sup>

## Ausnutzung: eine Vertrauensgrenze überschreiten

Teste Kanäle, nicht nur Prompt-Formulierungen. Beginne mit einer direkten Injection, um festzustellen, was die sichtbare Eingangstür blockiert, und wiederhole dann eine gleichwertige Absicht über die weniger sichtbaren Pfade unten:<sup>[[2]](#references)</sup>

- **Indirekte Inhalte:** Seiten, Dateien, E-Mails, Tickets, Metadaten, Alt-Text, HTML-Kommentare, außerhalb des sichtbaren Bereichs platzierter Text oder Zero-Width-Zeichen. Unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) findest du Techniken zur Übermittlung von Payloads.
- **Retrieval und Memory:** Inhalte einschleusen, die später abgerufen werden, oder Status, der in späteren Sitzungen erneut geladen wird. Halte fest, ob das Löschen der ursprünglichen Quelle das Verhalten beendet.
- **Tool-Ausgaben und Peer-Agenten:** Platziere den Marker in einer Tool-Antwort oder einer Agent-zu-Agent-Nachricht, um zu testen, ob interner Verkehr Filter umgeht, die nur auf Benutzereingaben und finale Ausgaben angewendet werden.
- **Supply Chain:** Prüfe Tool-Deskriptoren, Plugins, verbundene Server, Skills, Modelle und Abhängigkeiten als vertrauenswürdige Anweisungsquellen. Spezifische Tests für MCP findest du unter [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menschliche Genehmigung:** Vergleiche den tatsächlichen strukturierten Tool-Aufruf mit dem vom Modell generierten Genehmigungstext. Teste, ob Angreifereinfluss das Ziel, den Umfang, die betroffenen Objekte oder irreversible Nebenwirkungen auslassen kann.

Verwende zuerst einen harmlosen, eindeutigen Marker. Sichere das Quellartefakt, den zusammengestellten Kontext (falls sichtbar), den ausgewählten Tool-Aufruf, die Genehmigungsdaten, die Backend-Anfrage/-Antwort und den finalen Zustand. So lässt sich tatsächliche Beeinflussung von einer halluzinierten Behauptung unterscheiden, dass eine Aktion ausgeführt wurde.<sup>[[2]](#references)</sup>

### Richtlinienähnlicher Text in einem Tool-Risiko-Judge

Ein modellbasierter Tool-Gate kann angreifergesteuerten Text innerhalb eines ansonsten nützlichen Klassifizierungskontexts erhalten. LangChains experimentelles `AutoModeMiddleware` sendet beispielsweise einen vorgeschlagenen Tool-Aufruf, dessen Argumente, eine optionale Tool-Beschreibung und bis zu 30 aktuelle Nachrichten an einen TypeSafe-`is_risky`-Judge. Es blockiert konfigurierte Tools, wenn die zurückgegebene Noul-Wahrscheinlichkeit mindestens `0.5` beträgt; nicht aufgeführte Tools werden von dieser Middleware nicht klassifiziert.<sup>[[5]](#references)</sup> TypeSafe warnt außerdem, dass adversarialer Text im Status eine Klassifizierung beeinflussen kann, selbst wenn der Status als Daten gedacht ist.<sup>[[6]](#references)</sup>

Eine **gefälschte Richtlinie** unterscheidet sich davon, sich einfach als Systemnachricht auszugeben. Sie platziert alternative Bezeichnungen oder Risikodefinitionen in einem weniger vertrauenswürdigen Status und legt dem Judge nahe, diese Definitionen statt der vom Entwickler festgelegten Kriterien zu verwenden. Im Test von Datadog wurde eine vom Benutzer bearbeitbare `profile_description` zusammen mit `can_edit:false` in die Tool-Argumente kopiert. Ihr richtlinienähnlicher Text argumentierte, ein Schreibversuch sei risikoarm, weil eine separate Berechtigungsprüfung ihn vor jeder Änderung ablehnen sollte. Über 40 Durchläufe sank der mittlere `is_risky`-Score von `0.893` auf `0.290`, während ein direkter Vergleich mit Rollen-Spoofing im Mittel `0.905` ergab. Dass der Mittelwert unter `0.5` sank, beweist nicht, dass jeder einzelne Aufruf das Gate passierte; außerdem demonstrierte das Experiment **keinen** erfolgreich abgeschlossenen, nicht autorisierten Schreibvorgang.<sup>[[7]](#references)</sup>

Unterscheide beim Testen dieser Grenze zwischen dem Urteil des Classifiers und dem tatsächlichen Autorisierungsergebnis des Tools. Prüfe, welche bearbeitbaren Felder den Judge erreichen, vergleiche dieselbe vorgeschlagene Aktion mit und ohne richtlinienähnlichen Text und überprüfe den finalen Zustand unabhängig. Eine separate Berechtigungsprüfung muss weiterhin die Berechtigungen der authentifizierten anfragenden Person verwenden, nicht die Rechte des Servicekontos des Connectors.<sup>[[7]](#references)</sup> Weitere Fehlerarten von Classifiern findest du unter [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) betreffen eine andere Routing- und Zugangsdaten-Grenze.

### Kontextisolierung von Subagents

Ein Subagent des Claude Agent SDK, der nicht per Fork gestartet wird, erhält seine eigene `AgentDefinition.prompt`, den Delegations-Prompt und die verfügbaren Tools, jedoch nicht den System-Prompt oder die Konversation des Parents. Wenn `tools` in seiner Definition fehlt, erbt er die den Subagents verfügbaren Tools; die Projektdatei `CLAUDE.md` kann weiterhin geladen werden. Daher ist eine Einschränkung des Prompts nur im Parent keine zuverlässige Grenze, wenn das Child dieselben Dateisystem- oder Ausführungstools verwenden kann.<sup>[[4]](#references)</sup>

Teste die Grenze, indem du eine direkte Anfrage, die der Parent ablehnt, mit derselben Aufgabe vergleichst, die an einen benannten Subagent delegiert wird. NCC Group berichtet, dass eine abgelehnte Enumeration von Betriebssystemdateien erfolgreich war, als sie für ein Child als harmlose „layout map“ umformuliert wurde.<sup>[[3]](#references)</sup>

Prüfe die tatsächlichen Tool-Aufrufe des Childs und dessen effektive Tool-Allowlist, nicht nur die finale Antwort des Parents. Bestätige, ob das Child auf Dateien zugegriffen hat, auf die der Parent nicht zugreifen würde.<sup>[[4]](#references)</sup> Dies ist ein Fehler bei der Vererbung von Guardrails und kein Beleg für einen [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) oder Container Escape.<sup>[[3]](#references)[[4]](#references)</sup>

## Ausführung: reale Auswirkungen nachweisen

Es gibt zwei unterschiedliche Wege von der Beeinflussung zu den Auswirkungen:<sup>[[2]](#references)</sup>

1. **Missbrauch von Fähigkeiten:** Das autorisierte Tool führt das Ziel bereits selbst aus. Beispiele sind das Lesen des Datensatzes eines Mandanten und das Schreiben in einen für den Angreifer sichtbaren Bericht, das Senden einer E-Mail, das Ändern von Datensätzen, das Löschen einer Datei oder das Auslösen einer Zahlung. Ein weiterer Softwarefehler ist nicht erforderlich.
2. **Ausnutzung eines nachgelagerten Sinks:** Angreifergesteuerte Modellausgabe wird zur Syntax für eine andere Komponente. Prüfe Datenbankabfragen auf [SQL injection](../pentesting-web/sql-injection/README.md) oder [NoSQL injection](../pentesting-web/nosql-injection.md), Shell-Wrapper auf [command injection](../pentesting-web/command-injection.md), ausgewählte URLs auf [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), Dateioperationen auf Traversal, Template-/Code-Evaluatoren auf RCE und Objekt-Parser auf [unsafe deserialization](../pentesting-web/deserialization/README.md).

Weise für jeden möglichen Fall die folgende Kette nach:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Eine schreibgeschützte Integration ist weiterhin ausnutzbar, wenn eine spätere Komponente veröffentlichen kann, was sie gelesen hat. Teste gewöhnliche Antworten sowie weniger offensichtliche Egress-Kanäle wie vom Angreifer kontrollierte Links, automatisches Abrufen von Bildern, Webhooks, Logs, Berichte, Zähler, Benachrichtigungen und Nachrichten an andere Agents.<sup>[[2]](#references)</sup>

## Aktionen gegen Ziele

Nachdem eine Aktion bestätigt wurde, bewerte das gesamte Ausmaß der Auswirkungen, anstatt bei der ersten sichtbaren Wirkung aufzuhören:<sup>[[2]](#references)</sup>

- **Exfiltration:** Geheimnisse, Benutzerdatensätze, interne Dateien, Konversationsdaten oder Prompt-/Kontextinhalte verlassen das System über einen beobachtbaren Kanal.
- **Nicht autorisierte Aktion:** Der Agent verwendet legitime Schreibberechtigungen für das Ziel des Angreifers.
- **Denial of Service:** Destruktive Tools oder wiederholte, ressourcenintensive Vorgänge beeinträchtigen Integrität oder Verfügbarkeit.
- **Persistenz:** Manipuliertes Memory, indexierte Inhalte, vertrauenswürdiger Zustand oder Laufzeitänderungen bleiben nach Ende der auslösenden Sitzung oder Entfernung der Quelle bestehen.
- **Ausbreitung:** Ein vertrauenswürdiger Peer übernimmt die Nachricht oder den gemeinsamen Zustand des kompromittierten Agents und wiederholt die Aktion mit seinen eigenen Tools und Anmeldedaten.

Der Schweregrad sollte sich nach den erreichbaren Daten, den effektiven Berechtigungen, der Ausnutzbarkeit des Sinks, dem Egress, der Persistenz und der Ausbreitung richten – nicht danach, wie überraschend der Text des Modells erscheint.<sup>[[2]](#references)</sup>

## Während des Assessments zu überprüfende Kontrollen

Prompt-Filter und ein besserer System-Prompt können den Aufwand für Angreifer erhöhen, sollten aber nicht als Autorisierungsgrenzen betrachtet werden. Überprüfe die folgenden Kontrollen, indem du dieselbe Angriffskette über direkte Eingaben, indirekte Inhalte, Memory, Tools und Peer-Agents erneut ausführst:<sup>[[2]](#references)</sup>

- Eine deterministische Richtlinienebene prüft den authentifizierten Benutzer, den Mandanten, das Objekt, die Aktion und das Ziel bei **jedem Tool-Aufruf**; das Modell kann die Identität des Aufrufers weder angeben noch überschreiben.
- Lese- und Schreibberechtigungen verwenden getrennte, kurzlebige Anmeldedaten mit geringsten Berechtigungen; Tools mit weitreichenden Auswirkungen werden nur bei Bedarf bereitgestellt und niemals automatisch aufgrund eingelesener Inhalte ausgeführt.
- Ausgehender Netzwerkverkehr und interne Ziele werden unabhängig von den vom Modell ausgewählten URLs auf eine Erlaubnisliste gesetzt; der Laufzeitzugriff auf Metadaten-Endpunkte, eingebundene Geheimnisse und benachbarte Dienste wird blockiert, sofern er nicht erforderlich ist.
- Die Genehmigungsoberfläche wird aus der kanonischen strukturierten Anfrage generiert und zeigt die exakten Argumente, die Identität, das Ziel, die betroffenen Objekte und die Nebenwirkungen an – nicht eine frei formulierte Zusammenfassung des Modells.
- Der Erfolg wird anhand des Zielsystems oder führenden Datensystems überprüft. Die Beschreibung des Agents, eine Tool-Aufrufanfrage oder eine HTTP-Weiterleitung beweist nicht, dass die behauptete Zustandsänderung erfolgt ist.
- Memory- und Retrieval-Einträge behalten ihre Herkunft und Vertrauenskennzeichnungen, können invalidiert werden und werden bei ihrer Verwendung für eine spätere Aktion erneut autorisiert.
- Nachrichten zwischen Agents werden als nicht vertrauenswürdige Anfragen authentifiziert und autorisiert; der Ruf eines Peers oder dessen Agent-Karte überträgt nicht implizit die Tools des Empfängers.

## References

- [1] [OWASP Top 10 für agentische Anwendungen 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Der Hacker-Leitfaden zum Angriff auf AI-Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Wie schwierig ist es wirklich, einen AI-Agent aus seiner Sandbox auszubrechen?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents im SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Quellcode der TypeSafe-Auto-Mode-Middleware von LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-Modell-Jaggedness: adversariale Inhalte](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev als Richter: Wie gefälschte Richtlinien Jev beeinflussen](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
