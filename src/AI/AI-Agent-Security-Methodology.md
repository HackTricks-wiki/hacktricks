# Methodik zur Sicherheit von AI-Agenten

{{#include ../banners/hacktricks-training.md}}

Eine Agentenbewertung sollte den Weg von **angreifergesteuerter Eingabe zu einer extern beobachtbaren Auswirkung** verfolgen. Jailbreaking, Änderungen am Verhalten und die Offenlegung des System-Prompts zeigen, dass ein Reasoning-Kanal beeinflussbar ist. Der schwerwiegende Befund ist jedoch die Kette bis zu Datenzugriff, einer nicht autorisierten Tool-Aktion, einem nachgelagerten Injection-Sink, Persistenz oder einem anderen Agenten.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) eignet sich zur Kennzeichnung der Abdeckung (Goal Hijacking, Tool Misuse, Privilege Abuse, Supply Chain, Code Execution, Memory Poisoning, Inter-Agent Trust, Cascading Failures, Human Trust und Rogue Agents). Verwende diese Bezeichnungen, nachdem du einen durchgängigen Angriffspfad erstellt hast, statt unerwarteten Text eines Modells als Ende des Tests zu betrachten.<sup>[[1]](#references)[[2]](#references)</sup>

## Zielübersicht erstellen

Erfasse für jeden Agenten-Workflow vor dem Erstellen von Payloads diese fünf Dimensionen:<sup>[[2]](#references)</sup>

| Dimension | Was zu erfassen ist | Sicherheitsfrage |
|---|---|---|
| **Nicht vertrauenswürdige Eingaben** | Chat-/API-Parameter, URLs, Dokumente, E-Mails, Tickets, Kalendereinträge, abgerufene Textabschnitte, Speicher, Tool-Ergebnisse und Nachrichten von Peer-Agenten | Wo kann ein Angreifer Inhalte platzieren, die später in den Modellkontext gelangen? |
| **Tools** | Tool-Namen und -Schemas, Seiteneffekte, automatische Ausführung, Bestätigungsverhalten und dynamisch geladene Tools | Welche Aufrufe lesen Geheimnisse, schreiben Daten, senden Nachrichten, löschen Daten, führen Code aus oder übertragen Werte? |
| **Berechtigungen** | Delegation durch Benutzer, Dienstkonten, API-Tokens, Gültigkeitsdauer von Zugangsdaten, Mandanten-/Ressourcenbereich und Netzwerkzugriff | Unter welcher Identität wird jeder Aufruf ausgeführt, und wird die Autorisierung an der Tool-Grenze erneut geprüft? |
| **Verarbeitung** | Query-Builder, Shells, URL-Fetcher, Template-Engines, Interpreter, Parser, Dateizugriffe und Deserialisierer | Wo werden vom Modell erzeugte Daten zur Syntax für einen anderen Interpreter? |
| **Ausgabe** | Antworten, gerendertes Markdown/HTML, Links, Bildabrufe, Webhooks, E-Mails, Dateien, Logs, Berichte, Metriken und Peer-Agent-Datenverkehr | Welcher beobachtbare Kanal kann ein Geheimnis übertragen oder eine sekundäre Anfrage auslösen? |

Fasse dies nicht zu einer Liste beworbener Integrationen zusammen. Ein nützliches Artefakt ordnet jeder Quelle die genaue Kontextposition zu, die sie erreicht, die an diesem Punkt verfügbaren Tools, die von jedem Tool verwendeten Zugangsdaten, den nachgelagerten Interpreter und alle Exfiltrationswege. Dasselbe Tool kann mit einem benutzerspezifischen Lesetoken geringe Auswirkungen haben und mit einem gemeinsam genutzten Administrator-Zugang kritisch sein.<sup>[[2]](#references)</sup>

## Aufklärung

### Alle Übermittlungs- und Aufnahmewege erfassen

Beginne mit der Übermittlungsoberfläche (Web, Mobilgerät, API, E-Mail, Chat-Plattform, Browser-Erweiterung) und zeichne den Datenverkehr zwischen Client und Backend über einen Proxy auf. Prüfe Felder, die in der UI verborgen sind, Such-/Autovervollständigungs-/Filterparameter, Konversationsstatusobjekte, Upload- und Indizierungsaufträge, Tool-Antworten und den Datenverkehr von Sub-Agenten. Für reine Mobil-Clients sind möglicherweise ein Emulator und Instrumentierung erforderlich, um Certificate Pinning zu umgehen, bevor das tatsächliche Request-Schema sichtbar wird.<sup>[[2]](#references)</sup>

Erfasse anschließend den Stack unterhalb des Modells: Orchestrierungs-Framework, Prompt-Zusammenstellung, Retrieval- und Memory-Stores, Laufzeitumgebung (zum Beispiel Python, Container oder WASM), eingebundene Volumes, Host-Dienste, interne APIs, Erreichbarkeit von Cloud-Metadaten und benachbarte Netzwerke. Framework-Standardeinstellungen sind relevant, da einige „Tool-Aufrufe“ durch das Generieren oder Auswerten von Code implementiert werden. Die Laufzeit-/Sandbox-Grenze entscheidet, ob dieses Ergebnis isoliert bleibt.<sup>[[2]](#references)</sup>

### Routing mit nicht destruktiven Probes erkennen

Vergleiche eine Anfrage im Scope mit mehreren sachfremden Anfragen und erfasse dabei die vollständige Antwort, den Statuscode, die Latenz und das Streaming-Verhalten. Eine konsistente Ablehnung vor jeder aufgabenspezifischen Verarbeitung kann auf ein separates Gateway/einen Klassifizierer hindeuten; eine kontextbezogene Ablehnung legt nahe, dass die Anfrage das Modell erreicht hat; eine leere oder rein extraktive Antwort kann auf eine Stichwortsuche oder ein eng begrenztes Retrieval hinweisen. Behandle dies als Hypothesen und bestätige sie, indem du dieselbe Probe über alternative API-Felder und Aufnahmewege erneut ausführst.<sup>[[2]](#references)</sup>

Die Aufklärung ist abgeschlossen, wenn die Bewertung die früheste angreifergesteuerte Quelle benennen kann, die das Agentenverhalten verändert, **sowie** die von dieser Quelle erreichbaren Tools, Identitäten, Interpreter und Ausgaben.<sup>[[2]](#references)</sup>

## Ausnutzung: Eine Vertrauensgrenze überschreiten

Teste Kanäle, nicht nur Prompt-Formulierungen. Beginne mit direkter Injection, um festzustellen, was die sichtbare Eingangsstelle blockiert, und wiederhole dann eine entsprechende Absicht über die weniger sichtbaren Pfade unten:<sup>[[2]](#references)</sup>

- **Indirekte Inhalte:** Seiten, Dateien, E-Mails, Tickets, Metadaten, Alt-Text, HTML-Kommentare, Text außerhalb des sichtbaren Bereichs oder Zero-Width-Zeichen. Payload-Übermittlungstechniken findest du unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection).
- **Retrieval und Speicher:** Verunreinige Inhalte, die später abgerufen werden, oder Zustände, die in späteren Sitzungen erneut geladen werden. Halte fest, ob das Löschen der ursprünglichen Quelle das Verhalten beendet.
- **Tool-Ausgabe und Peer-Agenten:** Platziere den Marker in einer Tool-Antwort oder Agent-zu-Agent-Nachricht, um zu testen, ob interner Datenverkehr Filter umgeht, die nur auf Benutzereingaben und die endgültige Ausgabe angewendet werden.
- **Supply Chain:** Prüfe Tool-Deskriptoren, Plugins, verbundene Server, Skills, Modelle und Abhängigkeiten als vertrauenswürdige Instruktionsquellen. MCP-spezifische Tests findest du unter [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menschliche Genehmigung:** Vergleiche den tatsächlichen strukturierten Tool-Aufruf mit dem vom Modell erzeugten Genehmigungstext. Teste, ob der Angreifereinfluss das Ziel, den Umfang, die betroffenen Objekte oder irreversible Nebenwirkungen auslassen kann.

Verwende zuerst einen harmlosen, eindeutigen Marker. Sichere das Quellartefakt, den zusammengesetzten Kontext (falls beobachtbar), den ausgewählten Tool-Aufruf, die Genehmigungsdaten, Backend-Request/-Antwort und den endgültigen Zustand. So lässt sich Einfluss von einer halluzinierten Behauptung unterscheiden, eine Aktion sei erfolgt.<sup>[[2]](#references)</sup>

## Ausführung: Reale Auswirkungen nachweisen

Es gibt zwei unterschiedliche Wege von Einfluss zu Auswirkungen:<sup>[[2]](#references)</sup>

1. **Missbrauch von Fähigkeiten:** Das autorisierte Tool führt das gewünschte Ziel bereits aus. Beispiele sind das Lesen eines Datensatzes eines Mandanten und dessen Schreiben in einen für den Angreifer sichtbaren Bericht, das Senden einer E-Mail, das Ändern von Datensätzen, das Löschen einer Datei oder das Veranlassen einer Zahlung. Es ist kein sekundärer Softwarefehler erforderlich.
2. **Ausnutzung nachgelagerter Senken:** Vom Angreifer gesteuerte Modellausgabe wird zur Syntax für eine andere Komponente. Prüfe Datenbankabfragen auf [SQL injection](../pentesting-web/sql-injection/README.md) oder [NoSQL injection](../pentesting-web/nosql-injection.md), Shell-Wrapper auf [command injection](../pentesting-web/command-injection.md), ausgewählte URLs auf [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), Dateizugriffe auf Traversal, Template-/Code-Evaluatoren auf RCE und Objekt-Parser auf [unsafe deserialization](../pentesting-web/deserialization/README.md).

Weise für jeden möglichen Befund diese Kette nach:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Eine schreibgeschützte Integration ist weiterhin ausnutzbar, wenn eine nachgelagerte Komponente veröffentlichen kann, was sie gelesen hat. Teste gewöhnliche Antworten sowie weniger offensichtliche Egress-Kanäle wie vom Angreifer kontrollierte Links, automatisches Abrufen von Bildern, Webhooks, Logs, Berichte, Zähler, Benachrichtigungen und Nachrichten an andere Agents.<sup>[[2]](#references)</sup>

## Aktionen auf Ziele

Nachdem du eine Aktion bestätigt hast, bewerte die gesamte Auswirkung, statt bei der ersten sichtbaren Wirkung aufzuhören:<sup>[[2]](#references)</sup>

- **Exfiltration:** Secrets, Benutzerdatensätze, interne Dateien, Konversationsdaten oder Prompt-/Kontextinhalte verlassen das System über einen beobachtbaren Kanal.
- **Unbefugte Aktion:** Der Agent setzt legitime Schreibrechte für das Ziel des Angreifers ein.
- **Denial of service:** Destruktive Tools oder wiederholte, kostspielige Vorgänge beeinträchtigen Integrität oder Verfügbarkeit.
- **Persistenz:** Vergifteter Speicher, indexierte Inhalte, vertrauenswürdiger Zustand oder Laufzeitänderungen bleiben nach Ende der verursachenden Sitzung oder Entfernung der Quelle bestehen.
- **Ausbreitung:** Ein vertrauenswürdiger Peer konsumiert die Nachricht oder den gemeinsam genutzten Zustand des kompromittierten Agents und wiederholt die Aktion mit den eigenen Tools und Zugangsdaten.

Die Schwere sollte sich nach erreichbaren Daten, effektiven Berechtigungen, Ausnutzbarkeit des Sinks, Egress, Persistenz und Ausbreitung richten – nicht danach, wie überraschend der Text des Modells wirkt.<sup>[[2]](#references)</sup>

## Während der Bewertung zu überprüfende Kontrollen

Prompt-Filter und ein besserer System-Prompt können den Aufwand für Angreifer erhöhen, sollten aber nicht als Autorisierungsgrenzen betrachtet werden. Überprüfe die folgenden Kontrollen, indem du dieselbe Angriffskette erneut über direkte Eingaben, indirekte Inhalte, Speicher, Tools und Peer-Agents ausführst:<sup>[[2]](#references)</sup>

- Eine deterministische Richtlinienebene prüft bei **jedem Tool-Aufruf** den authentifizierten Benutzer, Mandanten, das Objekt, die Aktion und das Ziel; das Modell kann die Identität des Aufrufers weder angeben noch überschreiben.
- Lese- und Schreibberechtigungen verwenden getrennte, nach dem Prinzip der geringsten Berechtigungen ausgestellte, kurzlebige Zugangsdaten; Tools mit hoher Auswirkung werden nur bei Bedarf bereitgestellt und niemals automatisch aufgrund eingelesener Inhalte ausgeführt.
- Netzwerk-Egress und interne Ziele werden unabhängig von den vom Modell ausgewählten URLs auf eine Allowlist gesetzt; der Laufzeitzugriff auf Metadatenendpunkte, eingebundene Secrets und benachbarte Dienste wird blockiert, sofern er nicht erforderlich ist.
- Die Genehmigungsoberfläche wird aus der kanonischen strukturierten Anfrage generiert und zeigt die exakten Argumente, die Identität, das Ziel, die betroffenen Objekte und Nebenwirkungen an – keine frei formulierte Zusammenfassung des Modells.
- Der Erfolg wird anhand des Zielsystems oder des maßgeblichen Systems überprüft. Die Erzählung des Agents, eine Tool-Aufrufanfrage oder eine HTTP-Weiterleitung beweist nicht, dass die behauptete Zustandsänderung eingetreten ist.
- Speicher- und Retrieval-Einträge behalten ihre Herkunft und Vertrauenskennzeichnungen, können ungültig gemacht werden und werden bei ihrer Verwendung für spätere Aktionen erneut autorisiert.
- Nachrichten zwischen Agents werden als nicht vertrauenswürdige Anfragen authentifiziert und autorisiert; der Ruf eines Peers oder seine Agent Card überträgt dem Empfänger nicht implizit die Nutzung seiner Tools.

## References

- [1] [OWASP Top 10 für agentische Anwendungen 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Das Hacker-Handbuch zum Angriff auf AI-Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
