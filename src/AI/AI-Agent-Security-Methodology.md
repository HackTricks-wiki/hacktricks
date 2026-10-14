# AI-Agent-Sicherheitsmethodik

{{#include ../banners/hacktricks-training.md}}

Ein Agent-Assessment sollte dem Pfad **von angreifergesteuerter Eingabe bis zu einer extern beobachtbaren Wirkung** folgen. Jailbreaking, Änderungen am Verhalten und die Offenlegung des System-Prompts belegen, dass ein Reasoning-Kanal beeinflussbar ist. Der schwerwiegende Befund ist jedoch die Kette hin zu Datenzugriff, einer nicht autorisierten Tool-Aktion, einem nachgelagerten Injection-Sink, Persistenz oder einem anderen Agenten.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) eignet sich, um die Abdeckung zu kennzeichnen (Goal Hijacking, Tool-Missbrauch, Privilegienmissbrauch, Supply Chain, Codeausführung, Memory Poisoning, Vertrauen zwischen Agenten, kaskadierende Fehler, menschliches Vertrauen und Rogue Agents). Verwende diese Kennzeichnungen, nachdem du einen End-to-End-Angriffspfad ermittelt hast, statt unerwarteten Modelltext als Ende des Tests zu betrachten.<sup>[[1]](#references)[[2]](#references)</sup>

## Zielübersicht erstellen

Erfasse vor dem Erstellen von Payloads für jeden Agenten-Workflow die folgenden fünf Dimensionen:<sup>[[2]](#references)</sup>

| Dimension | Zu erfassende Elemente | Sicherheitsfrage |
|---|---|---|
| **Nicht vertrauenswürdige Eingabe** | Chat-/API-Parameter, URLs, Dokumente, E-Mails, Tickets, Kalendereinträge, abgerufene Chunks, Memory, Tool-Ergebnisse und Nachrichten von Peer-Agenten | Wo kann ein Angreifer Inhalte platzieren, die später in den Modellkontext gelangen? |
| **Tools** | Tool-Namen und -Schemas, Nebenwirkungen, automatische Ausführung, Bestätigungsverhalten und dynamisch geladene Tools | Welche Aufrufe lesen Geheimnisse, ändern Zustand, senden Nachrichten, löschen Daten, führen Code aus oder übertragen Werte? |
| **Berechtigungen** | Delegation durch Benutzer, Service Accounts, API-Tokens, Gültigkeitsdauer von Zugangsdaten, Tenant-/Ressourcenbereich und Netzwerkzugriff | Unter welcher Identität wird jeder Aufruf ausgeführt, und wird die Autorisierung an der Tool-Grenze erneut geprüft? |
| **Verarbeitung** | Query-Builder, Shells, URL-Fetcher, Template-Engines, Interpreter, Parser, Dateioperationen und Deserializer | Wo werden vom Modell erzeugte Daten zur Syntax für einen anderen Interpreter? |
| **Ausgabe** | Antworten, gerendertes Markdown/HTML, Links, Bildabrufe, Webhooks, E-Mails, Dateien, Logs, Berichte, Metriken und Peer-Agent-Datenverkehr | Welcher beobachtbare Kanal kann ein Geheimnis übertragen oder eine sekundäre Anfrage auslösen? |

Reduziere dies nicht auf eine Liste beworbener Integrationen. Ein nützliches Artefakt ordnet jede Quelle der genauen Kontextposition zu, an der sie ankommt, den dort verfügbaren Tools, den von jedem Tool verwendeten Zugangsdaten, dem nachgelagerten Interpreter und sämtlichen Egress-Pfaden. Dasselbe Tool kann mit einem benutzerspezifischen Read-Token geringe Auswirkungen haben und mit gemeinsamen Administrator-Zugangsdaten kritisch sein.<sup>[[2]](#references)</sup>

## Reconnaissance

### Alle Übermittlungs- und Ingestion-Pfade erfassen

Beginne mit der Übermittlungsoberfläche (Web, Mobile, API, E-Mail, Chat-Plattform, Browser-Erweiterung) und proxye den Client-zu-Backend-Datenverkehr. Untersuche in der UI verborgene Felder, Such-/Autocomplete-/Filterparameter, Konversationszustandsobjekte, Upload- und Indexierungsjobs, Tool-Antworten sowie Datenverkehr zwischen Subagenten. Bei Clients, die nur auf Mobilgeräten verfügbar sind, kann ein Emulator mit Instrumentierung erforderlich sein, um Certificate Pinning zu umgehen und das tatsächliche Request-Schema sichtbar zu machen.<sup>[[2]](#references)</sup>

Erfasse anschließend den Stack unterhalb des Modells: Orchestrierungs-Framework, Prompt-Zusammenstellung, Retrieval- und Memory-Speicher, Runtime (zum Beispiel Python, Container oder WASM), eingebundene Volumes, Host-Services, interne APIs, Erreichbarkeit von Cloud-Metadaten und benachbarte Netzwerke. Framework-Standardwerte sind relevant, denn manche „Tool-Aufrufe“ werden durch generierten oder ausgewerteten Code implementiert. Die Runtime-/Sandbox-Grenze entscheidet, ob das Ergebnis eingedämmt bleibt.<sup>[[2]](#references)</sup>

### Routing mit nicht destruktiven Probes erkennen

Vergleiche eine Anfrage innerhalb des Scope mit mehreren themenfremden Anfragen und bewahre dabei die vollständige Antwort, den Statuscode, die Latenz und das Streaming-Verhalten. Eine gleichbleibende Ablehnung vor jedem aufgabenspezifischen Reasoning kann auf ein separates Gateway/einen Classifier hindeuten; eine kontextbezogene Ablehnung lässt vermuten, dass die Anfrage das Modell erreicht hat; eine leere oder rein extraktive Antwort kann auf eine Stichwortsuche oder eingeschränktes Retrieval hindeuten. Behandle dies als Hypothesen und bestätige sie, indem du dieselbe Probe über alternative API-Felder und Ingestion-Pfade erneut ausführst.<sup>[[2]](#references)</sup>

Die Reconnaissance ist abgeschlossen, wenn das Assessment die früheste angreifergesteuerte Quelle benennen kann, die das Verhalten des Agenten verändert, **und** die von dieser Quelle aus erreichbaren Tools, Identitäten, Interpreter und Ausgaben.<sup>[[2]](#references)</sup>

## Exploitation: Eine Vertrauensgrenze überschreiten

Teste Kanäle, nicht nur die Formulierung des Prompts. Beginne mit direkter Injection, um festzustellen, was die sichtbare Eingangsoberfläche blockiert, und wiederhole dann dieselbe Absicht über die weniger sichtbaren Pfade:<sup>[[2]](#references)</sup>

- **Indirekte Inhalte:** Seiten, Dateien, E-Mails, Tickets, Metadaten, Alt-Text, HTML-Kommentare, nicht sichtbarer Text oder Zero-Width-Zeichen. Unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) findest du Techniken zur Payload-Übermittlung.
- **Retrieval und Memory:** Manipuliere Inhalte, die später abgerufen werden, oder Zustände, die in späteren Sitzungen erneut geladen werden. Halte fest, ob das Löschen der ursprünglichen Quelle das Verhalten beendet.
- **Tool-Ausgaben und Peer-Agenten:** Platziere den Marker in einer Tool-Antwort oder einer Nachricht zwischen Agenten, um zu prüfen, ob interner Datenverkehr Filter umgeht, die nur auf Benutzereingaben und finale Ausgaben angewendet werden.
- **Supply Chain:** Prüfe Tool-Beschreibungen, Plugins, verbundene Server, Skills, Modelle und Dependencies als vertrauenswürdige Anweisungsquellen. Spezifische Tests für MCP findest du unter [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menschliche Freigabe:** Vergleiche den tatsächlichen strukturierten Tool-Aufruf mit dem vom Modell erzeugten Freigabetext. Prüfe, ob ein Angreifer durch seine Einflussnahme das Ziel, den Umfang, die betroffenen Objekte oder irreversible Nebenwirkungen auslassen kann.

Verwende zuerst einen harmlosen, eindeutigen Marker. Sichere das Quellartefakt, den zusammengesetzten Kontext (falls beobachtbar), den ausgewählten Tool-Aufruf, Freigabedaten, Backend-Request/-Response und den Endzustand. So lässt sich Einfluss von einer halluzinierten Behauptung trennen, eine Aktion sei erfolgt.<sup>[[2]](#references)</sup>

### Kontextisolation von Subagenten

Ein Subagent des Claude Agent SDK, der nicht geforkt wird, erhält sein eigenes `AgentDefinition.prompt`, den Delegations-Prompt und seine verfügbaren Tools, aber nicht den System-Prompt oder die Konversation des übergeordneten Agenten. Wird `tools` in seiner Definition ausgelassen, übernimmt er die den Subagenten verfügbaren Tools. Die Projektdatei `CLAUDE.md` kann weiterhin geladen werden. Dadurch ist eine nur im übergeordneten Prompt enthaltene Einschränkung eine unzuverlässige Grenze, wenn das Kind dieselben Datei- oder Ausführungstools verwenden kann.<sup>[[4]](#references)</sup>

Teste die Grenze, indem du eine direkte Anfrage, die der übergeordnete Agent ablehnt, mit derselben Aufgabe vergleichst, die an einen benannten Subagenten delegiert wird. NCC Group berichtet, dass eine abgelehnte Dateiauflistung des Betriebssystems erfolgreich war, als sie für ein Kind als harmlose „Layout-Karte“ formuliert wurde.<sup>[[3]](#references)</sup>

Prüfe die tatsächlichen Tool-Aufrufe des Kindes und dessen effektive Tool-Allowlist, nicht nur die finale Antwort des übergeordneten Agenten. Bestätige, ob das Kind auf Dateien zugegriffen hat, auf die der übergeordnete Agent nicht zugreifen würde.<sup>[[4]](#references)</sup> Dies ist ein Fehler bei der Vererbung von Guardrails und kein Nachweis für einen [Python-Sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/)- oder Container-Escape.<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: Reale Auswirkungen nachweisen

Es gibt zwei unterschiedliche Wege von der Einflussnahme zu den Auswirkungen:<sup>[[2]](#references)</sup>

1. **Missbrauch von Fähigkeiten:** Das autorisierte Tool führt das gewünschte Ziel bereits aus. Beispiele sind das Lesen des Datensatzes eines Tenants und dessen Schreiben in einen für den Angreifer sichtbaren Bericht, das Senden einer E-Mail, das Ändern von Datensätzen, das Löschen einer Datei oder das Veranlassen einer Zahlung. Ein sekundärer Softwarefehler ist nicht erforderlich.
2. **Ausnutzung eines nachgelagerten Sinks:** Vom Angreifer gesteuerte Modellausgabe wird zur Syntax für eine andere Komponente. Prüfe Datenbankabfragen auf [SQL injection](../pentesting-web/sql-injection/README.md) oder [NoSQL injection](../pentesting-web/nosql-injection.md), Shell-Wrapper auf [command injection](../pentesting-web/command-injection.md), ausgewählte URLs auf [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), Dateioperationen auf Path Traversal, Template-/Code-Evaluatoren auf RCE und Objekt-Parser auf [unsafe deserialization](../pentesting-web/deserialization/README.md).

Weise für jeden möglichen Fall die folgende Kette nach:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Eine schreibgeschützte Integration ist weiterhin ausnutzbar, wenn eine spätere Komponente alles, was sie gelesen hat, veröffentlichen kann. Teste gewöhnliche Antworten sowie weniger offensichtliche Wege nach außen, etwa vom Angreifer kontrollierte Links, automatisches Abrufen von Bildern, Webhooks, Logs, Berichte, Zähler, Benachrichtigungen und Nachrichten an andere Agents.<sup>[[2]](#references)</sup>

## Aktionen zur Zielerreichung

Nachdem du eine Aktion bestätigt hast, bewerte die vollständigen Auswirkungen, statt bei der ersten sichtbaren Folge aufzuhören:<sup>[[2]](#references)</sup>

- **Exfiltration:** Geheimnisse, Benutzerdatensätze, interne Dateien, Konversationsdaten oder Prompt-/Kontextinhalte gelangen über einen beobachtbaren Kanal nach außen.
- **Unbefugte Aktion:** Der Agent nutzt legitime Schreibberechtigungen, um das Ziel des Angreifers zu erreichen.
- **Denial of Service:** Destruktive Tools oder wiederholte, kostspielige Vorgänge beeinträchtigen die Integrität oder Verfügbarkeit.
- **Persistenz:** Vergifteter Speicher, indexierte Inhalte, vertrauenswürdiger Zustand oder Laufzeitänderungen bleiben über die ursprüngliche Sitzung oder das Entfernen der Quelle hinaus bestehen.
- **Ausbreitung:** Ein vertrauenswürdiger Peer übernimmt die Nachricht oder den gemeinsam genutzten Zustand des kompromittierten Agents und wiederholt die Aktion mit seinen eigenen Tools und Zugangsdaten.

Der Schweregrad sollte sich nach den erreichbaren Daten, den effektiven Berechtigungen, der Ausnutzbarkeit des Sinks, dem Egress, der Persistenz und der Ausbreitung richten – nicht danach, wie überraschend der Text des Modells wirkt.<sup>[[2]](#references)</sup>

## Während der Bewertung zu prüfende Kontrollen

Prompt-Filter und ein besserer System-Prompt können den Aufwand für Angreifer erhöhen, sollten aber nicht als Autorisierungsgrenzen behandelt werden. Prüfe die folgenden Kontrollen, indem du dieselbe Angriffskette erneut über direkte Eingaben, indirekte Inhalte, Speicher, Tools und Peer-Agents ausführst:<sup>[[2]](#references)</sup>

- Eine deterministische Richtlinienebene prüft bei **jedem Tool-Aufruf** den authentifizierten Benutzer, den Mandanten, das Objekt, die Aktion und das Ziel; das Modell kann die Identität des Aufrufenden weder angeben noch überschreiben.
- Lese- und Schreibberechtigungen verwenden getrennte, minimal privilegierte, kurzlebige Zugangsdaten; Tools mit hohen Auswirkungen werden nur bei Bedarf verfügbar gemacht und niemals automatisch aufgrund eingelesener Inhalte ausgeführt.
- Netzwerkausgänge und interne Ziele werden unabhängig von den vom Modell ausgewählten URLs auf eine Allowlist gesetzt; der Laufzeitzugriff auf Metadaten-Endpunkte, eingebundene Geheimnisse und benachbarte Dienste wird blockiert, sofern er nicht erforderlich ist.
- Die Freigabeoberfläche wird aus der maßgeblichen strukturierten Anfrage erzeugt und zeigt die exakten Argumente, die Identität, das Ziel, die betroffenen Objekte und die Nebenwirkungen an – nicht eine frei formulierte Zusammenfassung des Modells.
- Der Erfolg wird anhand des Zielsystems oder des führenden Systems überprüft. Die Schilderung des Agents, eine Tool-Aufrufanfrage oder eine HTTP-Weiterleitung beweisen nicht, dass die behauptete Zustandsänderung erfolgt ist.
- Speicher- und Retrieval-Einträge behalten Herkunftsinformationen und Vertrauenslabels, können ungültig gemacht werden und werden bei der Verwendung für eine spätere Aktion erneut autorisiert.
- Inter-Agent-Nachrichten werden als nicht vertrauenswürdige Anfragen authentifiziert und autorisiert; der Ruf eines Peers oder dessen Agent Card delegiert nicht automatisch die Tools des empfangenden Agents.

## References

- [1] [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [The Hacker's Guide to Attacking AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [How Hard Is It Really to Break an AI Agent Out of Its Sandbox?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents in the SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
