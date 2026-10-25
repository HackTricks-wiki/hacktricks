# AI-Agent-Sicherheitsmethodik

{{#include ../banners/hacktricks-training.md}}

Eine Agentenbewertung sollte **vom angreiferkontrollierten Input bis zu einer extern beobachtbaren Wirkung** reichen. Jailbreaking, Zeichenänderungen und die Offenlegung des System-Prompts belegen, dass ein Reasoning-Kanal beeinflussbar ist. Der schwerwiegende Befund ist jedoch die Angriffskette bis zum Datenzugriff, einer nicht autorisierten Tool-Aktion, einem nachgelagerten Injection-Sink, Persistenz oder einem anderen Agenten.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) eignet sich zur Kennzeichnung der Abdeckung (Goal Hijacking, Tool-Missbrauch, Privilegienmissbrauch, Supply Chain, Codeausführung, Memory Poisoning, Vertrauen zwischen Agenten, kaskadierende Fehler, menschliches Vertrauen und Rogue Agents). Verwenden Sie diese Kennzeichnungen, nachdem Sie einen durchgängigen Angriffspfad erstellt haben, statt unerwarteten Modelltext als Ende des Tests zu betrachten.<sup>[[1]](#references)[[2]](#references)</sup>

## Zielübersicht erstellen

Erfassen Sie vor dem Erstellen von Payloads für jeden Agenten-Workflow die folgenden fünf Dimensionen:<sup>[[2]](#references)</sup>

| Dimension | Was zu erfassen ist | Sicherheitsfrage |
|---|---|---|
| **Nicht vertrauenswürdiger Input** | Chat/API-Parameter, URLs, Dokumente, E-Mail, Tickets, Kalendereinträge, abgerufene Chunks, Memory, Tool-Ergebnisse und Nachrichten von Peer-Agenten | Wo kann ein Angreifer Inhalte platzieren, die später in den Modellkontext gelangen? |
| **Tools** | Tool-Namen und -Schemas, Nebenwirkungen, automatische Ausführung, Bestätigungsverhalten und dynamisch geladene Tools | Welche Aufrufe lesen Secrets, schreiben Daten, senden Nachrichten, löschen Daten, führen Code aus oder übertragen Werte? |
| **Berechtigungen** | Benutzerdelegierung, Servicekonten, API-Tokens, Gültigkeitsdauer von Zugangsdaten, Mandanten-/Ressourcenbereich und Netzwerkzugriff | Mit welcher Identität wird jeder Aufruf ausgeführt, und wird die Autorisierung an der Tool-Grenze erneut geprüft? |
| **Verarbeitung** | Query Builder, Shells, URL-Abrufprogramme, Template Engines, Interpreter, Parser, Dateioperationen und Deserialisierer | Wo werden vom Modell generierte Daten zur Syntax für einen anderen Interpreter? |
| **Ausgabe** | Antworten, gerendertes Markdown/HTML, Links, Bildabrufe, Webhooks, E-Mail, Dateien, Logs, Berichte, Metriken und Peer-Agent-Verkehr | Über welchen beobachtbaren Kanal kann ein Secret übertragen oder eine sekundäre Anfrage ausgelöst werden? |

Reduzieren Sie dies nicht auf eine Liste der beworbenen Integrationen. Ein nützliches Artefakt ordnet jeder Quelle die genaue Kontextposition zu, die sie erreicht, die dort verfügbaren Tools, die von jedem Tool verwendeten Zugangsdaten, den nachgelagerten Interpreter und alle Egress-Routen. Dasselbe Tool kann mit einem benutzerspezifischen Lesetoken geringe Auswirkungen haben und mit einem gemeinsamen Administratorzugang kritisch sein.<sup>[[2]](#references)</sup>

## Aufklärung

### Alle Zustellungs- und Ingestion-Pfade erfassen

Beginnen Sie mit der Zustellungsoberfläche (Web, Mobile, API, E-Mail, Chat-Plattform, Browser-Erweiterung) und analysieren Sie den Client-zu-Backend-Verkehr über einen Proxy. Prüfen Sie von der UI verborgene Felder, Such-/Autocomplete-/Filterparameter, Konversationszustandsobjekte, Upload- und Indexierungsjobs, Tool-Antworten und Subagent-Verkehr. Bei reinen Mobile-Clients sind möglicherweise ein Emulator und Instrumentierung erforderlich, um Certificate Pinning zu umgehen, bevor das tatsächliche Request-Schema sichtbar wird.<sup>[[2]](#references)</sup>

Erfassen Sie anschließend den Stack unterhalb des Modells: Orchestrierungsframework, Prompt-Zusammenstellung, Retrieval- und Memory-Speicher, Runtime (zum Beispiel Python, Container oder WASM), eingebundene Volumes, Host-Dienste, interne APIs, Erreichbarkeit von Cloud-Metadaten und benachbarte Netzwerke. Framework-Standardeinstellungen sind wichtig, da manche „Tool-Aufrufe“ durch das Generieren oder Auswerten von Code umgesetzt werden. Die Runtime-/Sandbox-Grenze entscheidet, ob das Ergebnis eingeschlossen bleibt.<sup>[[2]](#references)</sup>

### Routing mit nicht destruktiven Probes ermitteln

Vergleichen Sie eine im Geltungsbereich liegende Anfrage mit mehreren nicht zusammenhängenden Anfragen und bewahren Sie dabei die vollständige Antwort, den Statuscode, die Latenz und das Streaming-Verhalten. Eine stabile Ablehnung vor jeder aufgabenspezifischen Verarbeitung kann auf ein separates Gateway/einen separaten Classifier hindeuten; eine kontextbezogene Ablehnung lässt vermuten, dass die Anfrage das Modell erreicht hat; eine leere oder rein extraktive Antwort kann auf eine Stichwortsuche oder ein begrenztes Retrieval hindeuten. Behandeln Sie dies als Hypothesen und bestätigen Sie sie, indem Sie dieselbe Probe über alternative API-Felder und Ingestion-Pfade erneut ausführen.<sup>[[2]](#references)</sup>

Die Aufklärung ist abgeschlossen, wenn die Bewertung die früheste angreiferkontrollierte Quelle benennen kann, die das Verhalten des Agenten verändert, **sowie** die von dieser Quelle erreichbaren Tools, Identitäten, Interpreter und Ausgaben.<sup>[[2]](#references)</sup>

## Exploitation: Eine Vertrauensgrenze überschreiten

Testen Sie Kanäle, nicht nur Prompt-Formulierungen. Beginnen Sie mit einer direkten Injection, um festzustellen, was der sichtbare Einstiegspunkt blockiert, und wiederholen Sie dann eine gleichwertige Absicht über die weniger sichtbaren Pfade unten:<sup>[[2]](#references)</sup>

- **Indirekte Inhalte:** Seiten, Dateien, E-Mail, Tickets, Metadaten, Alt-Text, HTML-Kommentare, außerhalb des Bildschirms platzierter Text oder Zero-Width-Zeichen. Siehe [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) für Techniken zur Payload-Zustellung.
- **Retrieval und Memory:** Inhalte vergiften, die später abgerufen werden, oder Zustände, die in späteren Sitzungen erneut geladen werden. Halten Sie fest, ob das Löschen der ursprünglichen Quelle das Verhalten beendet.
- **Tool-Ausgabe und Peer-Agenten:** Platzieren Sie den Marker in einer Tool-Antwort oder einer Agent-zu-Agent-Nachricht, um zu testen, ob interner Verkehr Filter umgeht, die nur auf Benutzereingaben und die endgültige Ausgabe angewendet werden.
- **Supply Chain:** Prüfen Sie Tool-Deskriptoren, Plugins, verbundene Server, Skills, Modelle und Abhängigkeiten als vertrauenswürdige Anweisungsquellen. MCP-spezifische Tests finden Sie unter [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menschliche Genehmigung:** Vergleichen Sie den tatsächlichen strukturierten Tool-Aufruf mit dem vom Modell generierten Genehmigungstext. Testen Sie, ob ein Angreifer die Angaben zu Ziel, Umfang, betroffenen Objekten oder irreversiblen Nebenwirkungen weglassen kann.

Verwenden Sie zuerst einen harmlosen, eindeutigen Marker. Bewahren Sie das Quellartefakt, den zusammengestellten Kontext (falls einsehbar), den ausgewählten Tool-Aufruf, die Genehmigungsdaten, die Backend-Anfrage/-Antwort und den endgültigen Zustand auf. So lässt sich tatsächliche Beeinflussung von einer halluzinierten Behauptung unterscheiden, eine Aktion sei erfolgt.<sup>[[2]](#references)</sup>

### Richtlinienähnlicher Text in einem Tool-Risiko-Judge

Ein modellbasiertes Tool-Gateway kann angreiferkontrollierten Text innerhalb eines ansonsten nützlichen Klassifizierungskontexts erhalten. LangChains experimentelles `AutoModeMiddleware` sendet beispielsweise einen vorgeschlagenen Tool-Aufruf, dessen Argumente, eine optionale Tool-Beschreibung und bis zu 30 aktuelle Nachrichten an einen TypeSafe-`is_risky`-Judge. Es blockiert konfigurierte Tools, wenn die zurückgegebene Noul-Wahrscheinlichkeit mindestens `0.5` beträgt; nicht aufgeführte Tools werden von dieser Middleware nicht klassifiziert.<sup>[[5]](#references)</sup> TypeSafe warnt außerdem, dass adversarialer Text im Zustand eine Klassifizierung beeinflussen kann, selbst wenn der Zustand als Daten gedacht ist.<sup>[[6]](#references)</sup>

Eine **gefälschte Richtlinie** unterscheidet sich von der bloßen Behauptung, eine Systemnachricht zu sein. Sie platziert alternative Bezeichnungen oder Risikodefinitionen in einem Zustand mit geringerem Vertrauensniveau und fordert den Judge auf, diese Definitionen statt der vom Entwickler festgelegten Kriterien zu verwenden. Im Test von Datadog wurde eine vom Benutzer bearbeitbare `profile_description` zusammen mit `can_edit:false` in die Tool-Argumente kopiert. Der richtlinienähnliche Text argumentierte, ein Schreibversuch sei risikoarm, da eine separate Berechtigungsprüfung ihn vor einer Änderung ablehnen sollte. In 40 Durchläufen sank der mittlere `is_risky`-Wert von `0.893` auf `0.290`, während ein direkter Vergleich mit vorgetäuschter Rolle im Mittel `0.905` ergab. Dass der Mittelwert unter `0.5` fiel, beweist nicht, dass jeder einzelne Aufruf das Gateway passierte, und das Experiment zeigte **keinen** abgeschlossenen, nicht autorisierten Schreibvorgang.<sup>[[7]](#references)</sup>

Unterscheiden Sie beim Testen dieser Grenze das Urteil des Classifiers vom tatsächlichen Autorisierungsergebnis des Tools. Prüfen Sie, welche bearbeitbaren Felder den Judge erreichen, vergleichen Sie dieselbe vorgeschlagene Aktion mit und ohne richtlinienähnlichen Text und überprüfen Sie den endgültigen Zustand unabhängig. Eine separate Berechtigungsprüfung muss weiterhin die Berechtigungen des authentifizierten Anfragenden verwenden, nicht die Rechte des Servicekontos des Connectors.<sup>[[7]](#references)</sup> Siehe [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) zu anderen Fehlerarten von Classifiern; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) betreffen eine andere Routing- und Berechtigungsgrenze.

### Isolation des Subagent-Kontexts

Ein Subagent ohne Fork im Claude Agent SDK erhält seine eigene `AgentDefinition.prompt`, den Delegierungs-Prompt und die verfügbaren Tools, aber nicht den System-Prompt oder die Konversation des übergeordneten Agenten. Wenn `tools` in seiner Definition fehlt, übernimmt er die den Subagenten verfügbaren Tools; die Projektdatei `CLAUDE.md` kann weiterhin geladen werden. Dadurch ist eine Einschränkung im Prompt des übergeordneten Agenten eine unzuverlässige Grenze, wenn das Child dieselben Datei- oder Ausführungstools verwenden kann.<sup>[[4]](#references)</sup>

Testen Sie die Grenze, indem Sie eine direkte Anfrage, die der übergeordnete Agent ablehnt, mit derselben Aufgabe vergleichen, die an einen benannten Subagenten delegiert wird. NCC Group berichtet, dass eine abgelehnte Aufzählung von Betriebssystemdateien erfolgreich war, als sie für ein Child als harmlose „layout map“ formuliert wurde.<sup>[[3]](#references)</sup>

Prüfen Sie die tatsächlichen Tool-Aufrufe des Childs und dessen wirksame Tool-Zulassungsliste, nicht nur die endgültige Antwort des übergeordneten Agenten. Bestätigen Sie, ob das Child auf Dateien zugegriffen hat, auf die der übergeordnete Agent nicht zugreifen würde.<sup>[[4]](#references)</sup> Dies ist ein Fehler bei der Übernahme von Schutzmaßnahmen, kein Beleg für einen [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) oder Container-Ausbruch.<sup>[[3]](#references)[[4]](#references)</sup>

## Ausführung: Tatsächliche Auswirkungen nachweisen

Es gibt zwei unterschiedliche Wege von der Beeinflussung zu den Auswirkungen:<sup>[[2]](#references)</sup>

1. **Missbrauch von Fähigkeiten:** Das autorisierte Tool führt das gewünschte Ziel bereits aus. Beispiele sind das Lesen eines Datensatzes eines Mandanten und dessen Schreiben in einen für den Angreifer sichtbaren Bericht, das Senden von E-Mails, Ändern von Datensätzen, Löschen einer Datei oder Einleiten einer Zahlung. Eine sekundäre Software-Schwachstelle ist nicht erforderlich.
2. **Exploitation eines nachgelagerten Sinks:** Eine vom Angreifer gesteuerte Modellausgabe wird zur Syntax für eine andere Komponente. Prüfen Sie Datenbankabfragen auf [SQL injection](../pentesting-web/sql-injection/README.md) oder [NoSQL injection](../pentesting-web/nosql-injection.md), Shell-Wrapper auf [command injection](../pentesting-web/command-injection.md), ausgewählte URLs auf [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), Dateioperationen auf Traversal, Template-/Code-Evaluatoren auf RCE und Objektparser auf [unsafe deserialization](../pentesting-web/deserialization/README.md).

Weisen Sie für jeden möglichen Befund diese Kette nach:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Eine schreibgeschützte Integration ist weiterhin ausnutzbar, wenn eine nachgelagerte Komponente veröffentlichen kann, was sie gelesen hat. Teste gewöhnliche Antworten sowie weniger offensichtliche Wege nach außen, etwa vom Angreifer kontrollierte Links, automatisches Abrufen von Bildern, Webhooks, Logs, Berichte, Zähler, Benachrichtigungen und Nachrichten an andere Agents.<sup>[[2]](#references)</sup>

## Aktionen auf Ziele

Nachdem du eine Aktion bestätigt hast, bewerte das gesamte Ausmaß der Auswirkungen, statt bei der ersten sichtbaren Wirkung aufzuhören:<sup>[[2]](#references)</sup>

- **Exfiltration:** Geheimnisse, Benutzerdatensätze, interne Dateien, Konversationsdaten oder Prompt-/Kontextinhalte verlassen das System über einen beobachtbaren Kanal.
- **Nicht autorisierte Aktion:** Der Agent nutzt legitime Schreibberechtigungen für das Ziel des Angreifers.
- **Denial of service:** Destruktive Tools oder wiederholte kostspielige Vorgänge beeinträchtigen die Integrität oder Verfügbarkeit.
- **Persistenz:** Vergifteter Speicher, indexierte Inhalte, vertrauenswürdiger Zustand oder Laufzeitänderungen bleiben über die ursprüngliche Sitzung oder das Entfernen der Quelle hinaus bestehen.
- **Ausbreitung:** Ein vertrauenswürdiger Peer konsumiert die Nachricht oder den gemeinsamen Zustand des kompromittierten Agents und wiederholt die Aktion mit seinen eigenen Tools und Zugangsdaten.

Der Schweregrad sollte sich nach den erreichbaren Daten, den effektiven Berechtigungen, der Ausnutzbarkeit des Senkenpunkts, dem Weg nach außen, der Persistenz und der Ausbreitung richten – nicht danach, wie überraschend der Text des Modells erscheint.<sup>[[2]](#references)</sup>

## Während der Bewertung zu validierende Kontrollen

Prompt-Filter und ein besserer System-Prompt können den Aufwand für Angreifer erhöhen, sollten aber nicht als Autorisierungsgrenzen betrachtet werden. Validiere die folgenden Kontrollen, indem du dieselbe Angriffskette erneut über direkte Eingaben, indirekte Inhalte, Speicher, Tools und Peer-Agents ausführst:<sup>[[2]](#references)</sup>

- Eine deterministische Richtlinienebene prüft bei **jedem Tool-Aufruf** den authentifizierten Benutzer, Mandanten, das Objekt, die Aktion und das Ziel; das Modell kann die Identität des Aufrufers weder angeben noch überschreiben.
- Lese- und Schreibberechtigungen verwenden getrennte, möglichst restriktive, kurzlebige Zugangsdaten; Tools mit weitreichenden Auswirkungen werden nur bei Bedarf freigegeben und nie automatisch aufgrund eingelesener Inhalte ausgeführt.
- Netzwerkverbindungen nach außen und interne Ziele werden unabhängig von den vom Modell ausgewählten URLs auf eine Zulassungsliste gesetzt; der Laufzeitzugriff auf Metadaten-Endpunkte, eingebundene Geheimnisse und benachbarte Dienste wird blockiert, sofern er nicht erforderlich ist.
- Die Genehmigungsoberfläche wird aus der maßgeblichen strukturierten Anfrage erzeugt und zeigt die exakten Argumente, Identität, Ziel, betroffenen Objekte und Nebenwirkungen an – nicht eine frei formulierte Modellzusammenfassung.
- Der Erfolg wird anhand des Zielsystems oder des führenden Datensystems überprüft. Die Erzählung des Agents, eine Tool-Aufrufanfrage oder eine HTTP-Weiterleitung beweisen nicht, dass die behauptete Zustandsänderung erfolgt ist.
- Speicher- und Retrieval-Einträge behalten Herkunftsinformationen und Vertrauenskennzeichnungen bei, können für ungültig erklärt werden und werden erneut autorisiert, wenn sie für eine spätere Aktion verwendet werden.
- Nachrichten zwischen Agents werden authentifiziert und als nicht vertrauenswürdige Anfragen autorisiert; der Ruf eines Peers oder eine Agent Card überträgt nicht automatisch die Tools des Empfängers.

Informationen zu A2A Agent Cards, Aufgabenabläufen und deren Angriffsfläche findest du unter [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 für agentische Anwendungen 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Das Hacker-Handbuch zum Angriff auf AI-Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Wie schwer ist es wirklich, einen AI-Agent aus seiner Sandbox auszubrechen?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents im SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Quellcode der LangChain-TypeSafe-Auto-Mode-Middleware](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-Modell-Jaggedness: adversariale Inhalte](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev als Richter: Wie gefälschte Richtlinien Jev beeinflussen](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
