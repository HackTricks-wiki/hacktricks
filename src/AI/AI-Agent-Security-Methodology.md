# AI-Agent-Sicherheitsmethodik

{{#include ../banners/hacktricks-training.md}}

Eine Agent-Bewertung sollte **vom angreiferkontrollierten Input bis zu einem extern beobachtbaren Effekt** reichen. Jailbreaking, Zeichenänderungen und die Offenlegung des System-Prompts belegen, dass ein Reasoning-Kanal beeinflussbar ist. Der besonders schwerwiegende Befund ist jedoch die Kette zu Datenzugriff, einer nicht autorisierten Tool-Aktion, einem nachgelagerten Injection-Sink, Persistenz oder einem anderen Agenten.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) eignet sich, um die Abdeckung zu kennzeichnen (Goal Hijacking, Tool-Missbrauch, Privilegienmissbrauch, Supply Chain, Codeausführung, Memory Poisoning, Vertrauen zwischen Agenten, kaskadierende Fehler, menschliches Vertrauen und Rogue Agents). Verwende diese Bezeichnungen, nachdem du einen durchgängigen Angriffspfad erstellt hast, anstatt unerwarteten Text eines Modells als Ende des Tests zu betrachten.<sup>[[1]](#references)[[2]](#references)</sup>

## Zielübersicht erstellen

Erfasse vor dem Erstellen von Payloads für jeden Agenten-Workflow diese fünf Dimensionen:<sup>[[2]](#references)</sup>

| Dimension | Was zu erfassen ist | Sicherheitsfrage |
|---|---|---|
| **Nicht vertrauenswürdiger Input** | Chat-/API-Parameter, URLs, Dokumente, E-Mails, Tickets, Kalendereinträge, abgerufene Chunks, Memory, Tool-Ergebnisse und Nachrichten anderer Agenten | Wo kann ein Angreifer Inhalte platzieren, die später in den Modellkontext gelangen? |
| **Tools** | Tool-Namen und -Schemas, Seiteneffekte, automatische Ausführung, Bestätigungsverhalten und dynamisch geladene Tools | Welche Aufrufe lesen Secrets, schreiben Daten, senden Nachrichten, löschen Daten, führen Code aus oder übertragen Werte? |
| **Berechtigungen** | Benutzerdelegierung, Servicekonten, API-Tokens, Gültigkeitsdauer von Zugangsdaten, Mandanten-/Ressourcenbereich und Netzwerkreichweite | Unter welcher Identität wird jeder Aufruf ausgeführt, und wird die Autorisierung an der Tool-Grenze erneut geprüft? |
| **Verarbeitung** | Query-Builder, Shells, URL-Fetcher, Template-Engines, Interpreter, Parser, Dateizugriffe und Deserialisierer | Wo werden vom Modell generierte Daten zur Syntax für einen anderen Interpreter? |
| **Ausgabe** | Antworten, gerendertes Markdown/HTML, Links, Bildabrufe, Webhooks, E-Mails, Dateien, Logs, Berichte, Metriken und Nachrichten zwischen Agenten | Welcher beobachtbare Kanal kann ein Secret übertragen oder eine sekundäre Anfrage auslösen? |

Fasse dies nicht zu einer Liste beworbener Integrationen zusammen. Ein nützliches Artefakt ordnet jede Quelle der genauen Kontextposition zu, die sie erreicht, den an dieser Stelle verfügbaren Tools, den von jedem Tool verwendeten Zugangsdaten, dem nachgelagerten Interpreter und allen Egress-Routen. Dasselbe Tool kann mit einem benutzerspezifischen Read-Token geringe Auswirkungen haben und mit gemeinsam genutzten Administrator-Zugangsdaten kritisch sein.<sup>[[2]](#references)</sup>

## Aufklärung

### Alle Übermittlungs- und Eingabepfade erfassen

Beginne mit der Angriffsfläche für die Übermittlung (Web, Mobilgerät, API, E-Mail, Chat-Plattform, Browsererweiterung) und zeichne den Client-zu-Backend-Verkehr über einen Proxy auf. Untersuche Felder, die in der UI verborgen sind, Such-/Autovervollständigungs-/Filterparameter, Conversation-State-Objekte, Upload- und Indexierungsjobs, Tool-Antworten sowie den Verkehr zwischen Subagenten. Bei ausschließlich mobilen Clients sind möglicherweise ein Emulator und Instrumentierung erforderlich, um Certificate Pinning zu umgehen und das tatsächliche Request-Schema sichtbar zu machen.<sup>[[2]](#references)</sup>

Erfasse anschließend den Stack unterhalb des Modells: Orchestrierungsframework, Prompt-Zusammenstellung, Retrieval- und Memory-Stores, Runtime (zum Beispiel Python, Container oder WASM), eingebundene Volumes, Host-Dienste, interne APIs, Erreichbarkeit von Cloud-Metadaten und benachbarte Netzwerke. Framework-Standardeinstellungen sind wichtig, da manche „Tool-Aufrufe“ durch das Generieren oder Evaluieren von Code umgesetzt werden. Die Runtime-/Sandbox-Grenze bestimmt, ob das Ergebnis eingeschlossen bleibt.<sup>[[2]](#references)</sup>

### Routing mit nicht destruktiven Probes erkennen

Vergleiche eine Anfrage im Geltungsbereich mit mehreren themenfremden Anfragen und erfasse dabei jeweils die vollständige Antwort, den Statuscode, die Latenz und das Streaming-Verhalten. Eine konsistente Ablehnung vor jeglichem aufgabenspezifischen Reasoning kann auf ein separates Gateway/einen separaten Classifier hindeuten; eine kontextbezogene Ablehnung legt nahe, dass die Anfrage das Modell erreicht hat; eine leere oder rein extraktive Antwort kann auf eine Stichwortsuche oder eingeschränktes Retrieval hindeuten. Behandle dies als Hypothesen und bestätige sie, indem du dieselbe Probe über alternative API-Felder und Eingabepfade erneut ausführst.<sup>[[2]](#references)</sup>

Die Aufklärung ist abgeschlossen, wenn die Bewertung die früheste angreiferkontrollierte Quelle benennen kann, die das Verhalten des Agenten verändert, **sowie** die von dieser Quelle erreichbaren Tools, Identitäten, Interpreter und Ausgaben.<sup>[[2]](#references)</sup>

## Exploitation: Eine Vertrauensgrenze überschreiten

Teste Kanäle, nicht nur Prompt-Formulierungen. Beginne mit direkter Injection, um festzustellen, was die sichtbare Eingangsstelle blockiert, und wiederhole dann eine gleichwertige Absicht über die weniger sichtbaren Pfade unten:<sup>[[2]](#references)</sup>

- **Indirekte Inhalte:** Seiten, Dateien, E-Mails, Tickets, Metadaten, Alt-Text, HTML-Kommentare, Text außerhalb des sichtbaren Bereichs oder Zero-Width-Zeichen. Unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) findest du Techniken zur Payload-Zustellung.
- **Retrieval und Memory:** Inhalte vergiften, die später abgerufen werden, oder Zustände, die in späteren Sitzungen erneut geladen werden. Erfasse, ob das Löschen der ursprünglichen Quelle das Verhalten beendet.
- **Tool-Ausgabe und andere Agenten:** Platziere den Marker in einer Tool-Antwort oder einer Nachricht zwischen Agenten, um zu testen, ob interner Verkehr Filter umgeht, die nur auf Benutzereingaben und finale Ausgaben angewendet werden.
- **Supply Chain:** Prüfe Tool-Deskriptoren, Plugins, verbundene Server, Skills, Modelle und Abhängigkeiten als vertrauenswürdige Instruktionsquellen. Spezifische Tests für MCP findest du unter [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menschliche Freigabe:** Vergleiche den tatsächlichen strukturierten Tool-Aufruf mit dem vom Modell generierten Freigabetext. Teste, ob der Angreifereinfluss das Ziel, den Umfang, betroffene Objekte oder irreversible Seiteneffekte auslassen kann.

Verwende zuerst einen harmlosen, eindeutigen Marker. Bewahre das Quellartefakt, den zusammengesetzten Kontext (falls einsehbar), den ausgewählten Tool-Aufruf, die Freigabedaten, die Backend-Anfrage/-Antwort und den finalen Zustand auf. So lässt sich Einfluss von einer halluzinierten Behauptung unterscheiden, eine Aktion sei erfolgt.<sup>[[2]](#references)</sup>

### Policy-ähnlicher Text in einem Tool-Risiko-Judge

Ein modellbasiertes Tool-Gate kann angreiferkontrollierten Text innerhalb eines ansonsten nützlichen Klassifizierungskontexts erhalten. LangChains experimentelle `AutoModeMiddleware` sendet beispielsweise einen vorgeschlagenen Tool-Aufruf, dessen Argumente, eine optionale Tool-Beschreibung und bis zu 30 aktuelle Nachrichten an einen TypeSafe-`is_risky`-Judge. Sie blockiert konfigurierte Tools, wenn die zurückgegebene Noul-Wahrscheinlichkeit mindestens `0.5` beträgt; nicht aufgeführte Tools werden von dieser Middleware nicht klassifiziert.<sup>[[5]](#references)</sup> TypeSafe warnt außerdem, dass adversarialer Text im State eine Klassifizierung beeinflussen kann, selbst wenn der State als Daten gedacht ist.<sup>[[6]](#references)</sup>

Eine **gefälschte Policy** unterscheidet sich von der bloßen Behauptung, eine Systemnachricht zu sein. Sie platziert alternative Labels oder Risikodefinitionen in einem Zustand mit geringerem Vertrauensniveau und fordert den Judge auf, diese Definitionen statt der vom Entwickler festgelegten Kriterien zu verwenden. Im Test von Datadog wurde eine vom Benutzer bearbeitbare `profile_description` neben `can_edit:false` in die Tool-Argumente kopiert. Ihr Policy-ähnlicher Text argumentierte, ein Schreibversuch sei risikoarm, weil eine separate Berechtigungsprüfung ihn vor jeder Änderung ablehnen sollte. Über 40 Durchläufe sank der mittlere `is_risky`-Score von `0.893` auf `0.290`, während ein direkter Vergleich mit gefälschter Rolle im Mittel `0.905` ergab. Dass der Mittelwert unter `0.5` liegt, beweist nicht, dass jeder einzelne Aufruf das Gate passierte; außerdem wurde in diesem Experiment **kein** abgeschlossener nicht autorisierter Schreibvorgang nachgewiesen.<sup>[[7]](#references)</sup>

Unterscheide beim Testen dieser Grenze das Urteil des Classifiers vom tatsächlichen Autorisierungsergebnis des Tools. Prüfe, welche bearbeitbaren Felder den Judge erreichen, vergleiche dieselbe vorgeschlagene Aktion mit und ohne Policy-ähnlichen Text und überprüfe den finalen Zustand unabhängig. Eine separate Berechtigungsprüfung muss weiterhin die Berechtigungen des authentifizierten Anfragenden verwenden, nicht die Rechte des Servicekontos des Connectors.<sup>[[7]](#references)</sup> Weitere Fehlerarten von Classifiern findest du unter [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass); [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) betreffen eine andere Routing- und Berechtigungsgrenze.

### Kontextisolierung von Subagenten

Ein Nicht-Fork-Subagent des Claude Agent SDK erhält seine eigene `AgentDefinition.prompt`, den Delegierungs-Prompt und seine verfügbaren Tools, aber nicht den System-Prompt oder die Konversation des übergeordneten Agenten. Wenn `tools` in seiner Definition fehlt, erbt er die den Subagenten verfügbaren Tools; die Projektdatei `CLAUDE.md` kann weiterhin geladen werden. Dadurch ist eine Prompt-Beschränkung, die nur für den übergeordneten Agenten gilt, eine unzuverlässige Grenze, wenn das Kind dieselben Dateisystem- oder Ausführungstools verwenden kann.<sup>[[4]](#references)</sup>

Teste die Grenze, indem du eine direkte Anfrage vergleichst, die der übergeordnete Agent ablehnt, mit derselben Aufgabe, die an einen benannten Subagenten delegiert wird. NCC Group berichtet, dass eine abgelehnte Betriebssystem-Dateiauflistung erfolgreich war, als sie für ein Kind als harmlose „Layout-Karte“ umformuliert wurde.<sup>[[3]](#references)</sup>

Untersuche die tatsächlichen Tool-Aufrufe des Kindes und dessen effektive Tool-Allowlist, nicht nur die finale Antwort des übergeordneten Agenten. Bestätige, ob das Kind auf Dateien zugegriffen hat, auf die der übergeordnete Agent nicht zugreifen würde.<sup>[[4]](#references)</sup> Dies ist ein Fehler bei der Vererbung von Guardrails, kein Beweis für eine [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) oder einen Container-Escape.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI-Agenten: Bildschirminstruktionen und Aktionsumbindung

Ein Phone-GUI-Agent kann jeden Screenshot an ein Cloud-Modell senden, bevor er die nächste anwendungsübergreifende Aktion auswählt. Um **indirekte visuelle Injection** zu testen, platziere angreiferkontrollierten Text in einer SMS, E-Mail oder Seite, die der Agent während einer autorisierten Aufgabe prüft. Vergleiche einen direkten Aufgaben-Prompt mit derselben Instruktion, die nur im Screenshot sichtbar ist, und untersuche anschließend die nächste Aktion sowie jede Entscheidung zu risikoreichen Vorgängen. Beim geprüften Assistenten filterte das clientseitige `checkPrompt` direkte Aufgabentexte, wandte aber keine gleichwertige Filterung auf Screenshot-Inhalte an. Dies ist eine mobile, anwendungsübergreifende Variante der [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), keine Möglichkeit, die Android-Komponentenauthentifizierung zu umgehen.<sup>[[9]](#references)</sup>

Ein veranschaulichender Seiteneffekt-Test verwendet ein angreiferkontrolliertes Formular, das den Agenten auffordert, sensible Felder auszufüllen, und dann einen menschlichen Klick auf „upload“ verlangt, während die Seite die ausgefüllten Felder sofort übermittelt, sobald sie geändert werden. Die Übergabe an einen Menschen schützt keine Daten, die bereits vom Seitencode gesendet wurden. Überprüfe die tatsächliche Übermittlung, statt die Erzählung des Agenten als Beweis zu werten. Die Quelle beschreibt dies als mögliches Muster, nicht als nachgewiesene Kompromittierung jedes Assistenten.<sup>[[9]](#references)</sup>

**GUI TOCTOU / Aktionsumbindung** ist ein separater Fehlermodus: Der Agent plant eine Eingabe anhand eines bei `t0` beobachteten Bildschirms, aber die Vordergrund-UI ändert sich, bevor die Eingabe bei `t1` injiziert wird.<sup>[[8]](#references)</sup> Ein späterer Screenshot bei `t2` kann eine bereits ausgeführte Aktion nicht rückgängig machen.<sup>[[9]](#references)</sup> Bei einem autorisierten Android-Test sieht der wiederverwendbare Workflow wie folgt aus:<sup>[[8]](#references)</sup>

1. Ermittle die Bildschirmkoordinaten des Ziel-Steuerelements und rendere in einer kontrollierten App an derselben Stelle ein harmloses Steuerelement.
2. Lasse diese Träger-App sichtbar, bis der Agent sie beobachtet hat, und löse dann während der Lücke zwischen Beobachtung und Aktion einen normalen Wechsel der Vordergrund-App aus.
3. Prüfe, ob der geplante Tap auf dem Steuerelement der neuen App landet, und überprüfe den daraus resultierenden Zustand in der Ziel-App, statt dich auf die Erzählung des Agenten zu verlassen.

Die ursprüngliche Studie zur Aktionsumbindung demonstriert dies mit einer App, die keine gefährlichen Berechtigungen besitzt. Sie beschreibt außerdem, wie sich der Wechsel für mehrstufige Abläufe über die Task-Wiederherstellungsschleife des Agenten wiederholen lässt.<sup>[[8]](#references)</sup>

Gehe **nicht** davon aus, dass das Primitive unverändert bei jedem Assistenten funktioniert. Bei der Doubao-Bewertung übersprang `OpClickUI` Klicks, wenn sich die Activity der obersten Ebene geändert hatte, und verglich Screenshots, wenn `OpOpenApp` in den vorherigen drei Schritten aufgetreten war. Einzeltaps, langes Drücken und Doppeltaps boten daher nur wenige verlässliche Möglichkeiten für angreiferkontrolliertes Timing. `OpTypeText`, `OpSwipeUI` und `OpScrollWheelAction` hatten keine gleichwertigen Schutzmechanismen, doch der Bericht stufte ihre praktischen Auswirkungen als begrenzter ein.<sup>[[9]](#references)</sup>

## Ausführung: Tatsächliche Auswirkungen nachweisen

Es gibt zwei unterschiedliche Wege vom Einfluss zu den Auswirkungen:<sup>[[2]](#references)</sup>

1. **Missbrauch vorhandener Fähigkeiten:** Das autorisierte Tool führt das Ziel bereits aus. Beispiele sind das Lesen eines Datensatzes eines Mandanten und dessen Schreiben in einen für den Angreifer sichtbaren Bericht, das Versenden von E-Mails, das Ändern von Datensätzen, das Löschen einer Datei oder das Veranlassen einer Zahlung. Ein zusätzlicher Softwarefehler ist nicht erforderlich.
2. **Ausnutzung eines nachgelagerten Sinks:** Vom Angreifer gesteuerte Modellausgabe wird zur Syntax für eine andere Komponente. Prüfe Datenbankabfragen auf [SQL injection](../pentesting-web/sql-injection/README.md) oder [NoSQL injection](../pentesting-web/nosql-injection.md), Shell-Wrapper auf [command injection](../pentesting-web/command-injection.md), ausgewählte URLs auf [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), Dateioperationen auf Traversal, Template-/Code-Evaluatoren auf RCE und Objektparser auf [unsafe deserialization](../pentesting-web/deserialization/README.md).

Weise für jeden möglichen Befund diese Kette nach:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Eine schreibgeschützte Integration ist weiterhin angreifbar, wenn eine nachgelagerte Komponente das Gelesene veröffentlichen kann. Teste gewöhnliche Antworten sowie weniger offensichtliche Wege nach außen, etwa angreiferkontrollierte Links, automatisches Abrufen von Bildern, Webhooks, Logs, Berichte, Zähler, Benachrichtigungen und Nachrichten an andere Agents.<sup>[[2]](#references)</sup>

## Aktionen zur Zielerreichung

Nachdem du eine Aktion bestätigt hast, bewerte das gesamte Ausmaß der Auswirkungen, anstatt beim ersten sichtbaren Effekt aufzuhören:<sup>[[2]](#references)</sup>

- **Exfiltration:** Geheimnisse, Benutzerdatensätze, interne Dateien, Konversationsdaten oder Prompt-/Kontextinhalte verlassen das System über einen beobachtbaren Kanal.
- **Nicht autorisierte Aktion:** Der Agent nutzt legitime Schreibrechte, um das Ziel des Angreifers zu erreichen.
- **Denial of Service:** Destruktive Tools oder wiederholte kostspielige Vorgänge beeinträchtigen Integrität oder Verfügbarkeit.
- **Persistenz:** Vergifteter Speicher, indexierte Inhalte, vertrauenswürdiger Zustand oder Laufzeitänderungen bleiben nach Ende der ursprünglichen Sitzung oder Entfernung der Quelle bestehen.
- **Ausbreitung:** Ein vertrauenswürdiger Peer übernimmt die Nachricht oder den gemeinsamen Zustand des kompromittierten Agents und wiederholt die Aktion mit seinen eigenen Tools und Zugangsdaten.

Der Schweregrad sollte sich nach den erreichbaren Daten, den effektiven Berechtigungen, der Ausnutzbarkeit der Senke, dem Egress, der Persistenz und der Ausbreitung richten – nicht danach, wie überraschend der Text des Modells wirkt.<sup>[[2]](#references)</sup>

## Während des Assessments zu überprüfende Schutzmaßnahmen

Prompt-Filter und ein besserer System-Prompt können den Aufwand für Angreifer erhöhen, sollten aber nicht als Autorisierungsgrenzen behandelt werden. Überprüfe die folgenden Schutzmaßnahmen, indem du dieselbe Angriffskette erneut über direkte Eingaben, indirekte Inhalte, Speicher, Tools und Peer-Agents ausführst:<sup>[[2]](#references)</sup>

- Eine deterministische Richtlinienebene prüft bei **jedem Tool-Aufruf** den authentifizierten Benutzer, den Mandanten, das Objekt, die Aktion und das Ziel; das Modell kann die Identität des Aufrufenden weder angeben noch überschreiben.
- Lese- und Schreibberechtigungen verwenden getrennte, möglichst restriktive, kurzlebige Zugangsdaten; Tools mit weitreichenden Auswirkungen werden nur bei Bedarf freigegeben und niemals automatisch aufgrund eingelesener Inhalte ausgeführt.
- Ausgehender Netzwerkverkehr und interne Ziele werden unabhängig von den vom Modell ausgewählten URLs auf eine Allowlist gesetzt; der Laufzeitzugriff auf Metadaten-Endpunkte, eingebundene Geheimnisse und benachbarte Dienste wird blockiert, sofern er nicht erforderlich ist.
- Die Genehmigungsoberfläche wird aus der kanonischen strukturierten Anfrage erstellt und zeigt die genauen Argumente, die Identität, das Ziel, die betroffenen Objekte und die Nebenwirkungen an – nicht eine frei formulierte Modellzusammenfassung.
- Der Erfolg wird anhand des Zielsystems oder maßgeblichen Systems überprüft. Die Beschreibung des Agents, eine Tool-Aufruf-Anfrage oder eine HTTP-Weiterleitung belegt die behauptete Zustandsänderung nicht.
- Speicher- und Retrieval-Einträge behalten ihre Herkunft und Vertrauenskennzeichnungen, können ungültig gemacht werden und werden bei Verwendung für eine spätere Aktion erneut autorisiert.
- Nachrichten zwischen Agents werden als nicht vertrauenswürdige Anfragen authentifiziert und autorisiert; der Ruf eines Peers oder seine Agent Card überträgt dem Empfänger nicht implizit dessen Tool-Berechtigungen.

Informationen zu A2A-Agent-Cards, Aufgabenabläufen und ihrer Angriffsfläche findest du unter [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 für agentische Anwendungen 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Der Leitfaden des Hackers zum Angriff auf AI-Agenten](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Wie schwer ist es wirklich, einen AI-Agenten aus seiner Sandbox auszubrechen?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents im SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Quellcode der TypeSafe-Auto-Mode-Middleware von LangChain](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-Modellunregelmäßigkeiten: adversariale Inhalte](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev als Richter: Wie gefälschte Richtlinien Jev beeinflussen](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulation ohne Berechtigungen: Können wir GUI-Agents vertrauen, die auf großen multimodalen Modellen basieren?](https://arxiv.org/html/2601.12349v1)
- [9] [Wenn ein AI-Assistent Teil der Angriffskette eines Hackers wird | Sicherheitsanalyse des Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
