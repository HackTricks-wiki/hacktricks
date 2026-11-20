# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## Was ist A2A

A2A (Agent2Agent) ist ein offenes Protokoll, mit dem ein AI-Agent einen anderen Agenten finden und ihm über HTTP Aufgaben senden kann. MCP verbindet einen Agenten mit **Tools und Daten**; A2A verbindet einen Agenten mit **anderen Agenten**, bei denen es sich meist um Remote-Services handelt, die einem anderen Team oder Unternehmen gehören. Ein A2A-Server ist eine Web-API mit einem LLM-Agenten dahinter. Daher bringen die eigenen Objekte des Protokolls (Agent Cards, Tasks, Webhooks für Push-Benachrichtigungen, erweiterte Cards) spezifische Prüfungen auf Authentifizierung, IDOR und SSRF in einen gewöhnlichen API-Test ein.<sup>[[1]](#references)[[2]](#references)</sup>

Die wichtigsten Bestandteile sind:

- **Agent Card:** ein JSON-Dokument, das den Agenten beschreibt: Name, Beschreibung, Skills, Service-URL(s), unterstützte Transports, Fähigkeiten (Streaming, Push-Benachrichtigungen, erweiterte Card) und die `securitySchemes`, die der Client verwenden muss. Sie wird unter `https://<host>/.well-known/agent-card.json` veröffentlicht. Ältere Deployments, die der Spezifikation 0.2.x folgen, verwenden `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** die Arbeitseinheit. Eine Message erstellt einen Task (mit einer serverseitig generierten `id` und einer `contextId`), den der Client später lesen, abbrechen oder abonnieren kann.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 über HTTP (mit SSE für Streaming), gRPC und eine HTTP+JSON-REST-Bindung.<sup>[[1]](#references)</sup>
- **Authentifizierung:** Zugangsdaten gehören in HTTP-Header (zum Beispiel `Authorization: Bearer ...`), niemals in den JSON-RPC-Payload. Die Agent Card gibt an, welches Schema erforderlich ist.<sup>[[1]](#references)</sup>

Die Methodennamen haben sich zwischen den Versionen geändert, daher sollten beide Sätze ausprobiert werden:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operation | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Message senden | `message/send` | `SendMessage` | `POST /message:send` |
| Streaming-Message senden | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task abrufen | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Tasks auflisten | - | `ListTasks` | `GET /tasks` |
| Task abbrechen | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push-Benachrichtigungskonfiguration | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Erweiterte Card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Die Spezifikation 1.0 verwendet den Header `A2A-Version` (oder einen Request-Parameter), um die Version auszuwählen. Requests ohne diesen Header werden als Version 0.3 behandelt.<sup>[[1]](#references)</sup>

## Auffinden

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Schreiben Sie aus der Karte Folgendes heraus:

- Jede `url` des Dienstes: In Version 1.0 befinden sich diese unter `supportedInterfaces`, während ältere Karten möglicherweise eine `url` auf oberster Ebene enthalten. Notieren Sie jeden Endpunkt und Transport, einschließlich interner Hostnamen, Staging-URLs und alternativer Ports.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: Sie zeigen, was der Agent kann und welche Tools oder Daten dahinterliegen.
- `securitySchemes` / `security`: Wenn sie leer sind oder fehlen, ist der Agent wahrscheinlich dafür vorgesehen, ohne Anmeldedaten aufgerufen zu werden.
- `capabilities.pushNotifications` und `capabilities.extendedAgentCard` (in Version 0.3 `supportsAuthenticatedExtendedCard`).

Laut Spezifikation sollte die öffentliche Karte keine Anmeldedaten oder internen Implementierungsdetails enthalten. Interne URLs, Schlüssel oder detaillierte Tool-Listen in einer öffentlichen Karte sind daher bereits ein Befund.<sup>[[1]](#references)</sup>

### Namenskollision bei Agent Cards auf einem Multi-Agent-Host

Das `name` einer Karte ist eine menschenlesbare Bezeichnung und keine stabile Routing-Identität.<sup>[[1]](#references)[[5]](#references)</sup> Wenn ein Host zwei unterschiedliche Remote-Peers unter demselben lokalen Namen registriert, können sein Agentenbaum, der generierte Tool-Name, die Client-Zuordnung oder die Broker-Route eine für den vertrauenswürdigen Peer bestimmte Aufgabe an den anderen Peer senden.<sup>[[5]](#references)</sup> Dafür muss der vom Angreifer kontrollierte Peer in denselben **Routing-Namespace** aufgenommen werden; allein das Veröffentlichen einer doppelten Karte im Internet reicht nicht aus.<sup>[[5]](#references)</sup>

Testen Sie den **Zulassungs-bis-Dispatch-Pfad** des Hosts mit zwei kontrollierten Peers, unterschiedlichen URLs und einem harmlosen Marker:<sup>[[5]](#references)</sup>

1. Erfassen Sie die Karte, den Ursprung und den lokalen Selektor des vertrauenswürdigen Peers. Registrieren Sie einen zweiten Peer, dessen Karte denselben `name` hat, dessen URL aber auf einen von Ihnen kontrollierten Endpunkt verweist.
2. Lösen Sie den Vorgang aus, der den vertrauenswürdigen Peer anhand seines Namens auswählt. Testen Sie beide Registrierungsreihenfolgen und, falls Namen zu Tool-Bezeichnern werden, die normale Namensnormalisierung des Hosts. Erfassen Sie, welcher Endpunkt den Marker empfängt und welcher Agent die Antwort zurückgibt.
3. Ändern Sie nur den Namen der zweiten Karte und wiederholen Sie den Test. Erreicht eine Anfrage den zweiten Endpunkt nur im Kollisionsfall, ist damit die Weiterleitung an den falschen Peer nachgewiesen. Prüfen Sie separat, ob tatsächlich sensibler Kontext oder Anmeldedaten mitgesendet wurden; die Namenskollision allein belegt **keine** Übertragung von Anmeldedaten oder Tool-Berechtigungen.

Wenn der Aufrufer einen festen, an den Ursprung gebundenen Endpunkt verwendet, statt einen Kartennamen aufzulösen, ist dieser Test nicht anwendbar.<sup>[[5]](#references)</sup> Für nachfolgende Antworten eines bösartigen Peers und die Auswirkungen von Prompt-Injection folgen Sie der [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Testen von A2A-Endpunkten

### Nicht authentifizierte Aufgabenübermittlung

Senden Sie eine minimale Nachricht ohne Anmeldedaten an jede in der Karte aufgeführte `url`:

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Ein `Task`- oder `Message`-Ergebnis mit `PONG` bedeutet, wenn die Card ein Security-Scheme deklariert, dass die Authentifizierung am RPC-Endpunkt nicht erzwungen wird (sie wird möglicherweise nur in der UI oder auf der Card erzwungen). Wenn die Card kein Scheme deklariert, prüfe, auf welche Ressourcen die Skills des Agents zugreifen können: Ein nicht authentifizierter Agent, der interne Daten lesen oder Tools aufrufen kann, entspricht einer nicht authentifizierten API für diese Tools.

### Task-IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Die Spezifikation verlangt, dass der Server bei jeder Anfrage prüft, ob der Aufrufer auf den Task zugreifen darf, und `ListTasks` auf den Aufrufer beschränkt, auch wenn kein Filter angegeben ist.<sup>[[1]](#references)</sup> Teste dies mit zwei Identitäten (A und B):

1. Erstelle als A einen Task und speichere dessen `id` und `contextId`.
2. Rufe als B (oder ohne Zugangsdaten) `tasks/get` / `GetTask` mit der `id` von A auf und anschließend `ListTasks` ohne Parameter.
3. Versuche außerdem, den Task von A abzubrechen und zu abonnieren, und sende als B eine neue Nachricht mit der `taskId` oder `contextId` von A (dadurch würde Bs Text zur Unterhaltung von A hinzugefügt).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Verwundbar: B erhält den Verlauf, Artefakte oder Status von A oder kann die Aufgabe von A ändern. Sicher: ein `TaskNotFoundError`, ohne Unterschied zwischen „existiert, gehört aber nicht dir“ und „existiert nicht“.<sup>[[1]](#references)</sup> Task-IDs sind häufig UUIDs. Suche daher an Stellen, an denen sie geleakt werden (gemeinsam genutzte Links, Logs, Push-Notification-Payloads, Fehlermeldungen).

### Push-Notification-Webhook-SSRF

Wenn `capabilities.pushNotifications` auf `true` gesetzt ist, gibt der Client dem Agenten eine Webhook-URL, an die der Agent später `POST`-Anfragen mit Task-Updates sendet. Die Spezifikation besagt, dass Agents private Bereiche, localhost und Link-Local-Adressen ablehnen und Allowlists verwenden sollten.<sup>[[1]](#references)</sup> Erstelle eine Task und registriere eine Push-Notification-Konfiguration, deren `url` auf deinen OAST-Host verweist, um ausgehende Anfragen zu bestätigen. Anschließend kannst du – nur wenn es der Scope erlaubt – interne Ziele wie `http://127.0.0.1:<port>/` oder `http://169.254.169.254/` testen. Vergleiche Fehler und Timing, um interne Services zu erfassen. Der Agent fügt diesen Anfragen außerdem den konfigurierten Authentifizierungs-Header hinzu. Prüfe daher, ob dieser an einen vom Angreifer gewählten Host gesendet wird, wenn du die URL der Konfiguration eines anderen Benutzers ändern kannst. Siehe [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### File-URL-Parts als zweiter SSRF-Einstiegspunkt

A2A 1.0 ermöglicht es einer Nachricht oder einem Artefakt, eine Dateireferenz als `Part` mit `url` zu enthalten (0.3 verwendet `kind: "file"` und `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Das Protokoll überträgt die Referenz; sie abzurufen ist Anwendungsverhalten und keine Anforderung des A2A SDK.<sup>[[6]](#references)</sup> Dies ist unabhängig von der oben genannten Push-Notification-Callback-URL. Teste beide Richtungen: eine vom Client bereitgestellte Datei, die an einen A2A-Server gesendet wird, und eine von einem Peer mit geringerem Vertrauensniveau zurückgegebene Datei-URL, die an einen Orchestrator geht.<sup>[[1]](#references)[[6]](#references)</sup>

Ersetze bei einem autorisierten 1.0-JSON-RPC-Endpunkt den normalen Text-Part durch eine URL mit einem eindeutigen OAST-Pfad und prüfe, **welche Komponente** die Anfrage stellt:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Nur wenn der Empfänger den Verweis dereferenziert, solltest du interne Ziele im Scope, Weiterleitungen und Änderungen der DNS-Auflösung mithilfe des [SSRF-Workflows](../pentesting-web/ssrf-server-side-request-forgery/) testen. Ein gültiges `Part` oder eine erfolgreiche Aufgabenantwort allein belegt kein SSRF; bestätige den Abruf am Ziel und ob der abgerufene Inhalt den Agenten erreicht.<sup>[[6]](#references)</sup>

### Zugriff auf die erweiterte Agentenkarte

`GetExtendedAgentCard` muss eine Authentifizierung erfordern und kann mehr Skills und Konfigurationen als die öffentliche Karte zurückgeben.<sup>[[1]](#references)</sup> Rufe die Methode ohne Zugangsdaten und mit einer Identität mit geringen Berechtigungen auf und vergleiche das Ergebnis mit der öffentlichen Karte.

### Push-Benachrichtigungskonfiguration und Zugangsdaten-Leaks in Aufgaben

Push-Benachrichtigungskonfigurationen speichern eine Webhook-URL und die Zugangsdaten, die der Agent dorthin sendet. Die Spezifikation verlangt, dass jeder Vorgang mit einer Push-Benachrichtigungskonfiguration (Erstellen, Abrufen, Auflisten, Löschen) prüft, ob der Aufrufer auf die Aufgabe zugreifen darf.<sup>[[1]](#references)</sup> Wiederhole den Test mit zwei Identitäten aus dem [Abschnitt zu Task-IDOR](#task-idor-tasksget-gettask-cancel-subscribe) für diese Routen. Eine lesbare Konfiguration eines anderen Benutzers leakt ein Webhook-Token; eine bearbeitbare Konfiguration leitet die Aufgabenaktualisierungen dieses Benutzers an deinen Host um.

Wenn ein Agent während einer Aufgabe eine zusätzliche Autorisierung benötigt, versetzt er die Aufgabe in den Zustand `TASK_STATE_AUTH_REQUIRED`. Der Client kann die Autorisierung über einen Out-of-Band-Kanal einrichten; laut Spezifikation müssen Agenten Zugangsdaten über einen Out-of-Band-Kanal erhalten, sofern kein In-Band-Mechanismus ausgehandelt wurde. Ein In-Band-Austausch kann Zugangsdaten über eine Kette von A2A-Agenten weitergeben und sie allen Agenten dieser Kette offenlegen.<sup>[[1]](#references)</sup> Prüfe bei einem Orchestrator-Test, ob Zugangsdaten, die der Benutzer für einen nachgelagerten Agenten bereitstellt, in Nachrichten, Artefakten oder im Aufgabenverlauf erscheinen, auf die andere Agenten (oder andere Benutzer über Task-IDOR) zugreifen können.

Agentenkartenfelder und Aufgabenergebnisse sind für den aufrufenden Agenten ebenfalls nicht vertrauenswürdige Eingaben. Teste sie mit den Techniken für indirekte Prompt-Injection unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) und den Prüfungen des Vertrauens zwischen Agenten in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [A2A-Protokollspezifikation](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Ankündigung des Agent2Agent-Protokolls (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A-Spezifikation v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A-Spezifikation v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Angriffe durch Namenskollisionen von Agenten in Multi-Agenten-Systemen](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK-Sicherheitsleitfaden](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Migrationsleitfaden für A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
