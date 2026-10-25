# Sicherheit des A2A-Protokolls

{{#include ../banners/hacktricks-training.md}}

## Was ist A2A?

A2A (Agent2Agent) ist ein offenes Protokoll, mit dem ein KI-Agent einen anderen Agenten finden und ihm über HTTP Aufgaben senden kann. MCP verbindet einen Agenten mit **Tools und Daten**; A2A verbindet einen Agenten mit **anderen Agenten**, bei denen es sich normalerweise um Remote-Dienste handelt, die einem anderen Team oder Unternehmen gehören. Ein A2A-Server ist eine Web-API mit einem LLM-Agenten im Hintergrund. Daher erfordern die protokolleigenen Objekte (Agent Cards, Tasks, Push-Notification-Webhooks und Extended Cards) bei einem normalen API-Test spezifische Prüfungen auf Authentifizierung, IDOR und SSRF.<sup>[[1]](#references)[[2]](#references)</sup>

Die wichtigsten Komponenten sind:

- **Agent Card:** ein JSON-Dokument, das den Agenten beschreibt: Name, Beschreibung, Skills, Service-URL(s), unterstützte Transportprotokolle, Funktionen (Streaming, Push Notifications, Extended Card) und die `securitySchemes`, die der Client verwenden muss. Sie wird unter `https://<host>/.well-known/agent-card.json` veröffentlicht. Ältere Deployments, die der Spezifikation 0.2.x folgen, verwenden `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** die Arbeitseinheit. Eine Nachricht erstellt einen Task (mit einer serverseitig generierten `id` und einer `contextId`), den der Client später abruft, abbricht oder abonniert.<sup>[[1]](#references)</sup>
- **Transporte:** JSON-RPC 2.0 über HTTP (mit SSE für Streaming), gRPC und eine HTTP+JSON-REST-Bindung.<sup>[[1]](#references)</sup>
- **Authentifizierung:** Zugangsdaten werden in HTTP-Headern übermittelt (zum Beispiel `Authorization: Bearer ...`), niemals im JSON-RPC-Payload. Die Agent Card gibt an, welches Verfahren erforderlich ist.<sup>[[1]](#references)</sup>

Die Methodennamen haben sich zwischen den Versionen geändert. Probiere daher beide Varianten aus:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Vorgang | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Nachricht senden | `message/send` | `SendMessage` | `POST /message:send` |
| Nachricht im Streaming senden | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Task abrufen | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Tasks auflisten | - | `ListTasks` | `GET /tasks` |
| Task abbrechen | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push-Notification-Konfiguration | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended Card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Die Spezifikation 1.0 verwendet den Header `A2A-Version` (oder einen Request-Parameter) zur Auswahl der Version. Requests ohne diesen Header werden als Version 0.3 behandelt.<sup>[[1]](#references)</sup>

## Erkennung

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Schreibe aus der Card Folgendes heraus:

- Jede Service-`url` (oft ein interner Hostname, eine Staging-URL oder ein anderer Port als der der öffentlichen Website).
- `skills`: Sie zeigen, was der Agent tun kann und welche Tools oder Daten dahinterliegen.
- `securitySchemes` / `security`: Wenn sie leer sind oder fehlen, ist der Agent wahrscheinlich dafür vorgesehen, ohne Credentials aufgerufen zu werden.
- `capabilities.pushNotifications` und `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

Laut Spezifikation sollte die öffentliche Card keine Credentials oder internen Implementierungsdetails enthalten. Interne URLs, Keys oder detaillierte Tool-Listen in einer öffentlichen Card sind daher bereits ein Finding.<sup>[[1]](#references)</sup>

## A2A-Endpunkte testen

### Unauthentifizierte Task-Übermittlung

Sende ohne Credentials eine minimale Nachricht an jede in der Card aufgeführte `url`:

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

Ein `Task`- oder `Message`-Ergebnis mit `PONG` bedeutet bei einer Card, die ein Security Scheme deklariert, dass die Authentifizierung am RPC-Endpunkt nicht erzwungen wird (sie wird möglicherweise nur in der UI oder auf der Card erzwungen). Wenn die Card kein Scheme deklariert, prüfe, auf welche Ressourcen die Skills des Agents zugreifen können: Ein nicht authentifizierter Agent, der interne Daten lesen oder Tools aufrufen kann, ist für diese Tools gleichbedeutend mit einer nicht authentifizierten API.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Die Spezifikation verlangt, dass der Server bei jeder Anfrage prüft, ob der Aufrufer auf die Task zugreifen darf, und dass `ListTasks` auf den Aufrufer beschränkt wird, selbst wenn kein Filter angegeben ist.<sup>[[1]](#references)</sup> Teste dies mit zwei Identitäten (A und B):

1. Erstelle als A eine Task und speichere ihre `id` und `contextId`.
2. Rufe als B (oder ohne Credentials) `tasks/get` / `GetTask` mit der `id` von A auf und anschließend `ListTasks` ohne Parameter.
3. Versuche außerdem, A's Task abzubrechen und zu abonnieren, und sende als B eine neue Nachricht, die A's `taskId` oder `contextId` enthält (dadurch würde B's Text zu A's Unterhaltung hinzugefügt).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Verwundbar: B erhält den Verlauf, Artefakte oder Status von A oder kann die Aufgabe von A ändern. Sicher: ein `TaskNotFoundError`, ohne Unterschied zwischen „existiert, gehört aber nicht dir“ und „existiert nicht“.<sup>[[1]](#references)</sup> Task-IDs sind oft UUIDs. Suche daher an Stellen danach, an denen sie leaken können (geteilte Links, Logs, Push-Benachrichtigungs-Payloads, Fehlermeldungen).

### SSRF über Push-Benachrichtigungs-Webhook

Wenn `capabilities.pushNotifications` den Wert `true` hat, übergibt der Client dem Agent eine Webhook-URL, an die der Agent später `POST`-Anfragen mit Aufgaben-Updates sendet. Die Spezifikation besagt, dass Agents private Bereiche, localhost und Link-Local-Adressen ablehnen und Allowlists verwenden sollten.<sup>[[1]](#references)</sup> Erstelle eine Aufgabe und registriere eine Push-Benachrichtigungskonfiguration, deren `url` auf deinen OAST-Host verweist, um ausgehende Anfragen zu bestätigen. Teste anschließend (nur, wenn es der Scope erlaubt) interne Ziele wie `http://127.0.0.1:<port>/` oder `http://169.254.169.254/`. Vergleiche Fehler und Timing, um interne Dienste zu ermitteln. Der Agent fügt diesen Anfragen außerdem den konfigurierten Authentifizierungs-Header hinzu. Prüfe daher, ob dieser an einen vom Angreifer gewählten Host gesendet wird, wenn du die URL der Konfiguration eines anderen Benutzers ändern kannst. Siehe [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Zugriff auf die erweiterte Agent-Karte

`GetExtendedAgentCard` muss Authentifizierung erfordern und kann mehr Skills und Konfigurationen zurückgeben als die öffentliche Karte.<sup>[[1]](#references)</sup> Rufe sie ohne Anmeldedaten und mit einer Identität mit geringen Berechtigungen auf und vergleiche das Ergebnis mit der öffentlichen Karte.

### Push-Benachrichtigungskonfiguration und Credential-Leaks innerhalb von Aufgaben

Push-Benachrichtigungskonfigurationen speichern eine Webhook-URL und die Credentials, die der Agent an sie sendet. Die Spezifikation verlangt, dass bei jeder Aktion mit einer Push-Benachrichtigungskonfiguration (Erstellen, Abrufen, Auflisten, Löschen) geprüft wird, ob der Aufrufer auf die Aufgabe zugreifen darf.<sup>[[1]](#references)</sup> Wiederhole den Zwei-Identitäten-Test aus dem Abschnitt [Task-IDOR](#task-idor-tasksget-gettask-cancel-subscribe) für diese Routen. Eine lesbare Konfiguration eines anderen Benutzers leakt ein Webhook-Token, eine beschreibbare Konfiguration leitet die Aufgaben-Updates dieses Benutzers an deinen Host um.

Wenn ein Agent während einer Aufgabe eine zusätzliche Autorisierung benötigt, wechselt er in den Status `TASK_STATE_AUTH_REQUIRED`. Der Client kann die Autorisierung out of band bereitstellen; laut Spezifikation müssen Agents Credentials out of band erhalten, sofern kein In-Band-Mechanismus ausgehandelt wurde. Ein In-Band-Austausch kann ein Credential durch eine Kette von A2A-Agents weitergeben und es jedem Agent in dieser Kette offenlegen.<sup>[[1]](#references)</sup> Prüfe bei einem Orchestrator-Test, ob ein Credential, das der Benutzer für einen nachgelagerten Agent bereitstellt, in Nachrichten, Artefakten oder im Aufgabenverlauf auftaucht, auf die andere Agents (oder andere Benutzer über Task-IDOR) zugreifen können.

Agent-Kartenfelder und Aufgabenergebnisse sind für den aufrufenden Agent ebenfalls nicht vertrauenswürdige Eingaben. Teste sie mit den indirekten Prompt-Injection-Techniken unter [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) und den Prüfungen des Vertrauens zwischen Agents unter [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [A2A-Protokollspezifikation](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Ankündigung des Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A-Spezifikation v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A-Spezifikation v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
