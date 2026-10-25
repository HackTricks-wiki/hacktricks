# Sicurezza del protocollo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Cos'è A2A

A2A (Agent2Agent) è un protocollo aperto che consente a un agente AI di individuare un altro agente e affidargli del lavoro tramite HTTP. MCP connette un agente a **strumenti e dati**; A2A connette un agente ad **altri agenti**, che di solito sono servizi remoti gestiti da un altro team o da un'altra azienda. Un server A2A è un'API web con un agente LLM dietro, quindi gli oggetti specifici del protocollo (agent card, task, webhook di push notification, extended card) richiedono verifiche specifiche di autenticazione, IDOR e SSRF durante un normale test API.<sup>[[1]](#references)[[2]](#references)</sup>

Gli elementi principali sono:

- **Agent Card:** un documento JSON che descrive l'agente: nome, descrizione, skill, URL dei servizi, trasporti supportati, funzionalità (streaming, push notification, extended card) e `securitySchemes` che il client deve usare. Viene pubblicato su `https://<host>/.well-known/agent-card.json`. Le distribuzioni meno recenti che seguono la spec 0.2.x usano `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** l'unità di lavoro. Un messaggio crea un task (con un `id` generato dal server e un `contextId`) e in seguito il client può leggerlo, annullarlo o sottoscriversi ad esso.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 su HTTP (con SSE per lo streaming), gRPC e un binding REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** le credenziali vanno negli header HTTP (per esempio `Authorization: Bearer ...`), mai all'interno del payload JSON-RPC. L'agent card indica lo schema richiesto.<sup>[[1]](#references)</sup>

I nomi dei metodi sono cambiati tra le versioni, quindi prova entrambi gli insiemi:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operazione | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Invio di un messaggio | `message/send` | `SendMessage` | `POST /message:send` |
| Invio in streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Recupero di un task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Elenco dei task | - | `ListTasks` | `GET /tasks` |
| Annullamento di un task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configurazione delle push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La spec 1.0 usa l'header `A2A-Version` (o un parametro della richiesta) per selezionare la versione; le richieste che ne sono prive vengono considerate 0.3.<sup>[[1]](#references)</sup>

## Individuazione

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Dalla card, annota:

- Ogni `url` del servizio (spesso un hostname interno, un URL di staging o una porta diversa da quella del sito pubblico).
- `skills`: mostrano cosa può fare l'agent e quali strumenti o dati ha a disposizione.
- `securitySchemes` / `security`: se sono vuoti o assenti, probabilmente l'agent è progettato per essere chiamato senza credenziali.
- `capabilities.pushNotifications` e `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

La spec dice che la card pubblica non dovrebbe contenere credenziali o dettagli interni dell'implementazione, quindi URL interni, chiavi o elenchi dettagliati di strumenti in una card pubblica sono già un finding.<sup>[[1]](#references)</sup>

## Test degli endpoint A2A

### Invio di task senza autenticazione

Invia un messaggio minimo senza credenziali a ogni `url` elencato nella card:

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

Un risultato `Task` o `Message` con `PONG`, quando la card dichiara uno schema di sicurezza, significa che l'autenticazione non è applicata sull'endpoint RPC (potrebbe essere applicata solo sulla UI o sulla card). Se la card non dichiara alcuno schema, verifica a quali risorse possono accedere le skill dell'agente: un agente non autenticato in grado di leggere dati interni o chiamare tool equivale a un'API non autenticata per quei tool.

### IDOR sui task (`tasks/get`, `GetTask`, cancel, subscribe)

La specifica richiede che il server verifichi, a ogni richiesta, che il chiamante possa accedere al task e che `ListTasks` sia limitato al chiamante anche quando non viene fornito alcun filtro.<sup>[[1]](#references)</sup> Esegui il test con due identità (A e B):

1. Come A, crea un task e salva il suo `id` e `contextId`.
2. Come B (o senza credenziali), chiama `tasks/get` / `GetTask` con l'`id` di A, quindi `ListTasks` senza parametri.
3. Prova anche a eseguire cancel e subscribe sul task di A e invia un nuovo messaggio come B che includa il `taskId` o il `contextId` di A (in questo modo il testo di B verrebbe aggiunto alla conversazione di A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerabile: B riceve la cronologia, gli artifact o lo stato di A, oppure può modificare il task di A. Sicuro: un `TaskNotFoundError`, senza differenze tra «esiste ma non è tuo» e «non esiste».<sup>[[1]](#references)</sup> Gli ID dei task sono spesso UUID, quindi cercali nei punti in cui possono essere esposti (link condivisi, log, payload delle notifiche push, messaggi di errore).

### SSRF tramite webhook delle notifiche push

Quando `capabilities.pushNotifications` è impostato su true, il client fornisce all'agent un URL webhook e in seguito l'agent invia richieste `POST` a quell'URL con gli aggiornamenti del task. La specifica dice che gli agent devono rifiutare gli indirizzi di range privati, localhost e link-local, e usare allowlist.<sup>[[1]](#references)</sup> Crea un task, registra una configurazione delle notifiche push il cui `url` punti al tuo host OAST per confermare le richieste in uscita e poi (solo se lo scope lo consente) prova target interni come `http://127.0.0.1:<port>/` o `http://169.254.169.254/`. Confronta errori e tempi di risposta per individuare i servizi interni. L'agent aggiunge anche l'header di autenticazione configurato a queste richieste: verifica quindi che non venga inviato a un host scelto dall'attaccante quando puoi modificare l'URL della configurazione di un altro utente. Vedi [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Accesso alla scheda estesa dell'agent

`GetExtendedAgentCard` deve richiedere l'autenticazione e può restituire più skill e configurazioni rispetto alla scheda pubblica.<sup>[[1]](#references)</sup> Invocalo senza credenziali e con un'identità con privilegi limitati, quindi confronta il risultato con la scheda pubblica.

### Configurazione delle notifiche push e leak di credenziali durante un task

Le configurazioni delle notifiche push memorizzano un URL webhook e le credenziali che l'agent invia a tale URL. La specifica richiede che ogni operazione sulle configurazioni delle notifiche push (creazione, lettura, elenco, eliminazione) verifichi che il chiamante possa accedere al task.<sup>[[1]](#references)</sup> Ripeti su questi endpoint il test con due identità descritto nella [sezione task IDOR](#task-idor-tasksget-gettask-cancel-subscribe). Una configurazione leggibile appartenente a un altro utente espone un token webhook; una configurazione modificabile reindirizza gli aggiornamenti dei task di quell'utente al tuo host.

Quando un agent ha bisogno di un'autorizzazione aggiuntiva durante un task, porta il task allo stato `TASK_STATE_AUTH_REQUIRED`. Il client può gestire l'autorizzazione out of band; la specifica dice che gli agent devono ricevere le credenziali out of band, a meno che non sia stato concordato un meccanismo in-band. Lo scambio in-band può far passare una credenziale attraverso una catena di agent A2A ed esporla a ogni agent della catena.<sup>[[1]](#references)</sup> In un test dell'orchestrator, verifica se una credenziale fornita dall'utente per un agent downstream compare in messaggi, artifact o nella cronologia del task, dove altri agent (o altri utenti tramite task IDOR) possono leggerla.

Anche i campi delle schede degli agent e i risultati dei task sono input non attendibili per l'agent chiamante. Testali con le tecniche di prompt injection indiretta descritte in [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) e con i controlli di fiducia tra agent descritti in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Specifica del protocollo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog di Google Developers — Annuncio del protocollo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specifica A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specifica A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
