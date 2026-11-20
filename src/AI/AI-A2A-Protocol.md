# Sicurezza del protocollo A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Cos'è A2A

A2A (Agent2Agent) è un protocollo aperto che permette a un agente AI di individuare un altro agente e assegnargli del lavoro tramite HTTP. MCP connette un agente a **strumenti e dati**; A2A connette un agente ad **altri agenti**, che di solito sono servizi remoti gestiti da un altro team o da un'altra azienda. Un server A2A è un'API web con un agente LLM alle spalle, quindi gli oggetti propri del protocollo (agent card, task, webhook per le push notification, extended card) richiedono controlli specifici di autenticazione, IDOR e SSRF durante un normale test delle API.<sup>[[1]](#references)[[2]](#references)</sup>

Gli elementi principali sono:

- **Agent Card:** un documento JSON che descrive l'agente: nome, descrizione, skill, URL del servizio, trasporti supportati, funzionalità (streaming, push notification, extended card) e `securitySchemes` che il client deve usare. Viene pubblicato in `https://<host>/.well-known/agent-card.json`. Le distribuzioni meno recenti che seguono la specifica 0.2.x usano `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** l'unità di lavoro. Un messaggio crea un task (con un `id` generato dal server e un `contextId`), che il client può poi leggere, annullare o a cui può iscriversi.<sup>[[1]](#references)</sup>
- **Trasporti:** JSON-RPC 2.0 su HTTP (con SSE per lo streaming), gRPC e un binding REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Autenticazione:** le credenziali vanno negli header HTTP (ad esempio `Authorization: Bearer ...`), mai nel payload JSON-RPC. L'agent card indica quale schema è richiesto.<sup>[[1]](#references)</sup>

I nomi dei metodi sono cambiati tra le versioni, quindi prova entrambi gli insiemi:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operazione | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Invia messaggio | `message/send` | `SendMessage` | `POST /message:send` |
| Invio in streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Recupera task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Elenca task | - | `ListTasks` | `GET /tasks` |
| Annulla task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configurazione delle push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La specifica 1.0 usa l'header `A2A-Version` (o un parametro della richiesta) per selezionare la versione; le richieste che ne sono prive vengono considerate 0.3.<sup>[[1]](#references)</sup>

## Individuazione

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Dalla card, annota:

- Ogni `url` del servizio: in 1.0 si trova in `supportedInterfaces`, mentre le card più vecchie possono esporre un `url` di primo livello. Registra ogni endpoint e trasporto, inclusi hostname interni, URL di staging e porte alternative.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: mostrano cosa può fare l'agent e quali strumenti o dati sono disponibili.
- `securitySchemes` / `security`: se sono vuoti o mancanti, probabilmente l'agent è destinato a essere chiamato senza credenziali.
- `capabilities.pushNotifications` e `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

La specifica afferma che la card pubblica non dovrebbe contenere credenziali né dettagli interni di implementazione; quindi URL interni, chiavi o elenchi dettagliati di strumenti in una card pubblica costituiscono già un rilievo.<sup>[[1]](#references)</sup>

### Collisione del nome della Agent Card in un host multi-agent

Il `name` di una card è un'etichetta leggibile da una persona, non un'identità di routing stabile.<sup>[[1]](#references)[[5]](#references)</sup> Se un host registra due peer remoti distinti con lo stesso nome locale, l'albero degli agent, il nome dello strumento generato, la mappa client o la route del broker potrebbero inviare al peer sbagliato un task destinato a quello attendibile.<sup>[[5]](#references)</sup> Perché ciò accada, il peer controllato dall'attaccante deve essere ammesso nello **stesso namespace di routing**; pubblicare una card duplicata su Internet non è sufficiente.<sup>[[5]](#references)</sup>

Testa il percorso di **ammissione-dispatch** dell'host con due peer controllati, URL distinti e un marker innocuo:<sup>[[5]](#references)</sup>

1. Registra la card, l'origine e il selettore locale del peer attendibile. Registra un secondo peer la cui card abbia lo stesso `name` ma il cui URL punti a un endpoint che controlli.
2. Attiva l'operazione che seleziona il peer attendibile in base al nome. Prova entrambi gli ordini di registrazione e, se i nomi diventano identificatori di strumenti, la normale normalizzazione dei nomi dell'host. Rileva quale endpoint riceve il marker e quale agent restituisce la risposta.
3. Modifica solo il nome della seconda card e ripeti. Se la richiesta raggiunge il secondo endpoint solo in caso di collisione, ciò dimostra l'invio al peer sbagliato. Verifica separatamente se sono stati effettivamente allegati dati sensibili o credenziali; la sola collisione del nome **non** dimostra il trasferimento di credenziali o autorità sugli strumenti.

Se il chiamante si rivolge a un endpoint fisso e associato all'origine anziché risolvere il nome di una card, questo test non si applica.<sup>[[5]](#references)</sup> Per le successive risposte di peer malevoli e l'impatto della prompt injection, consulta [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Test degli endpoint A2A

### Invio di task non autenticato

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

Un risultato `Task` o `Message` con `PONG`, quando la card dichiara uno schema di sicurezza, significa che l'autenticazione non è applicata sull'endpoint RPC (potrebbe essere applicata solo sulla UI o sulla card). Se la card non dichiara alcuno schema, verifica a cosa possono accedere le skill dell'agent: un agent non autenticato che può leggere dati interni o chiamare tool equivale a un'API non autenticata per quei tool.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

La spec richiede che il server verifichi, a ogni richiesta, che il chiamante possa accedere al task e che limiti `ListTasks` al chiamante anche quando non viene fornito alcun filtro.<sup>[[1]](#references)</sup> Verifica usando due identità (A e B):

1. Come A, crea un task e salva il suo `id` e `contextId`.
2. Come B (o senza credenziali), chiama `tasks/get` / `GetTask` con l'`id` di A, quindi `ListTasks` senza parametri.
3. Prova anche a eseguire cancel e subscribe sul task di A e invia un nuovo messaggio come B includendo il `taskId` o il `contextId` di A (in questo modo il testo di B verrebbe aggiunto alla conversazione di A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnerabile: B riceve la cronologia, gli artefatti o lo stato di A, oppure può modificare l'attività di A. Sicuro: un `TaskNotFoundError`, senza differenze tra «esiste ma non è tuo» e «non esiste».<sup>[[1]](#references)</sup> Gli ID delle task sono spesso UUID, quindi cercali nei punti in cui possono essere esposti (link condivisi, log, payload delle notifiche push, messaggi di errore).

### SSRF tramite webhook delle notifiche push

Quando `capabilities.pushNotifications` è `true`, il client fornisce all'agent un URL webhook e, in seguito, l'agent invia richieste `POST` con gli aggiornamenti delle task a quell'URL. La specifica dice che gli agent dovrebbero rifiutare gli intervalli privati, localhost e gli indirizzi link-local e usare allowlist.<sup>[[1]](#references)</sup> Crea una task, registra una configurazione per le notifiche push il cui `url` punta al tuo host OAST per confermare le richieste in uscita e poi (solo se lo scope lo consente) prova target interni come `http://127.0.0.1:<port>/` o `http://169.254.169.254/`. Confronta errori e tempi di risposta per individuare i servizi interni. L'agent aggiunge anche l'header di autenticazione configurato a queste richieste: se puoi modificare l'URL della configurazione di un altro utente, verifica che non venga inviato a un host scelto dall'attaccante. Vedi [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Le parti file-URL come secondo punto d'ingresso SSRF

A2A 1.0 permette a un messaggio o a un artefatto di contenere un riferimento a un file come `Part` con `url` (la versione 0.3 usa `kind: "file"` e `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Il protocollo trasporta il riferimento; recuperarlo è un comportamento dell'applicazione, non un requisito dell'SDK A2A.<sup>[[6]](#references)</sup> Si tratta di un caso distinto dall'URL di callback delle notifiche push descritto sopra. Verifica entrambe le direzioni: un file fornito dal client e inviato a un server A2A e un URL di file restituito da un peer meno affidabile a un orchestrator.<sup>[[1]](#references)[[6]](#references)</sup>

Per un endpoint JSON-RPC 1.0 autorizzato, sostituisci la normale parte di testo con un URL a un percorso OAST univoco e verifica **quale componente** effettua la richiesta:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Solo se il destinatario lo dereferenzia, verifica le destinazioni interne in-scope, i redirect e le modifiche alla risoluzione DNS usando il [workflow SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Un `Part` valido o una risposta riuscita all’attività, da soli, non dimostrano la presenza di SSRF: conferma che la richiesta raggiunga la destinazione e verifica se il contenuto recuperato viene trasmesso all’agent.<sup>[[6]](#references)</sup>

### Accesso alla scheda estesa dell’agent

`GetExtendedAgentCard` deve richiedere l’autenticazione e può restituire più skill e configurazioni rispetto alla scheda pubblica.<sup>[[1]](#references)</sup> Chiamalo senza credenziali e con un’identità con privilegi limitati, quindi confronta il risultato con la scheda pubblica.

### Configurazioni delle notifiche push e leak di credenziali durante un task

Le configurazioni delle notifiche push memorizzano un URL webhook e le credenziali che l’agent gli invia. La specifica richiede che ogni operazione sulle configurazioni delle notifiche push (create, get, list, delete) verifichi che il chiamante possa accedere al task.<sup>[[1]](#references)</sup> Ripeti su queste route il test con due identità descritto nella [sezione task IDOR](#task-idor-tasksget-gettask-cancel-subscribe). Una configurazione di un altro utente accessibile in lettura rivela un token webhook, mentre una accessibile in scrittura reindirizza gli aggiornamenti dei task di quell’utente al tuo host.

Quando un agent ha bisogno di un’autorizzazione aggiuntiva durante un task, sposta il task nello stato `TASK_STATE_AUTH_REQUIRED`. Il client può organizzare l’autorizzazione out of band; la specifica stabilisce che gli agent devono ricevere le credenziali out of band, a meno che non sia stato concordato un meccanismo in-band. Uno scambio in-band può trasmettere una credenziale attraverso una catena di agent A2A e renderla visibile a tutti gli agent della catena.<sup>[[1]](#references)</sup> In un test dell’orchestrator, verifica se una credenziale fornita dall’utente per un agent downstream compare nei messaggi, negli artifact o nella cronologia dei task accessibili ad altri agent (o ad altri utenti tramite task IDOR).

Anche i campi della scheda dell’agent e i risultati dei task sono input non attendibili per l’agent chiamante. Verificali usando le tecniche di indirect prompt injection descritte in [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) e i controlli di fiducia tra agent descritti in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Specifiche del protocollo A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog di Google Developers — Annuncio del protocollo Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Specifiche A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Specifiche A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Attacchi di collisione dei nomi degli agent nei sistemi multi-agent](https://arxiv.org/abs/2609.27624)
- [6] [Guida alla sicurezza dell’SDK A2A .NET](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Guida alla migrazione di A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
