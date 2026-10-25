# A2A (Agent2Agent) Protocol Security

{{#include ../banners/hacktricks-training.md}}

## Wat is A2A

A2A (Agent2Agent) is ’n oop protokol waarmee een AI-agent ’n ander agent kan ontdek en werk via HTTP daarheen kan stuur. MCP koppel ’n agent aan **tools en data**; A2A koppel ’n agent aan **ander agente**, wat gewoonlik afgeleë dienste is wat deur ’n ander span of maatskappy besit word. ’n A2A-bediener is ’n web-API met ’n LLM-agent daaragter, dus voeg die protokol se eie voorwerpe (agent cards, tasks, push-notification-webhooks, extended cards) spesifieke verifikasie-, IDOR- en SSRF-kontroles by ’n gewone API-toets.<sup>[[1]](#references)[[2]](#references)</sup>

Die hoofdele is:

- **Agent Card:** ’n JSON-dokument wat die agent beskryf: naam, beskrywing, vaardighede, diens-URL’s, ondersteunde transports, capabilities (streaming, push notifications, extended card) en die `securitySchemes` wat die kliënt moet gebruik. Dit word gepubliseer by `https://<host>/.well-known/agent-card.json`. Ouer ontplooiings wat spec 0.2.x volg, gebruik `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** die eenheid van werk. ’n Boodskap skep ’n task (met ’n bediener-gegenereerde `id` en ’n `contextId`), en die kliënt lees dit later, kanselleer dit of teken daarop in.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 oor HTTP (met SSE vir streaming), gRPC en ’n HTTP+JSON REST-binding.<sup>[[1]](#references)</sup>
- **Authentication:** geloofsbriewe word in HTTP-headers geplaas (byvoorbeeld `Authorization: Bearer ...`), nooit binne die JSON-RPC-payload nie. Die agent card dui aan watter skema vereis word.<sup>[[1]](#references)</sup>

Metodename het tussen weergawes verander, dus probeer albei stelle:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operasie | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Stuur boodskap | `message/send` | `SendMessage` | `POST /message:send` |
| Stuur streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Kry task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Lys tasks | - | `ListTasks` | `GET /tasks` |
| Kanselleer task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Push-notification-konfigurasie | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Die 1.0-spec gebruik die `A2A-Version`-header (of ’n versoekparameter) om die weergawe te kies; versoeke daarsonder word as 0.3 hanteer.<sup>[[1]](#references)</sup>

## Ontdekking

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Skryf die volgende uit die kaart neer:

- Elke diens se `url` (dikwels ’n interne gasheernaam, ’n staging-URL of ’n ander poort as dié van die publieke webwerf).
- `skills`: dit wys wat die agent kan doen en watter nutsmiddels of data daaragter sit.
- `securitySchemes` / `security`: as hulle leeg of ontbreek, is die agent waarskynlik bedoel om sonder aanmeldbewyse aangeroep te word.
- `capabilities.pushNotifications` en `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

Die spesifikasie sê dat die publieke kaart nie aanmeldbewyse of interne implementeringsbesonderhede moet bevat nie; interne URL’s, sleutels of gedetailleerde lyste van nutsmiddels in ’n publieke kaart is dus reeds ’n bevinding.<sup>[[1]](#references)</sup>

## Toetsing van A2A-eindpunte

### Indiening van take sonder verifikasie

Stuur ’n minimale boodskap sonder enige aanmeldbewyse na elke `url` wat in die kaart gelys word:

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

'n `Task`- of `Message`-resultaat met `PONG`, wanneer die card 'n sekuriteitskema verklaar, beteken dat verifikasie nie op die RPC-endpoint afgedwing word nie (dit word moontlik net op die UI of op die card afgedwing). As die card geen skema verklaar nie, kyk waartoe die agent se skills toegang het: 'n agent sonder verifikasie wat interne data kan lees of tools kan aanroep, is dieselfde as 'n API sonder verifikasie vir daardie tools.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Die spesifikasie vereis dat die server by elke versoek nagaan of die caller toegang tot die task mag hê, en dat `ListTasks` beperk word tot die caller, selfs wanneer geen filter gegee word nie.<sup>[[1]](#references)</sup> Toets dit met twee identiteite (A en B):

1. Skep as A 'n task en stoor sy `id` en `contextId`.
2. Roep as B (of sonder credentials) `tasks/get` / `GetTask` aan met A se `id`, en daarna `ListTasks` sonder parameters.
3. Probeer ook om A se task te cancel en daarop in te teken, en stuur 'n nuwe message as B wat A se `taskId` of `contextId` bevat (dit sal B se teks by A se gesprek voeg).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Kwetsbaar: B ontvang A se geskiedenis, artefakte of status, of kan A se taak verander. Veilig: ’n `TaskNotFoundError`, sonder enige verskil tussen “bestaan, maar is nie joune nie” en “bestaan nie”.<sup>[[1]](#references)</sup> Taak-ID’s is dikwels UUID’s, soek dus daarna op plekke waar hulle kan lek (gedeelde skakels, logs, stootkennisgewing-loogslaaie, foutboodskappe).

### SSRF via stootkennisgewing-webhook

Wanneer `capabilities.pushNotifications` waar is, gee die kliënt die agent ’n webhook-URL, waarna die agent later `POST`-versoeke met taakopdaterings na daardie URL stuur. Die spesifikasie sê agente moet private reekse, localhost en skakellokale adresse weier en toelaatlyste gebruik.<sup>[[1]](#references)</sup> Skep ’n taak en registreer ’n stootkennisgewingkonfigurasie waarvan die `url` na jou OAST-gasheer wys om uitgaande versoeke te bevestig, en daarna (slegs indien die omvang dit toelaat) na interne teikens soos `http://127.0.0.1:<port>/` of `http://169.254.169.254/`. Vergelyk foute en tydsberekening om interne dienste in kaart te bring. Die agent voeg ook die gekonfigureerde verifikasie-opskrif by hierdie versoeke, so kyk dat dit nie na ’n aanvallergekose gasheer gestuur word wanneer jy die URL van ’n ander gebruiker se konfigurasie kan verander nie. Sien [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Toegang tot uitgebreide agentkaart

`GetExtendedAgentCard` moet verifikasie vereis en kan meer vaardighede en konfigurasie as die publieke kaart teruggee.<sup>[[1]](#references)</sup> Roep dit sonder geloofsbriewe en met ’n identiteit met min voorregte aan, en vergelyk die resultaat met die publieke kaart.

### Stootkennisgewingkonfigurasie en lekkasies van geloofsbriewe binne take

Stootkennisgewingkonfigurasies stoor ’n webhook-URL en die geloofsbriewe wat die agent daarheen stuur. Die spesifikasie vereis dat elke bewerking met ’n stootkennisgewingkonfigurasie (skep, kry, lys, verwyder) verifieer dat die oproeper toegang tot die taak mag hê.<sup>[[1]](#references)</sup> Herhaal die twe identiteite-toets van die [taak-IDOR-afdeling](#task-idor-tasksget-gettask-cancel-subscribe) op hierdie roetes. ’n Leesbare konfigurasie van ’n ander gebruiker lek ’n webhook-token, en ’n skryfbare konfigurasie herlei daardie gebruiker se taakopdaterings na jou gasheer.

Wanneer ’n agent ekstra magtiging tydens ’n taak nodig het, skuif dit die taak na `TASK_STATE_AUTH_REQUIRED`. Die kliënt kan magtiging buite die band reël; die spesifikasie sê agente moet geloofsbriewe buite die band ontvang, tensy ’n inband-meganisme onderhandel is. ’n Inband-uitruiling kan ’n geloofsbrief deur ’n ketting A2A-agente stuur en dit aan elke agent in daardie ketting blootstel.<sup>[[1]](#references)</sup> Kyk in ’n orkestreerdertoets of ’n geloofsbrief wat die gebruiker vir een stroomaf-agent gee, verskyn in boodskappe, artefakte of taakgeskiedenis wat ander agente (of ander gebruikers deur taak-IDOR) kan lees.

Agentkaartvelde en taakresultate is ook onbetroubare invoer vir die oproepende agent. Toets hulle met die indirekte prompt-inspuitingstegnieke in [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) en die vertrouenskontroles tussen agente in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [A2A-protokolspesifikasie](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Kondig die Agent2Agent-protokol (A2A) aan](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A-spesifikasie v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A-spesifikasie v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
