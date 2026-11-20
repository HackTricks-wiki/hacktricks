# A2A (Agent2Agent)-protokolsekuriteit

{{#include ../banners/hacktricks-training.md}}

## Wat is A2A

A2A (Agent2Agent) is ’n oop protokol waarmee een AI-agent ’n ander agent kan ontdek en werk via HTTP aan hom kan stuur. MCP koppel ’n agent aan **nutsmiddels en data**; A2A koppel ’n agent aan **ander agents**, wat gewoonlik afgeleë dienste is wat deur ’n ander span of maatskappy besit word. ’n A2A-bediener is ’n web-API met ’n LLM-agent daaragter, dus voeg die protokol se eie objekte (agent cards, take, webhooks vir stootkennisgewings, uitgebreide cards) spesifieke verifikasie-, IDOR- en SSRF-kontroles by ’n gewone API-toets.<sup>[[1]](#references)[[2]](#references)</sup>

Die hoofdele is:

- **Agent Card:** ’n JSON-dokument wat die agent beskryf: naam, beskrywing, vaardighede, diens-URL(s), ondersteunde transportmetodes, vermoëns (streaming, stootkennisgewings, uitgebreide card) en die `securitySchemes` wat die kliënt moet gebruik. Dit word by `https://<host>/.well-known/agent-card.json` gepubliseer. Ouer ontplooiings wat spec 0.2.x volg, gebruik `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** die werkeenheid. ’n Boodskap skep ’n task (met ’n bediener-gegenereerde `id` en ’n `contextId`), en die kliënt lees, kanselleer of teken later daarop in.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 oor HTTP (met SSE vir streaming), gRPC en ’n HTTP+JSON REST-binding.<sup>[[1]](#references)</sup>
- **Authentication:** geloofsbriewe word in HTTP-headers geplaas (byvoorbeeld `Authorization: Bearer ...`), nooit binne die JSON-RPC-payload nie. Die agent card dui aan watter skema vereis word.<sup>[[1]](#references)</sup>

Metodename het tussen weergawes verander, dus probeer albei stelle:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operasie | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Stuur boodskap | `message/send` | `SendMessage` | `POST /message:send` |
| Stuur boodskap met streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Kry task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Lys tasks | - | `ListTasks` | `GET /tasks` |
| Kanselleer task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Konfigurasie van stootkennisgewings | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Uitgebreide card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Die 1.0-spec gebruik die `A2A-Version`-header (of ’n versoekparameter) om die weergawe te kies, en versoeke daarsonder word as 0.3 behandel.<sup>[[1]](#references)</sup>

## Ontdekking

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Skryf die volgende uit die kaart neer:

- Elke diens-`url`: in 1.0 verskyn hierdie onder `supportedInterfaces`, terwyl ouer kaarte moontlik `url` op die boonste vlak kan blootlê. Teken elke eindpunt en transport aan, insluitend interne gasheername, staging-URL’s en alternatiewe poorte.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: dit wys wat die agent kan doen en watter tools of data daaragter sit.
- `securitySchemes` / `security`: as hulle leeg of afwesig is, is die agent waarskynlik bedoel om sonder credentials aangeroep te word.
- `capabilities.pushNotifications` en `capabilities.extendedAgentCard` (in 0.3 `supportsAuthenticatedExtendedCard`).

Die spesifikasie sê dat die openbare kaart nie credentials of interne implementasiebesonderhede moet bevat nie, dus is interne URL’s, keys of gedetailleerde tool-lyste in ’n openbare kaart reeds ’n finding.<sup>[[1]](#references)</sup>

### Agent Card-naamk botsing in ’n multi-agent host

’n Kaart se `name` is ’n mensleesbare etiket, nie ’n stabiele roeteringsidentiteit nie.<sup>[[1]](#references)[[5]](#references)</sup> As ’n host twee verskillende afgeleë peers onder dieselfde plaaslike naam registreer, kan sy agent-boom, gegenereerde tool-naam, kliëntkaart of broker-roete ’n taak wat vir die vertroude peer bedoel is, na die ander peer stuur.<sup>[[5]](#references)</sup> Dit vereis dat die aanvallerbeheerde peer tot dieselfde roeteringsnaamruimte toegelaat word; om ’n duplikaatkaart op die Internet te publiseer, is op sigself nie genoeg nie.<sup>[[5]](#references)</sup>

Toets die host se **toelating-tot-versending**-pad met twee peers wat jy beheer, verskillende URL’s en ’n onskadelike merker:<sup>[[5]](#references)</sup>

1. Teken die vertroude peer se kaart, oorsprong en plaaslike selektor aan. Registreer ’n tweede peer waarvan die kaart dieselfde `name` het, maar waarvan die URL na ’n eindpunt wys wat jy beheer.
2. Aktiveer die bewerking wat die vertroude peer op naam kies. Probeer albei registrasie-ordes en, as name tool-identifiseerders word, die host se gewone naamnormalisering. Teken aan watter eindpunt die merker ontvang en watter agent die antwoord terugstuur.
3. Verander net die tweede kaart se naam en herhaal. As ’n versoek slegs in die botsingsgeval die tweede eindpunt bereik, bewys dit verkeerde-peer-versending. Kontroleer afsonderlik of enige sensitiewe konteks of credential werklik aangeheg is; die naambotsing alleen bewys **nie** dat credentials of tool-bevoegdheid oorgedra is nie.

As die oproeper ’n vaste, oorspronggebonde eindpunt aanspreek eerder as om ’n kaartnaam op te los, is hierdie toets nie van toepassing nie.<sup>[[5]](#references)</sup> Vir daaropvolgende kwaadwillige peer-antwoorde en die impak van prompt-injection, volg [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Toetsing van A2A-eindpunte

### Taakindiening sonder verifikasie

Stuur ’n minimale boodskap sonder credentials na elke `url` wat in die kaart gelys word:

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

’n `Task`- of `Message`-resultaat met `PONG`, wanneer die card ’n sekuriteitskema verklaar, beteken dat verifikasie nie op die RPC-eindpunt afgedwing word nie (dit word dalk net op die UI of op die card afgedwing). As die card geen skema verklaar nie, kyk waartoe die agent se vaardighede toegang het: ’n agent sonder verifikasie wat interne data kan lees of tools kan aanroep, is dieselfde as ’n API sonder verifikasie vir daardie tools.

### Task-IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Die spesifikasie vereis dat die bediener by elke versoek nagaan of die aanroeper toegang tot die taak mag hê, en dat `ListTasks` tot die aanroeper beperk word, selfs wanneer geen filter gegee word nie.<sup>[[1]](#references)</sup> Toets dit met twee identiteite (A en B):

1. Skep ’n taak as A en stoor die `id` en `contextId` daarvan.
2. Roep as B (of sonder geloofsbriewe) `tasks/get` / `GetTask` met A se `id` aan, en roep dan `ListTasks` sonder parameters aan.
3. Probeer ook om A se taak te kanselleer en daarop in te teken, en stuur as B ’n nuwe boodskap wat A se `taskId` of `contextId` bevat (dit sal B se teks by A se gesprek voeg).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Kwetsbaar: B ontvang A se geskiedenis, artefakte of status, of kan A se taak verander. Veilig: ’n `TaskNotFoundError`, sonder enige verskil tussen “bestaan maar is nie joune nie” en “bestaan nie”.<sup>[[1]](#references)</sup> Taak-ID’s is dikwels UUID’s, soek dus daarna op plekke waar hulle kan lek (gedeelde skakels, logs, push notification-payloads, foutboodskappe).

### Push notification-webhook SSRF

Wanneer `capabilities.pushNotifications` true is, gee die kliënt die agent ’n webhook-URL, en die agent stuur later `POST`-versoeke met taakopdaterings na daardie URL. Die spesifikasie sê agente moet private reekse, localhost en link-local-adresse verwerp, en allowlists gebruik.<sup>[[1]](#references)</sup> Skep ’n taak, registreer ’n push notification-konfigurasie waarvan `url` na jou OAST-host wys om uitgaande versoeke te bevestig, en dan (slegs as die omvang dit toelaat) na interne teikens soos `http://127.0.0.1:<port>/` of `http://169.254.169.254/`. Vergelyk foute en tydsberekening om interne dienste in kaart te bring. Die agent voeg ook die gekonfigureerde verifikasieheader by hierdie versoeke, so kyk dat dit nie na ’n aanvallergekose host gestuur word wanneer jy die URL van ’n ander gebruiker se konfigurasie kan verander nie. Sien [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### File-URL-Parts as ’n tweede SSRF-ingangspunt

A2A 1.0 laat ’n boodskap of artefak toe om ’n lêerverwysing as ’n `Part` met `url` te dra (0.3 gebruik `kind: "file"` en `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Die protokol dra die verwysing; om dit te gaan haal, is toepassingsgedrag, nie ’n vereiste van die A2A SDK nie.<sup>[[6]](#references)</sup> Dit is apart van die push notification-terugbel-URL hierbo. Toets albei rigtings: ’n lêer wat deur die kliënt voorsien en na ’n A2A-bediener gestuur word, en ’n lêer-URL wat deur ’n eweknie met laer vertroue aan ’n orkestreerder teruggestuur word.<sup>[[1]](#references)[[6]](#references)</sup>

Vir ’n gemagtigde 1.0 JSON-RPC-eindpunt, vervang die gewone teksdeel met ’n URL na ’n unieke OAST-pad en kyk **watter komponent** die versoek maak:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Slegs as die ontvanger dit dereferenceer, moet jy in-scope interne bestemmings, redirects en DNS-resolusieveranderinge toets met die [SSRF-werkvloei](../pentesting-web/ssrf-server-side-request-forgery/). ’n Geldige `Part` of ’n suksesvolle taakrespons bewys nie op sigself SSRF nie; bevestig dat die fetch by die bestemming plaasvind en of die agent die opgehaalde inhoud ontvang.<sup>[[6]](#references)</sup>

### Toegang tot uitgebreide agentkaart

`GetExtendedAgentCard` moet verifikasie vereis en kan meer vaardighede en konfigurasie as die publieke kaart terugstuur.<sup>[[1]](#references)</sup> Roep dit sonder geloofsbriewe en met ’n identiteit met lae voorregte aan, en vergelyk die resultaat met die publieke kaart.

### Push-notifikasiekonfigurasie en lekkasies van geloofsbriewe tydens take

Push-notifikasiekonfigurasies stoor ’n webhook-URL en die geloofsbriewe wat die agent daarheen stuur. Die spesifikasie vereis dat elke bewerking met ’n push-notifikasiekonfigurasie (create, get, list, delete) verifieer dat die oproeper toegang tot die taak mag hê.<sup>[[1]](#references)</sup> Herhaal die twe identiteit-toets uit die [task IDOR-afdeling](#task-idor-tasksget-gettask-cancel-subscribe) op hierdie roetes. ’n Leesbare konfigurasie van ’n ander gebruiker lek ’n webhook-token, en ’n skryfbare een stuur daardie gebruiker se taakopdaterings na jou host aan.

Wanneer ’n agent tydens ’n taak ekstra magtiging benodig, skuif dit die taak na `TASK_STATE_AUTH_REQUIRED`. Die kliënt kan magtiging buite die band reël; die spesifikasie sê dat agente geloofsbriewe buite die band moet ontvang, tensy ’n in-band-meganisme onderhandel is. In-band-uitruiling kan ’n geloofsbrief deur ’n ketting van A2A-agente stuur en dit aan elke agent in daardie ketting blootstel.<sup>[[1]](#references)</sup> Kyk in ’n orkestreerdertoets of ’n geloofsbrief wat die gebruiker vir een afstroomagent gee, verskyn in boodskappe, artifacts of taakgeskiedenis wat ander agente (of ander gebruikers deur task IDOR) kan lees.

Agentkaartvelde en taakresultate is ook onbetroubare invoer vir die agent wat die oproep doen. Toets dit met die indirekte prompt injection-tegnieke in [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) en die vertrouenskontroles tussen agente in [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [A2A-protokolspesifikasie](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Kondig die Agent2Agent-protokol (A2A) aan](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A-spesifikasie v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A-spesifikasie v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Aanvalle met agentnaam-botsings in multi-agentstelsels](https://arxiv.org/abs/2609.27624)
- [6] [A2A .NET SDK-sekuriteitsgids](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [A2A Python v1.0-migrasiegids](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
