# Usalama wa Itifaki ya A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## A2A ni nini

A2A (Agent2Agent) ni itifaki huria inayowezesha agenti moja ya AI kugundua agenti nyingine na kuitumia kutuma kazi kupitia HTTP. MCP huunganisha agenti na **tools na data**; A2A huunganisha agenti na **agenti nyingine**, ambazo kwa kawaida ni huduma za mbali zinazomilikiwa na timu au kampuni nyingine. Seva ya A2A ni API ya wavuti iliyo na agenti ya LLM nyuma yake, kwa hivyo vitu vya itifaki yenyewe (agent cards, tasks, push-notification webhooks, extended cards) huongeza ukaguzi mahususi wa authentication, IDOR na SSRF kwenye jaribio la kawaida la API.<sup>[[1]](#references)[[2]](#references)</sup>

Vipengele vikuu ni:

- **Agent Card:** hati ya JSON inayoeleza agenti: jina, maelezo, skills, URL(s) za huduma, transports zinazotumika, capabilities (streaming, push notifications, extended card) na `securitySchemes` ambazo client lazima itumie. Huchapishwa kwenye `https://<host>/.well-known/agent-card.json`. Deployments za zamani zinazofuata spec 0.2.x hutumia `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** kitengo cha kazi. Ujumbe huunda task (yenye `id` na `contextId` zinazotengenezwa na seva), na baadaye client huisoma, huighairi au hujisajili kuipokea.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 kupitia HTTP (pamoja na SSE kwa streaming), gRPC, na binding ya REST ya HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentication:** credentials huwekwa kwenye HTTP headers (kwa mfano `Authorization: Bearer ...`), kamwe si ndani ya JSON-RPC payload. Agent card huonyesha scheme inayohitajika.<sup>[[1]](#references)</sup>

Majina ya methods yalibadilika kati ya matoleo, kwa hivyo jaribu seti zote mbili:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operesheni | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Tuma ujumbe | `message/send` | `SendMessage` | `POST /message:send` |
| Tuma ujumbe kwa streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Pata task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Orodhesha tasks | - | `ListTasks` | `GET /tasks` |
| Ghairi task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Mipangilio ya push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Spec 1.0 hutumia header ya `A2A-Version` (au parameter ya request) kuchagua toleo, na requests zisizo na hiyo huchukuliwa kuwa za 0.3.<sup>[[1]](#references)</sup>

## Ugunduzi

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Kutoka kwenye kadi, andika:

- Kila `url` ya huduma (mara nyingi jina la mpangishi la ndani, URL ya staging au port tofauti na ile ya tovuti ya umma).
- `skills`: zinaonyesha kile ambacho agent inaweza kufanya na zana au data zilizo nyuma yake.
- `securitySchemes` / `security`: ikiwa hazina kitu au hazipo, huenda agent imekusudiwa kuitwa bila credentials.
- `capabilities.pushNotifications` na `capabilities.extendedAgentCard` (katika 0.3, `supportsAuthenticatedExtendedCard`).

Spec inasema kuwa kadi ya umma haipaswi kuwa na credentials au maelezo ya utekelezaji wa ndani, kwa hiyo URL za ndani, keys au orodha za kina za zana kwenye kadi ya umma tayari ni finding.<sup>[[1]](#references)</sup>

## Kujaribu A2A endpoints

### Kuwasilisha task bila uthibitishaji

Tuma ujumbe wa chini kabisa bila credentials zozote kwa kila `url` iliyoorodheshwa kwenye kadi:

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

Matokeo ya `Task` au `Message` yenye `PONG`, wakati kadi inapotangaza security scheme, yanamaanisha kuwa uthibitishaji hautekelezwi kwenye RPC endpoint (huenda ukatekelezwa tu kwenye UI au kwenye kadi). Ikiwa kadi haitangazi scheme, kagua ni nini skills za agent zinaweza kufikia: agent isiyohitaji uthibitishaji inayoweza kusoma data za ndani au kuita zana ni sawa na API isiyohitaji uthibitishaji ya zana hizo.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec inamtaka server akague, kwenye kila ombi, kwamba mpigaji simu anaruhusiwa kufikia task, na kuweka `ListTasks` kwenye upeo wa mpigaji simu hata kama hakuna kichujio kilichotolewa.<sup>[[1]](#references)</sup> Ijaribu kwa kutumia utambulisho mbili (A na B):

1. Kama A, tengeneza task na uhifadhi `id` na `contextId` yake.
2. Kama B (au bila credentials), ita `tasks/get` / `GetTask` ukitumia `id` ya A, kisha `ListTasks` bila vigezo.
3. Pia jaribu cancel na subscribe kwenye task ya A, na utume ujumbe mpya kama B unaojumuisha `taskId` au `contextId` ya A (hii itaongeza maandishi ya B kwenye mazungumzo ya A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Zilizo hatarini: B hupokea historia, artifacts au hali ya A, au inaweza kubadilisha task ya A. Salama: `TaskNotFoundError`, bila tofauti kati ya “ipo lakini si yako” na “haipo”.<sup>[[1]](#references)</sup> Task IDs mara nyingi ni UUID, kwa hivyo zitafute katika sehemu zinakoweza leak (viungo vilivyoshirikiwa, logs, payloads za arifa za push, ujumbe wa hitilafu).

### SSRF kupitia webhook ya arifa za push

Wakati `capabilities.pushNotifications` ni true, client huipa agent URL ya webhook, kisha agent hutuma maombi ya `POST` yenye masasisho ya task kwenye URL hiyo. Spec inasema agents wanapaswa kukataa private ranges, localhost na link-local addresses, na kutumia allowlists.<sup>[[1]](#references)</sup> Unda task, sajili push notification config ambayo `url` inaelekeza kwenye OAST host yako ili kuthibitisha maombi yanayotoka, kisha (ikiwa tu scope inaruhusu) elekeza kwenye targets za ndani kama `http://127.0.0.1:<port>/` au `http://169.254.169.254/`. Linganisha hitilafu na muda wa majibu ili kutambua internal services. Agent pia huongeza authentication header iliyosanidiwa kwenye maombi haya, kwa hivyo hakikisha haitumwi kwa host iliyochaguliwa na mshambuliaji ikiwa unaweza kubadilisha URL ya config ya mtumiaji mwingine. Tazama [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Ufikiaji wa extended agent card

`GetExtendedAgentCard` lazima ihitaji authentication na inaweza kurejesha skills na configuration nyingi zaidi kuliko public card.<sup>[[1]](#references)</sup> Iite bila credentials na kwa identity yenye ruhusa ndogo, kisha linganisha matokeo na public card.

### Push notification config na credential leaks ndani ya task

Push notification configs huhifadhi URL ya webhook na credentials ambazo agent hutuma humo. Spec inahitaji kila operesheni ya push notification config (create, get, list, delete) ithibitishe kuwa caller anaweza kufikia task.<sup>[[1]](#references)</sup> Rudia jaribio la identities mbili kutoka [sehemu ya task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) kwenye routes hizi. Config ya mtumiaji mwingine inayoweza kusomwa huleak token ya webhook, na inayoweza kuandikwa huelekeza masasisho ya task ya mtumiaji huyo kwenye host yako.

Agent inapohitaji uidhinishaji wa ziada wakati wa task, huihamisha task hadi `TASK_STATE_AUTH_REQUIRED`. Client inaweza kupanga uidhinishaji out of band; specification inasema agents lazima zipokee credentials out of band isipokuwa mechanism ya in-band iwe imekubaliwa. Exchange ya in-band inaweza kupitisha credential kwenye mnyororo wa A2A agents na kuifichua kwa kila agent katika mnyororo huo.<sup>[[1]](#references)</sup> Katika jaribio la orchestrator, hakikisha credential ambayo mtumiaji anatoa kwa downstream agent mmoja haionekani kwenye messages, artifacts au historia ya task ambayo agents wengine (au watumiaji wengine kupitia task IDOR) wanaweza kusoma.

Sehemu za agent card na matokeo ya task pia ni ingizo lisiloaminika kwa agent anayeziita. Zijaribu kwa kutumia mbinu za indirect prompt injection katika [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) na ukaguzi wa inter-agent trust katika [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [A2A Protocol Specification](https://a2a-protocol.org/latest/specification/)
- [2] [Blogu ya Google Developers — Kutangaza Agent2Agent Protocol (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [A2A specification v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [A2A specification v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
