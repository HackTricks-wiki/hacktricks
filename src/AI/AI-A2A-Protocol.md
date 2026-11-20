# Usalama wa Itifaki ya A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## A2A ni nini

A2A (Agent2Agent) ni itifaki iliyo wazi inayomwezesha agent mmoja wa AI kugundua agent mwingine na kumtumia kazi kupitia HTTP. MCP huunganisha agent na **tools and data**; A2A huunganisha agent na **agents wengine**, ambao kwa kawaida ni huduma za mbali zinazomilikiwa na timu au kampuni nyingine. Server ya A2A ni API ya wavuti yenye agent ya LLM nyuma yake, kwa hiyo vitu vya itifaki yenyewe (agent cards, tasks, push-notification webhooks, extended cards) huongeza ukaguzi mahususi wa authentication, IDOR na SSRF kwenye jaribio la kawaida la API.<sup>[[1]](#references)[[2]](#references)</sup>

Vipengele vikuu ni:

- **Agent Card:** hati ya JSON inayoeleza agent: jina, maelezo, skills, URL za huduma, transports zinazotumika, capabilities (streaming, push notifications, extended card) na `securitySchemes` ambazo client lazima itumie. Huchapishwa kwenye `https://<host>/.well-known/agent-card.json`. Deployments za zamani zinazofuata spec 0.2.x hutumia `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** kipengele cha kazi. Message huunda task (yenye `id` na `contextId` zinazozalishwa na server), na baadaye client huisoma, huighairi au hujisajili kuipokea.<sup>[[1]](#references)</sup>
- **Transports:** JSON-RPC 2.0 kupitia HTTP (pamoja na SSE kwa streaming), gRPC, na HTTP+JSON REST binding.<sup>[[1]](#references)</sup>
- **Authentication:** credentials huwekwa kwenye HTTP headers (kwa mfano `Authorization: Bearer ...`), kamwe si ndani ya JSON-RPC payload. Agent card huonyesha scheme inayohitajika.<sup>[[1]](#references)</sup>

Majina ya method yalibadilika kati ya matoleo, kwa hiyo jaribu seti zote mbili:<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Operesheni | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Tuma message | `message/send` | `SendMessage` | `POST /message:send` |
| Tuma kwa streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Pata task | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Orodhesha tasks | - | `ListTasks` | `GET /tasks` |
| Ghairi task | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Usanidi wa push notification | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3); HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

Spec 1.0 hutumia header ya `A2A-Version` (au kigezo cha request) kuchagua toleo, na requests zisizo na header hiyo huchukuliwa kuwa za 0.3.<sup>[[1]](#references)</sup>

## Ugunduzi

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Kutoka kwenye kadi, andika:

- Kila `url` ya huduma: katika 1.0, hizi ziko chini ya `supportedInterfaces`, ilhali kadi za zamani zinaweza kuwa na `url` ya kiwango cha juu. Rekodi kila endpoint na transport, ikijumuisha majina ya ndani ya host, URL za staging na port mbadala.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills`: zinaonyesha kile ambacho agent inaweza kufanya na zana au data zilizo nyuma yake.
- `securitySchemes` / `security`: ikiwa hazina thamani au hazipo, huenda agent imekusudiwa kuitwa bila credentials.
- `capabilities.pushNotifications` na `capabilities.extendedAgentCard` (katika 0.3, `supportsAuthenticatedExtendedCard`).

Spec inasema kadi ya umma haipaswi kuwa na credentials au maelezo ya ndani ya utekelezaji, kwa hivyo URL za ndani, keys au orodha za kina za zana kwenye kadi ya umma tayari ni finding.<sup>[[1]](#references)</sup>

### Mgongano wa jina la Agent Card katika host yenye agents wengi

`name` ya kadi ni lebo inayosomeka na binadamu, si utambulisho thabiti wa routing.<sup>[[1]](#references)[[5]](#references)</sup> Ikiwa host itasajili peers wawili tofauti wa mbali chini ya jina moja la ndani, mti wa agent, jina la zana linalozalishwa, ramani ya client au njia ya broker inaweza kutuma task iliyokusudiwa kwa peer anayeaminika kwa peer mwingine.<sup>[[5]](#references)</sup> Hili linahitaji peer inayodhibitiwa na mshambuliaji kukubaliwa katika **namespace ileile ya routing**; kuchapisha kadi rudufu kwenye Internet pekee hakutoshi.<sup>[[5]](#references)</sup>

Jaribu njia ya host ya **kukubali hadi kutuma** kwa kutumia peers wawili unaowadhibiti, URL tofauti na alama isiyo na madhara:<sup>[[5]](#references)</sup>

1. Rekodi kadi, origin na selector ya ndani ya peer anayeaminika. Sajili peer wa pili ambaye kadi yake ina `name` ileile, lakini URL yake inaelekeza kwenye endpoint unayoidhibiti.
2. Anzisha operesheni inayochagua peer anayeaminika kwa jina. Jaribu mpangilio wa usajili wa aina zote mbili na, ikiwa majina yanakuwa vitambulishi vya zana, jaribu urekebishaji wa kawaida wa majina wa host. Nasa ni endpoint gani inayopokea alama na ni agent gani inayorejesha jibu.
3. Badilisha jina la kadi ya pili pekee kisha urudie. Ombi kufika kwenye endpoint ya pili katika hali ya mgongano pekee kunathibitisha kutumwa kwa peer isiyo sahihi. Kando na hilo, angalia kama muktadha wowote nyeti au credential iliambatishwa; mgongano wa jina peke yake **hauthibitishi** uhamisho wa credential au mamlaka ya zana.

Ikiwa caller inatumia endpoint isiyobadilika na inayofungamana na origin badala ya kutafuta jina la kadi, jaribio hili halitumiki.<sup>[[5]](#references)</sup> Kwa majibu ya peers hasidi yanayofuata na athari za prompt injection, fuata [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Kupima endpoints za A2A

### Kuwasilisha task bila uthibitishaji

Tuma ujumbe mfupi usio na credentials kwa kila `url` iliyoorodheshwa kwenye kadi:

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

Matokeo ya `Task` au `Message` yenye `PONG`, wakati card inapotangaza security scheme, yanamaanisha kuwa uthibitishaji hautekelezwi kwenye RPC endpoint (huenda unatekelezwa tu kwenye UI au kwenye card). Ikiwa card haitangazi scheme, angalia ni nini skills za agent zinaweza kufikia: agent asiyehitaji uthibitishaji anayeweza kusoma data za ndani au kuita tools ni sawa na API isiyohitaji uthibitishaji kwa tools hizo.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

Spec inamtaka server aangalie, kwenye kila ombi, ikiwa caller anaruhusiwa kufikia task, na aweke `ListTasks` kwenye mipaka ya caller hata kama hakuna filter iliyotolewa.<sup>[[1]](#references)</sup> Ijaribu kwa kutumia identity mbili (A na B):

1. Ukiwa A, tengeneza task na uhifadhi `id` na `contextId` yake.
2. Ukiwa B (au bila credentials), ita `tasks/get` / `GetTask` kwa kutumia `id` ya A, kisha ita `ListTasks` bila parameters.
3. Pia jaribu cancel na subscribe kwenye task ya A, na utume ujumbe mpya ukiwa B unaojumuisha `taskId` au `contextId` ya A (hii ingeongeza maandishi ya B kwenye mazungumzo ya A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Inaweza kuathiriwa: B hupokea historia, artifacts au hali ya A, au inaweza kubadilisha task ya A. Salama: `TaskNotFoundError`, bila tofauti kati ya “ipo lakini si yako” na “haipo”.<sup>[[1]](#references)</sup> Task IDs mara nyingi ni UUID, kwa hivyo zitafute kwenye sehemu zinakoweza kuvuja (shared links, logs, push notification payloads, error messages).

### SSRF kupitia push notification webhook

Wakati `capabilities.pushNotifications` ni true, client huipa agent URL ya webhook, kisha agent hutuma maombi ya `POST` yenye masasisho ya task kwenye URL hiyo. Spec inasema agents zinapaswa kukataa private ranges, localhost na link-local addresses, na kutumia allowlists.<sup>[[1]](#references)</sup> Unda task, sajili push notification config ambayo `url` inaelekeza kwenye OAST host yako ili kuthibitisha maombi yanayotoka, kisha (ikiwa tu scope inaruhusu) elekeza kwenye internal targets kama `http://127.0.0.1:<port>/` au `http://169.254.169.254/`. Linganisha errors na muda wa majibu ili kutambua internal services. Agent pia huongeza authentication header iliyosanidiwa kwenye maombi haya, kwa hivyo hakikisha haitumwi kwa host iliyochaguliwa na mshambuliaji ikiwa unaweza kubadilisha URL ya config ya mtumiaji mwingine. Angalia [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### File-URL Parts kama sehemu ya pili ya kuingilia SSRF

A2A 1.0 huruhusu message au artifact kubeba rejeleo la file kama `Part` yenye `url` (0.3 hutumia `kind: "file"` na `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Protocol hubeba rejeleo; kulichukua ni tabia ya application, si sharti la A2A SDK.<sup>[[6]](#references)</sup> Hili ni tofauti na URL ya push-notification callback iliyo hapo juu. Jaribu pande zote mbili: file iliyotolewa na client na kutumwa kwa A2A server, na file URL iliyorejeshwa na peer yenye kiwango cha chini cha uaminifu kwa orchestrator.<sup>[[1]](#references)[[6]](#references)</sup>

Kwa endpoint ya JSON-RPC ya 1.0 iliyoidhinishwa, badilisha text part ya kawaida na URL inayoelekeza kwenye OAST path ya kipekee, kisha angalia **ni component gani** inayotuma ombi:<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Iwapo tu mpokeaji ataifuata, ndipo ujaribu maeneo ya ndani yaliyo ndani ya wigo, uelekezaji upya na mabadiliko ya utatuzi wa DNS kwa kutumia [mchakato wa SSRF](../pentesting-web/ssrf-server-side-request-forgery/). `Part` halali au jibu la kazi lililofaulu pekee havithibitishi SSRF; thibitisha kuwa ombi limefika kwenye lengwa na kama maudhui yaliyopatikana yanafika kwa agent.<sup>[[6]](#references)</sup>

### Ufikiaji wa kadi ya agent iliyopanuliwa

`GetExtendedAgentCard` lazima ihitaji uthibitishaji na inaweza kurudisha ujuzi na usanidi mwingi zaidi kuliko kadi ya umma.<sup>[[1]](#references)</sup> Iite bila vitambulisho na kwa utambulisho wenye ruhusa ndogo, kisha linganisha matokeo na kadi ya umma.

### Mipangilio ya arifa za push na uvujaji wa vitambulisho ndani ya kazi

Mipangilio ya arifa za push huhifadhi URL ya webhook na vitambulisho ambavyo agent hutuma kwake. Spec inahitaji kila operesheni ya mipangilio ya arifa za push (kuunda, kupata, kuorodhesha, kufuta) ithibitishe kuwa mpigaji anaweza kufikia kazi hiyo.<sup>[[1]](#references)</sup> Rudia jaribio la utambulisho mbili kutoka sehemu ya [task IDOR](#task-idor-tasksget-gettask-cancel-subscribe) kwenye njia hizi. Mipangilio ya mtumiaji mwingine inayoweza kusomwa hufichua tokeni ya webhook; mipangilio inayoweza kuandikwa huelekeza masasisho ya kazi ya mtumiaji huyo kwenye host yako.

Agent inapohitaji idhini ya ziada wakati wa kazi, huhamisha kazi hadi `TASK_STATE_AUTH_REQUIRED`. Mteja anaweza kupanga idhini nje ya mkondo; specification inasema agents lazima zipokee vitambulisho nje ya mkondo isipokuwa utaratibu wa ndani ya mkondo ulijadiliwa. Mabadilishano ya ndani ya mkondo yanaweza kupitisha kitambulisho kupitia msururu wa agents za A2A na kukifichua kwa kila agent kwenye msururu huo.<sup>[[1]](#references)</sup> Katika jaribio la orchestrator, angalia kama kitambulisho ambacho mtumiaji anatoa kwa agent moja ya chini ya mkondo kinaonekana kwenye ujumbe, artifacts au historia ya kazi ambayo agents wengine (au watumiaji wengine kupitia task IDOR) wanaweza kusoma.

Sehemu za kadi ya agent na matokeo ya kazi pia ni ingizo lisiloaminika kwa agent inayopiga simu. Zijaribu kwa mbinu za indirect prompt injection katika [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) na ukaguzi wa uaminifu kati ya agents katika [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Maelezo ya Itifaki ya A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Google Developers Blog — Kutangaza Itifaki ya Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Maelezo ya A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Maelezo ya A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Mashambulizi ya Mgongano wa Majina ya Agent katika Mifumo ya Multi-Agent](https://arxiv.org/abs/2609.27624)
- [6] [Mwongozo wa Usalama wa A2A .NET SDK](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Mwongozo wa Uhamishaji wa A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
