# Mbinu ya Usalama wa AI Agent

{{#include ../banners/hacktricks-training.md}}

Tathmini ya agent inapaswa kufuata **ingizo linalodhibitiwa na mshambuliaji hadi athari inayoweza kuonekana kutoka nje**. Jailbreaking, mabadiliko ya herufi, na kufichua system prompt huthibitisha kuwa njia ya reasoning inaweza kuathiriwa, lakini finding yenye athari kubwa ni mnyororo unaoishia kwenye ufikiaji wa data, kitendo cha tool kisichoidhinishwa, sinki ya downstream injection, persistence, au agent mwingine.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ni muhimu kwa kuweka lebo za maeneo yaliyokaguliwa (goal hijacking, matumizi mabaya ya tool, matumizi mabaya ya privilege, supply chain, utekelezaji wa code, memory poisoning, uaminifu kati ya agent, hitilafu zinazofuatana, uaminifu wa binadamu, na rogue agents). Tumia lebo hizo baada ya kujenga attack path ya mwanzo hadi mwisho badala ya kuchukulia maandishi yasiyotarajiwa ya model kama mwisho wa test.<sup>[[1]](#references)[[2]](#references)</sup>

## Tengeneza ramani ya lengo

Rekodi vipengele hivi vitano kwa kila workflow ya agent kabla ya kuandika payloads:<sup>[[2]](#references)</sup>

| Kipengele | Vitu vya kuorodhesha | Swali la usalama |
|---|---|---|
| **Ingizo lisiloaminika** | Vigezo vya Chat/API, URLs, hati, barua pepe, tiketi, maingizo ya kalenda, vipande vilivyorejeshwa, memory, matokeo ya tool, na ujumbe kutoka kwa agent rika | Mshambuliaji anaweza kuweka maudhui wapi ili baadaye yaingie kwenye muktadha wa model? |
| **Tools** | Majina na schemas za tool, athari zake, utekelezaji wa kiotomatiki, tabia ya uthibitishaji, na tools zinazopakiwa kwa nguvu | Ni miito ipi husoma siri, hubadilisha hali, hutuma ujumbe, hufuta data, hutekeleza code, au huhamisha thamani? |
| **Mamlaka** | Uwakilishaji wa mtumiaji, service accounts, API tokens, muda wa uhai wa credentials, wigo wa tenant/resource, na ufikiaji wa mtandao | Kila mwito hutekelezwa kwa utambulisho upi, na je, uidhinishaji hurudiwa kwenye mpaka wa tool? |
| **Uchakataji** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, shughuli za faili, na deserializers | Data iliyotengenezwa na model inakuwa sintaksia ya interpreter nyingine wapi? |
| **Matokeo** | Majibu, Markdown/HTML iliyowasilishwa, links, image fetches, webhooks, barua pepe, faili, logs, ripoti, metrics, na mawasiliano ya agent rika | Ni njia gani inayoonekana inaweza kubeba siri au kuchochea ombi la pili? |

Usiyabane haya kuwa orodha ya integrations zinazotangazwa. Artifact yenye manufaa huonyesha kila chanzo na nafasi halisi ya muktadha kinakofikia, tools zinazopatikana wakati huo, credential inayotumiwa na kila tool, interpreter ya downstream, na kila njia ya egress. Tool ileile inaweza kuwa na athari ndogo kwa read token ya kila mtumiaji, na kuwa muhimu sana kwa credential ya pamoja ya msimamizi.<sup>[[2]](#references)</sup>

## Upelelezi

### Ramani ya kila njia ya uwasilishaji na uingizaji

Anza na sehemu ya uwasilishaji (web, mobile, API, barua pepe, jukwaa la chat, browser extension) na chunguza trafiki ya client-to-backend kupitia proxy. Kagua sehemu zilizofichwa na UI, vigezo vya search/autocomplete/filter, vitu vya hali ya mazungumzo, kazi za upload na indexing, majibu ya tool, na trafiki ya sub-agent. Client za mobile pekee huenda zikahitaji emulator na instrumentation ili kupita certificate pinning kabla schema halisi ya ombi haijaonekana.<sup>[[2]](#references)</sup>

Kisha chora ramani ya stack iliyo chini ya model: orchestration framework, prompt assembly, hifadhi za retrieval na memory, runtime (kwa mfano Python, container, au WASM), volumes zilizowekwa, huduma za host, APIs za ndani, ufikikaji wa cloud metadata, na mitandao jirani. Mipangilio chaguomsingi ya framework ni muhimu kwa sababu baadhi ya “tool calls” hutekelezwa kwa kutengeneza au kutathmini code; mpaka wa runtime/sandbox huamua kama matokeo hayo yanabaki ndani ya sandbox.<sup>[[2]](#references)</sup>

### Tambua routing kwa probes zisizo na madhara

Linganisha ombi lililo ndani ya upeo na maombi kadhaa yasiyohusiana huku ukihifadhi jibu kamili, status code, latency, na tabia ya streaming. Kukataliwa kwa namna thabiti kabla ya reasoning yoyote inayohusu kazi maalum kunaweza kuashiria gateway/classifier tofauti; kukataa kunakotegemea muktadha huashiria kuwa ombi limefika kwa model; jibu tupu au la kutoa tu taarifa zilizopo linaweza kuashiria keyword search au retrieval finyu. Chukulia haya kama dhana na uyathibitishe kwa kutuma tena probe ileile kupitia sehemu mbadala za API na njia za ingestion.<sup>[[2]](#references)</sup>

Upelelezi umekamilika pale tathmini inapoweza kutaja chanzo cha mapema zaidi kinachodhibitiwa na mshambuliaji na kubadilisha tabia ya agent **pamoja na** tools, identities, interpreters, na outputs zinazoweza kufikiwa kutoka kwenye chanzo hicho.<sup>[[2]](#references)</sup>

## Unyonyaji: vuka mpaka wa uaminifu

Test njia za kuingiza maudhui, si maneno ya prompt pekee. Anza na direct injection ili kubaini kinachozuiwa na mlango wa mbele unaoonekana, kisha rudia nia hiyo hiyo kupitia njia zisizoonekana sana hapa chini:<sup>[[2]](#references)</sup>

- **Maudhui yasiyo ya moja kwa moja:** kurasa, faili, barua pepe, tiketi, metadata, alt text, HTML comments, maandishi yasiyoonekana kwenye skrini, au herufi za zero-width. Tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) kwa mbinu za kuwasilisha payload.
- **Retrieval na memory:** weka maudhui yenye sumu yatakayorejeshwa baadaye au hali itakayopakiwa upya katika vipindi vijavyo. Rekodi kama kufuta chanzo asili huondoa tabia hiyo.
- **Matokeo ya tool na agent rika:** weka marker kwenye jibu la tool au ujumbe wa agent-kwa-agent ili kupima kama trafiki ya ndani inapita filters zinazotumika kwa ingizo la mtumiaji na matokeo ya mwisho pekee.
- **Supply chain:** kagua maelezo ya tool, plugins, servers zilizounganishwa, skills, models, na dependencies kama vyanzo vinavyoaminika vya maelekezo. Kwa tests maalum za MCP, tazama [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Uidhinishaji wa binadamu:** linganisha tool call halisi yenye muundo na maandishi ya idhini yaliyotengenezwa na model. Test kama ushawishi wa mshambuliaji unaweza kuondoa destination, scope, objects zinazoathiriwa, au athari zisizoweza kutenduliwa.

Tumia marker isiyo na madhara na ya kipekee kwanza. Hifadhi artifact ya chanzo, muktadha uliokusanywa ikiwa unaweza kuonekana, tool call iliyochaguliwa, data ya idhini, ombi/jibu la backend, na hali ya mwisho. Hii hutenganisha ushawishi na dai la kubuniwa kwamba kitendo kilifanyika.<sup>[[2]](#references)</sup>

### Maandishi yanayofanana na sera ndani ya tool-risk judge

Tool gate inayotegemea model inaweza kupokea maandishi yanayodhibitiwa na mshambuliaji ndani ya muktadha wa uainishaji ambao vinginevyo una manufaa. Kwa mfano, `AutoModeMiddleware` ya majaribio ya LangChain hutuma tool call inayopendekezwa, arguments zake, maelezo ya hiari ya tool, na hadi ujumbe 30 wa hivi karibuni kwa judge ya TypeSafe `is_risky`. Huzuia tools zilizosanidiwa pale uwezekano wa Noul unaorudishwa unapokuwa angalau `0.5`; tools ambazo hazijaorodheshwa haziainishwi na middleware hii.<sup>[[5]](#references)</sup> TypeSafe pia inaonya kuwa maandishi ya adui katika state yanaweza kuathiri uainishaji hata pale state inapokusudiwa kuwa data.<sup>[[6]](#references)</sup>

**Sera ya kughushi** ni tofauti na kudai tu kuwa ujumbe ni wa mfumo. Huongeza lebo mbadala au ufafanuzi wa hatari ndani ya state yenye kiwango cha chini cha uaminifu, na kujaribu kumshawishi judge atumie ufafanuzi huo badala ya vigezo vilivyowekwa na developer. Katika test ya Datadog, `profile_description` inayoweza kuhaririwa na mtumiaji ilinakiliwa kwenye tool arguments pamoja na `can_edit:false`. Maandishi yake yanayofanana na sera yalidai kuwa jaribio la kuandika lilikuwa na hatari ndogo kwa sababu ukaguzi tofauti wa ruhusa ungelikataa kabla ya mabadiliko yoyote. Katika majaribio 40, wastani wa alama ya `is_risky` ulishuka kutoka `0.893` hadi `0.290`, huku ulinganisho wa moja kwa moja wa kujifanya role ukiwa na wastani wa `0.905`. Kushuka kwa wastani chini ya `0.5` hakuthibitishi kuwa kila call moja moja ilipita gate, na jaribio **halikuonyesha** maandishi yasiyoidhinishwa yaliyokamilika.<sup>[[7]](#references)</sup>

Unapojaribu mpaka huu, tofautisha uamuzi wa classifier na matokeo halisi ya uidhinishaji wa tool. Kagua ni sehemu zipi zinazoweza kuhaririwa zinazofika kwa judge, linganisha kitendo kilekile kinachopendekezwa kikiwa na na bila maandishi yanayofanana na sera, na uthibitishe hali ya mwisho kwa njia huru. Ukaguzi tofauti wa ruhusa bado lazima utumie mamlaka ya mwombaji aliyeidhinishwa badala ya haki za service account ya connector.<sup>[[7]](#references)</sup> Tazama [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) kwa njia nyingine za kushindwa kwa classifier; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) inahusu mpaka tofauti wa routing na credentials.

### Kutenganisha muktadha wa subagent

Subagent isiyotumia fork ya Claude Agent SDK hupokea `AgentDefinition.prompt` yake, prompt ya delegation, na tools zinazopatikana kwake, lakini si system prompt au mazungumzo ya parent. Ikiwa `tools` haijawekwa kwenye definition yake, hurithi tools zinazopatikana kwa subagents; `CLAUDE.md` ya project bado inaweza kupakiwa. Hii hufanya kizuizi cha prompt cha parent pekee kuwa mpaka usioaminika pale child inapoweza kutumia tools zilezile za filesystem au execution.<sup>[[4]](#references)</sup>

Test mpaka huu kwa kulinganisha ombi la moja kwa moja ambalo parent hulikataa na kazi ileile iliyokabidhiwa kwa subagent mwenye jina maalum. NCC Group inaripoti kuwa uorodheshaji wa faili za mfumo wa uendeshaji uliokataliwa ulifanikiwa ulipowasilishwa upya kwa child kama “ramani ya mpangilio” isiyo na madhara.<sup>[[3]](#references)</sup>

Kagua tool calls halisi za child na orodha halisi ya tools anazoruhusiwa kutumia, si jibu la mwisho la parent pekee; thibitisha kama child alifikia faili ambazo parent asingefikia.<sup>[[4]](#references)</sup> Huu ni ushindwaji wa kurithisha guardrails, si uthibitisho wa [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) au kutoroka container.<sup>[[3]](#references)[[4]](#references)</sup>

## Utekelezaji: thibitisha athari halisi

Kuna njia mbili tofauti kutoka kwenye ushawishi hadi athari:<sup>[[2]](#references)</sup>

1. **Matumizi mabaya ya uwezo:** tool iliyoidhinishwa tayari hutekeleza lengo. Mifano ni kusoma rekodi ya tenant mmoja na kuiandika kwenye ripoti inayoonekana kwa mshambuliaji, kutuma barua pepe, kubadilisha rekodi, kufuta faili, au kuanzisha malipo. Hakuna hitilafu ya ziada ya software inayohitajika.
2. **Unyonyaji wa sinki ya downstream:** matokeo ya model yanayoelekezwa na mshambuliaji huwa sintaksia kwa component nyingine. Kagua database queries kwa [SQL injection](../pentesting-web/sql-injection/README.md) au [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers kwa [command injection](../pentesting-web/command-injection.md), URLs zilizochaguliwa kwa [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), shughuli za faili kwa directory traversal, template/code evaluators kwa RCE, na object parsers kwa [unsafe deserialization](../pentesting-web/deserialization/README.md).

Kwa kila uwezekano wa shambulio, thibitisha mnyororo huu:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Muunganisho wa read-only bado unaweza kutumiwa vibaya ikiwa sehemu yoyote ya baadaye inaweza kuchapisha ilichosoma. Jaribu majibu ya kawaida pamoja na njia zisizo dhahiri za egress, kama vile viungo vinavyodhibitiwa na mshambuliaji, upakuaji wa picha kiotomatiki, webhooks, kumbukumbu, ripoti, kaunta, arifa na ujumbe kwa mawakala wengine.<sup>[[2]](#references)</sup>

## Vitendo dhidi ya malengo

Baada ya kuthibitisha kitendo kimoja, tathmini wigo kamili wa athari badala ya kusimama kwenye athari ya kwanza inayoonekana:<sup>[[2]](#references)</sup>

- **Uchujaji wa data:** siri, rekodi za watumiaji, faili za ndani, data ya mazungumzo au maudhui ya prompt/context hutoka kupitia njia inayoweza kuonekana.
- **Kitendo kisichoidhinishwa:** wakala hutumia uwezo halali wa kuandika kutimiza lengo la mshambuliaji.
- **Kunyimwa huduma:** zana haribifu au shughuli za gharama kubwa zinazojirudia huathiri uadilifu au upatikanaji.
- **Uendelevu:** memory iliyochafuliwa, maudhui yaliyowekwa kwenye faharasa, hali inayoaminika au mabadiliko ya runtime huendelea baada ya session au chanzo kilichoyaanzisha kuondolewa.
- **Kuenea:** rika linaloaminika hutumia ujumbe au hali iliyoshirikiwa na wakala aliyeathiriwa na kurudia kitendo hicho kwa kutumia zana na credentials zake.

Ukali unapaswa kuamuliwa kwa kuzingatia data inayoweza kufikiwa, kiwango halisi cha ruhusa, uwezekano wa sink kutumiwa vibaya, egress, uendelevu na kuenea—si kwa jinsi maandishi ya model yanavyoshangaza.<sup>[[2]](#references)</sup>

## Vidhibiti vya kuthibitisha wakati wa tathmini

Vichujio vya prompt na system prompt bora vinaweza kuongeza gharama kwa mshambuliaji, lakini havipaswi kuchukuliwa kuwa mipaka ya uidhinishaji. Thibitisha vidhibiti vilivyo hapa chini kwa kuendesha tena mnyororo uleule kupitia ingizo la moja kwa moja, maudhui yasiyo ya moja kwa moja, memory, zana na mawakala rika:<sup>[[2]](#references)</sup>

- Tabaka la sera linalotenda kwa namna thabiti hukagua mtumiaji aliyeidhinishwa, tenant, object, action na destination kwenye **kila mwito wa zana**; model haiwezi kutoa au kubatilisha utambulisho wa mwitaji.
- Uwezo wa kusoma na kuandika hutumia credentials tofauti zenye ruhusa za chini kabisa na muda mfupi; zana zenye athari kubwa hutolewa kwa wakati unaohitajika tu na hazitekelezwi kiotomatiki kamwe kutokana na maudhui yaliyoingizwa.
- Egress ya mtandao na destinations za ndani huwekwa kwenye allowlist tofauti na URL zilizochaguliwa na model; ufikiaji wa runtime kwa endpoints za metadata, siri zilizowekwa kwenye mount na huduma jirani huzuiwa isipokuwa kama unahitajika.
- UI ya idhini hutengenezwa kutokana na ombi rasmi lenye muundo na huonyesha hoja halisi, utambulisho, destination, objects zinazoathiriwa na athari za ziada—si muhtasari huru wa model.
- Mafanikio huthibitishwa kutoka kwenye mfumo lengwa au mfumo rasmi wa kumbukumbu. Maelezo ya wakala, ombi la kuita zana au HTTP redirect si uthibitisho kwamba mabadiliko ya hali yaliyodaiwa yametokea.
- Maingizo ya memory na retrieval huhifadhi asili na lebo za uaminifu, yanaweza kubatilishwa na huidhinishwa upya yanapotumiwa kwa kitendo cha baadaye.
- Ujumbe kati ya mawakala huthibitishwa na kuidhinishwa kama maombi yasiyoaminika; sifa ya rika au agent card haihamishi moja kwa moja ruhusa za zana za mpokeaji.

Kwa agent cards za A2A, mtiririko wa kazi na maeneo yake ya mashambulizi, angalia [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 kwa Programu za Agentic za 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Mwongozo wa Hacker wa Kushambulia Mawakala wa AI](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Kwa Kweli Ni Vigumu Kiasi Gani Kutoa Wakala wa AI Kwenye Sandbox Yake?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents katika SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Msimbo chanzo wa middleware ya LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jaggedness ya model ya TypeSafe AI Jev: maudhui hasimu](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kama mwamuzi: Jinsi sera ghushi inavyoielekeza Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
