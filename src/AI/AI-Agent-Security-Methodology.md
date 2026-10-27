# Mbinu ya Usalama wa AI Agent

{{#include ../banners/hacktricks-training.md}}

Tathmini ya agent inapaswa kufuata **ingizo linalodhibitiwa na mshambuliaji hadi athari inayoweza kuonekana nje**. Jailbreaking, kubadilisha tabia, na kufichua system prompt kunathibitisha kuwa njia ya reasoning inaweza kuathiriwa, lakini finding yenye athari kubwa ni mnyororo unaofikia ufikiaji wa data, kitendo cha tool kisichoidhinishwa, downstream injection sink, persistence, au agent mwingine.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ni muhimu kwa kuweka lebo za maeneo yaliyokaguliwa (goal hijacking, matumizi mabaya ya tool, matumizi mabaya ya mamlaka, supply chain, code execution, memory poisoning, uaminifu kati ya agents, hitilafu zinazofuatana, uaminifu wa binadamu, na rogue agents). Tumia lebo hizo baada ya kuunda njia ya mashambulizi ya mwanzo hadi mwisho badala ya kuchukulia maandishi yasiyotarajiwa ya model kuwa mwisho wa test.<sup>[[1]](#references)[[2]](#references)</sup>

## Tengeneza ramani ya lengo

Rekodi vipengele hivi vitano kwa kila workflow ya agent kabla ya kuandika payloads:<sup>[[2]](#references)</sup>

| Kipengele | Vitu vya kuorodhesha | Swali la usalama |
|---|---|---|
| **Ingizo lisiloaminika** | Vigezo vya Chat/API, URLs, nyaraka, barua pepe, tiketi, miingizo ya kalenda, vipande vilivyorejeshwa, memory, matokeo ya tool, na ujumbe wa agent-mwenza | Mshambuliaji anaweza kuweka maudhui wapi ili baadaye yaingie kwenye muktadha wa model? |
| **Tools** | Majina na schemas za tools, madhara ya vitendo, utekelezaji wa kiotomatiki, tabia ya uthibitishaji, na tools zinazopakiwa kwa nguvu | Ni miito ipi inayosoma siri, kubadilisha state, kutuma ujumbe, kufuta data, kutekeleza code, au kuhamisha thamani? |
| **Mamlaka** | Uwakilishaji wa mtumiaji, service accounts, API tokens, muda wa uhai wa credential, upeo wa tenant/resource, na ufikiaji wa mtandao | Kila mwito hutekelezwa kwa utambulisho upi, na je, uidhinishaji hukaguliwa tena kwenye mpaka wa tool? |
| **Uchakataji** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, shughuli za faili, na deserializers | Data inayozalishwa na model inakuwa syntax ya interpreter nyingine wapi? |
| **Matokeo** | Majibu, Markdown/HTML iliyowasilishwa, links, image fetches, webhooks, barua pepe, faili, logs, reports, metrics, na mawasiliano ya agent-mwenza | Ni njia gani inayoonekana inaweza kubeba siri au kuanzisha ombi la pili? |

Usibane haya yote kuwa orodha ya integrations zinazotangazwa. Kitu muhimu cha kuandaa huunganisha kila chanzo na nafasi halisi ya muktadha kinayofikia, tools zinazopatikana wakati huo, credential inayotumiwa na kila tool, downstream interpreter, na kila njia ya egress. Tool ileile inaweza kuwa na athari ndogo ikiwa na read token ya kila mtumiaji, lakini ikawa muhimu sana ikiwa na credential ya pamoja ya msimamizi.<sup>[[2]](#references)</sup>

## Upelelezi

### Ramani ya kila njia ya uwasilishaji na uingizaji

Anza na sehemu ya uwasilishaji (web, mobile, API, barua pepe, jukwaa la chat, browser extension) na ukague trafiki kati ya client na backend kupitia proxy. Kagua sehemu zilizofichwa na UI, vigezo vya utafutaji/autocomplete/filter, objects za hali ya mazungumzo, kazi za kupakia na ku-index, majibu ya tools, na trafiki ya sub-agent. Clients za mobile pekee zinaweza kuhitaji emulator na instrumentation ili kukwepa certificate pinning kabla schema halisi ya ombi haijaonekana.<sup>[[2]](#references)</sup>

Kisha ramani ya stack iliyo chini ya model: orchestration framework, ukusanyaji wa prompt, hifadhi za retrieval na memory, runtime (kwa mfano Python, container, au WASM), mounted volumes, huduma za host, internal APIs, ufikikaji wa cloud metadata, na mitandao jirani. Defaults za framework ni muhimu kwa sababu baadhi ya “tool calls” hutekelezwa kwa kuzalisha au kutathmini code; mpaka wa runtime/sandbox huamua kama matokeo hayo yatabaki yamezuiliwa.<sup>[[2]](#references)</sup>

### Tambua uelekezaji kwa probes zisizoleta madhara

Linganisha ombi lililo ndani ya upeo na maombi kadhaa yasiyohusiana huku ukihifadhi response nzima, status code, latency, na tabia ya streaming. Kukataliwa kunakotokea kwa uthabiti kabla ya reasoning yoyote mahususi ya kazi kunaweza kuashiria gateway/classifier tofauti; kukataa kunakotegemea muktadha huashiria kuwa ombi limefika kwa model; jibu tupu au linalotoa tu taarifa zilizopo linaweza kuashiria keyword search au retrieval finyu. Chukulia haya kama dhana na yathibitishe kwa kurudia probe ileile kupitia sehemu mbadala za API na njia za uingizaji.<sup>[[2]](#references)</sup>

Upelelezi umekamilika pale tathmini inapoweza kutaja chanzo cha kwanza kabisa kinachodhibitiwa na mshambuliaji kinachobadilisha tabia ya agent **na** tools, identities, interpreters, na matokeo yanayoweza kufikiwa kutoka kwenye chanzo hicho.<sup>[[2]](#references)</sup>

## Exploitation: vuka mpaka wa uaminifu

Jaribu channels, si maneno ya prompt pekee. Anza kwa direct injection ili kubaini kile ambacho sehemu ya mbele inayoonekana inazuia, kisha rudia nia ileile kupitia njia zisizoonekana sana hapa chini:<sup>[[2]](#references)</sup>

- **Maudhui yasiyo ya moja kwa moja:** kurasa, faili, barua pepe, tiketi, metadata, alt text, maoni ya HTML, maandishi yaliyo nje ya skrini, au zero-width characters. Tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) kwa mbinu za kuwasilisha payload.
- **Retrieval na memory:** weka maudhui yenye sumu ambayo yatarejeshwa baadaye au state itakayopakiwa tena katika sessions zijazo. Rekodi kama kufuta chanzo asili kunasitisha tabia hiyo.
- **Matokeo ya tool na agents wenza:** weka marker kwenye jibu la tool au ujumbe kati ya agents ili kupima kama trafiki ya ndani inapita filters zinazotumika kwa ingizo la mtumiaji na matokeo ya mwisho pekee.
- **Supply chain:** kagua maelezo ya tools, plugins, servers zilizounganishwa, skills, models, na dependencies kama vyanzo vya maelekezo vinavyoaminika. Kwa tests mahususi za MCP, tazama [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Idhini ya binadamu:** linganisha tool call halisi yenye muundo maalum na maandishi ya idhini yaliyotengenezwa na model. Jaribu kama ushawishi wa mshambuliaji unaweza kuondoa destination, scope, objects zilizoathiriwa, au madhara yasiyoweza kutenduliwa.

Tumia marker ya kipekee isiyo na madhara kwanza. Hifadhi artifact ya chanzo, muktadha uliokusanywa kama unaweza kuonekana, tool call iliyochaguliwa, data ya idhini, ombi/jibu la backend, na hali ya mwisho. Hii hutenganisha ushawishi na madai ya kubuni kwamba kitendo kilifanyika.<sup>[[2]](#references)</sup>

### Maandishi yanayofanana na sera ndani ya tool-risk judge

Tool gate inayotegemea model inaweza kupokea maandishi yanayodhibitiwa na mshambuliaji ndani ya muktadha mwingine wa uainishaji wenye manufaa. Kwa mfano, `AutoModeMiddleware` ya majaribio ya LangChain hutuma tool call inayopendekezwa, arguments zake, maelezo ya tool ya hiari, na hadi ujumbe 30 wa hivi karibuni kwa judge wa TypeSafe `is_risky`. Huzuia tools zilizosanidiwa wakati uwezekano wa Noul unaorudishwa ni angalau `0.5`; tools zisizoorodheshwa haziainishwi na middleware hii.<sup>[[5]](#references)</sup> TypeSafe pia inaonya kuwa maandishi ya adui kwenye state yanaweza kuathiri uainishaji hata pale state inakusudiwa kuwa data.<sup>[[6]](#references)</sup>

**Sera bandia** ni tofauti na kudai tu kuwa ujumbe wa system. Huweka lebo mbadala au ufafanuzi wa hatari ndani ya state yenye uaminifu mdogo na kuishawishi judge itumie ufafanuzi huo badala ya vigezo vilivyowekwa na developer. Katika test ya Datadog, `profile_description` inayoweza kuhaririwa na mtumiaji ilinakiliwa kwenye tool arguments pamoja na `can_edit:false`. Maandishi hayo yanayofanana na sera yalidai kuwa jaribio la kuandika lilikuwa na hatari ndogo kwa sababu ukaguzi tofauti wa ruhusa ungelikataa kabla ya mabadiliko yoyote. Katika runs 40, wastani wa alama ya `is_risky` ulishuka kutoka `0.893` hadi `0.290`, huku ulinganisho wa moja kwa moja wa kujifanya kuwa na role ukifikia wastani wa `0.905`. Kushuka kwa wastani chini ya `0.5` hakuthibitishi kuwa kila mwito mmoja mmoja ulipita gate, na jaribio **halikuonyesha** uandishi usioidhinishwa uliokamilika.<sup>[[7]](#references)</sup>

Unapojaribu mpaka huu, tofautisha uamuzi wa classifier na matokeo halisi ya uidhinishaji wa tool. Kagua ni sehemu zipi zinazoweza kuhaririwa zinafika kwa judge, linganisha kitendo kilekile kinachopendekezwa kikiwa na maandishi yanayofanana na sera na bila hayo, kisha hakikisha hali ya mwisho kwa njia huru. Ukaguzi tofauti wa ruhusa lazima bado utumie mamlaka ya mwombaji aliyeidhinishwa badala ya haki za service account ya connector.<sup>[[7]](#references)</sup> Tazama [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) kwa aina nyingine za hitilafu za classifier; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) inahusu mpaka tofauti wa uelekezaji na credential.

### Kutenganisha muktadha wa subagent

Subagent isiyotumia fork ya Claude Agent SDK hupokea `AgentDefinition.prompt` yake, prompt ya delegation, na tools zinazopatikana kwake, lakini haipati system prompt au mazungumzo ya parent. Ikiwa `tools` haijawekwa kwenye definition yake, hurithi tools zinazopatikana kwa subagents; `CLAUDE.md` ya project bado inaweza kupakiwa. Kwa hivyo, kizuizi cha prompt cha parent pekee si mpaka wa kuaminika pale child inapoweza kutumia tools zilezile za filesystem au execution.<sup>[[4]](#references)</sup>

Jaribu mpaka huu kwa kulinganisha ombi la moja kwa moja ambalo parent inakataa na kazi hiyohiyo ikikabidhiwa kwa subagent mwenye jina. NCC Group inaripoti kuwa uorodheshaji wa faili za operating system uliokataliwa ulifanikiwa ulipowasilishwa kwa child kama “ramani ya mpangilio” isiyo na madhara.<sup>[[3]](#references)</sup>

Kagua tool calls halisi za child na orodha yake inayotumika ya tools zinazoruhusiwa, si jibu la mwisho la parent pekee; thibitisha kama child ilifikia faili ambazo parent isingefikia.<sup>[[4]](#references)</sup> Hili ni hitilafu ya kurithisha guardrail, si uthibitisho wa kukwepa [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) au container.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobile GUI agents: maelekezo ya skrini na kubadilishwa kwa kitendo

Agent ya GUI ya simu inaweza kutuma kila screenshot kwa cloud model kabla ya kuchagua kitendo kinachofuata cha kuvuka apps. Ili kujaribu **indirect visual injection**, weka maandishi yanayodhibitiwa na mshambuliaji kwenye SMS, barua pepe, au ukurasa ambao agent itakagua wakati wa kazi iliyoidhinishwa. Linganisha prompt ya kazi ya moja kwa moja na maelekezo yaleyale yanayoonekana kwenye screenshot pekee, kisha kagua kitendo kinachofuata na uamuzi wowote kuhusu operesheni hatari sana. Katika assistant iliyotathminiwa, `checkPrompt` ya client ilikagua maandishi ya kazi ya moja kwa moja lakini haikutumia uchujaji sawa kwa maudhui ya screenshot. Hii ni aina ya mobile, cross-app ya [agentic-browser screenshot injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), si njia ya kukwepa uthibitishaji wa Android component.<sup>[[9]](#references)</sup>

Jaribio la mfano la side-effect hutumia form inayodhibitiwa na mshambuliaji inayomwomba agent ijaze sehemu nyeti, kisha kuomba binadamu abonyeze “upload,” huku ukurasa ukituma sehemu hizo mara tu zinapobadilika. Kukabidhi hatua kwa binadamu hakuwezi kulinda data ambayo code ya ukurasa tayari imetuma; thibitisha utumaji halisi badala ya kuchukulia maelezo ya agent kuwa uthibitisho. Chanzo kinaeleza hili kama muundo unaowezekana, si udukuzi uliothibitishwa wa kila assistant.<sup>[[9]](#references)</sup>

**GUI TOCTOU / kubadilishwa kwa kitendo** ni aina tofauti ya hitilafu: agent hupanga ingizo kutokana na skrini iliyoonekana kwenye `t0`, lakini UI iliyo mbele hubadilika kabla ingizo halijaingizwa kwenye `t1`.<sup>[[8]](#references)</sup> Screenshot ya baadaye kwenye `t2` haiwezi kutengua kitendo ambacho tayari kimefanyika.<sup>[[9]](#references)</sup> Katika test ya Android iliyoidhinishwa, workflow inayoweza kutumiwa tena ni:<sup>[[8]](#references)</sup>

1. Tambua coordinates za control lengwa kwenye skrini, kisha uonyeshe control isiyo na madhara katika eneo hilo hilo kwenye app inayodhibitiwa.
2. Iache app hiyo ionekane hadi agent iione, kisha anzisha mabadiliko ya kawaida ya foreground wakati wa pengo kati ya uchunguzi na kitendo.
3. Kagua kama tap iliyopangwa inagusa control ya app mpya na uthibitishe hali inayotokana nayo kwenye app lengwa, badala ya kutegemea maelezo ya agent.

Utafiti wa awali wa kubadilisha kitendo unaonyesha hili kwa app isiyo na ruhusa hatari; pia unaeleza jinsi ya kurudia mabadiliko hayo kupitia recovery loop ya kazi ya agent kwa mtiririko wa hatua nyingi.<sup>[[8]](#references)</sup>

**Usidhani** kuwa primitive hii itafanya kazi vilevile kwa kila assistant. Katika tathmini ya Doubao, `OpClickUI` iliruka clicks ikiwa Activity ya kiwango cha juu ilibadilika na ililinganisha screenshots pale `OpOpenApp` ilipotokea ndani ya hatua tatu zilizotangulia. Kwa hiyo, taps za mara moja, long presses, na double taps hazikumpa mshambuliaji uwezo wa kutegemewa wa kudhibiti muda. `OpTypeText`, `OpSwipeUI`, na `OpScrollWheelAction` hazikuwa na ulinzi sawa, lakini ripoti ilitathmini athari zake za kiutendaji kuwa ndogo zaidi.<sup>[[9]](#references)</sup>

## Execution: thibitisha athari halisi

Kuna njia mbili tofauti kutoka kwenye ushawishi hadi athari:<sup>[[2]](#references)</sup>

1. **Matumizi mabaya ya uwezo:** tool iliyoidhinishwa tayari hutekeleza lengo. Mifano ni kusoma rekodi ya tenant moja na kuiandika kwenye ripoti inayoonekana kwa mshambuliaji, kutuma barua pepe, kubadilisha rekodi, kufuta faili, au kuanzisha malipo. Hakuna hitilafu ya pili ya software inayohitajika.
2. **Unyonyaji wa downstream sink:** matokeo ya model yanayoelekezwa na mshambuliaji yanakuwa syntax kwa component nyingine. Kagua database queries kwa [SQL injection](../pentesting-web/sql-injection/README.md) au [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers kwa [command injection](../pentesting-web/command-injection.md), URLs zilizochaguliwa kwa [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), shughuli za faili kwa traversal, template/code evaluators kwa RCE, na object parsers kwa [unsafe deserialization](../pentesting-web/deserialization/README.md).

Kwa kila uwezekano, thibitisha mnyororo huu:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Uunganishaji wa read-only bado unaweza kutumiwa vibaya ikiwa sehemu yoyote ya baadaye inaweza kuchapisha kile ulichosoma. Jaribu majibu ya kawaida pamoja na njia zisizo dhahiri za kutoa data, kama vile viungo vinavyodhibitiwa na mshambuliaji, upataji wa picha kiotomatiki, webhooks, logs, ripoti, vihesabio, arifa na ujumbe kwa agents wengine.<sup>[[2]](#references)</sup>

## Vitendo vinavyolenga malengo

Baada ya kuthibitisha kitendo kimoja, tathmini wigo mzima wa athari badala ya kusimama kwenye athari ya kwanza inayoonekana:<sup>[[2]](#references)</sup>

- **Exfiltration:** siri, rekodi za watumiaji, faili za ndani, data ya mazungumzo au maudhui ya prompt/context hutoka kupitia njia inayoweza kuonekana.
- **Unauthorized action:** agent hutumia uwezo halali wa kuandika kutimiza lengo la mshambuliaji.
- **Denial of service:** tools haribifu au shughuli ghali zinazojirudia huathiri uadilifu au upatikanaji.
- **Persistence:** memory iliyochafuliwa, maudhui yaliyowekwa kwenye index, hali inayoaminika au mabadiliko ya runtime hubaki hata baada ya session au chanzo kilichosababisha kuondolewa.
- **Propagation:** peer inayoaminika hutumia ujumbe au hali iliyoshirikiwa kutoka kwa agent iliyoathiriwa na kurudia kitendo kwa kutumia tools na credentials zake yenyewe.

Ukali unapaswa kutegemea data inayoweza kufikiwa, kiwango halisi cha ruhusa, uwezekano wa sink kutumiwa vibaya, egress, persistence na propagation—si jinsi maandishi ya model yanavyoshangaza.<sup>[[2]](#references)</sup>

## Controls za kuthibitisha wakati wa tathmini

Prompt filters na system prompt iliyo bora zaidi zinaweza kuongeza gharama kwa mshambuliaji, lakini hazipaswi kuchukuliwa kuwa mipaka ya idhini. Thibitisha controls zilizo hapa chini kwa kutekeleza tena chain ileile kupitia direct input, maudhui yasiyo ya moja kwa moja, memory, tools na peer agents:<sup>[[2]](#references)</sup>

- Safu ya deterministic policy hukagua mtumiaji aliye-authenticate, tenant, object, action na destination kwenye **kila mwito wa tool**; model haiwezi kutoa au kubatilisha utambulisho wa mpigaji.
- Uwezo wa kusoma na kuandika hutumia credentials tofauti zenye ruhusa za kiwango cha chini na muda mfupi; tools zenye athari kubwa hutolewa kwa wakati unaohitajika tu na haziendeshwi kiotomatiki kamwe kutokana na maudhui yaliyoingizwa.
- Egress ya mtandao na destinations za ndani huwekwa kwenye allowlist tofauti na URLs zilizochaguliwa na model; ufikiaji wa runtime kwa metadata endpoints, secrets zilizowekwa na services jirani huzuiwa isipokuwa unahitajika.
- Approval UI hutengenezwa kutokana na ombi sanifu la msingi na huonyesha arguments, utambulisho, destination, objects zinazoathiriwa na athari za pembeni zilizo sahihi—si muhtasari huru wa model.
- Mafanikio huthibitishwa kutoka kwenye mfumo lengwa au mfumo rasmi wa rekodi. Maelezo ya agent, ombi la mwito wa tool au HTTP redirect si uthibitisho wa mabadiliko ya hali yanayodaiwa.
- Maingizo ya memory na retrieval huhifadhi provenance na trust labels, yanaweza kubatilishwa, na huidhinishwa upya yanapotumiwa kwa kitendo cha baadaye.
- Ujumbe baina ya agents huthibitishwa utambulisho na kuidhinishwa kama maombi yasiyoaminika; sifa ya peer au agent card yake haitoi moja kwa moja ruhusa ya kutumia tools za mpokeaji.

Kwa agent cards za A2A, mtiririko wa tasks na eneo lake la mashambulizi, angalia [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 kwa Agentic Applications za 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Mwongozo wa Hacker wa Kushambulia AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Kwa Kweli, Ni Vigumu Kiasi Gani Kutoa AI Agent Kwenye Sandbox Yake?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents katika SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Chanzo cha middleware ya LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev model jaggedness: maudhui hasimu](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kama mwamuzi: Jinsi sera ghushi inavyoelekeza Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Udanganyifu Bila Ruhusa: Je, Tunaweza Kuamini GUI Agents Zinazoendeshwa na Large Multimodal Models?](https://arxiv.org/html/2601.12349v1)
- [9] [Wakati AI Assistant Inakuwa Sehemu ya Msururu wa Mashambulizi wa Hacker | Uchambuzi wa Usalama wa Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
