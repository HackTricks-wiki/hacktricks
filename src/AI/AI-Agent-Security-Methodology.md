# Mbinu ya Usalama wa AI Agent

{{#include ../banners/hacktricks-training.md}}

Tathmini ya agent inapaswa kufuata **ingizo linalodhibitiwa na mshambuliaji hadi athari inayoweza kuonekana kwa nje**. Jailbreaking, mabadiliko ya herufi na kufichua system prompt vinathibitisha kuwa njia ya reasoning inaweza kuathiriwa, lakini finding yenye athari kubwa ni mnyororo unaofikia ufikiaji wa data, kitendo cha tool kisichoidhinishwa, downstream injection sink, persistence, au agent mwingine.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ni muhimu kwa kuweka lebo za coverage (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, na rogue agents). Tumia lebo hizo baada ya kuunda njia ya mashambulizi ya mwanzo hadi mwisho, badala ya kuchukulia maandishi yasiyotarajiwa ya model kama mwisho wa test.<sup>[[1]](#references)[[2]](#references)</sup>

## Tengeneza ramani ya target

Rekodi vipengele hivi vitano kwa kila workflow ya agent kabla ya kuandika payloads:<sup>[[2]](#references)</sup>

| Kipengele | Vya kuorodhesha | Swali la usalama |
|---|---|---|
| **Ingizo lisiloaminika** | Vigezo vya Chat/API, URL, nyaraka, email, tickets, maingizo ya kalenda, vipande vilivyorejeshwa, memory, matokeo ya tool, na ujumbe wa agent rika | Mshambuliaji anaweza kuweka wapi maudhui ambayo baadaye yataingia kwenye muktadha wa model? |
| **Tools** | Majina na schemas za tools, side effects, auto-execution, tabia ya uthibitishaji, na tools zinazopakiwa dynamically | Ni miito ipi husoma secrets, huandika state, hutuma ujumbe, hufuta data, huendesha code, au huhamisha thamani? |
| **Mamlaka** | Delegation ya mtumiaji, service accounts, API tokens, muda wa uhalali wa credentials, scope ya tenant/resource, na ufikiaji wa mtandao | Kila mwito huendeshwa kwa utambulisho upi, na je, authorization hurudiwa kwenye mpaka wa tool? |
| **Uchakataji** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, file operations, na deserializers | Data iliyozalishwa na model inakuwa syntax ya interpreter nyingine wapi? |
| **Matokeo** | Majibu, Markdown/HTML iliyowasilishwa, links, image fetches, webhooks, email, files, logs, reports, metrics, na mawasiliano ya agent rika | Ni njia gani inayoonekana inaweza kubeba secret au kuanzisha ombi la pili? |

Usibane haya kuwa orodha ya integrations zinazotangazwa. Artifact yenye manufaa huunganisha kila chanzo na sehemu halisi ya muktadha kinayofikia, tools zinazopatikana hapo, credential inayotumiwa na kila tool, interpreter ya downstream, na kila njia ya egress. Tool ileile inaweza kuwa na athari ndogo ikiwa na token ya kusoma ya kila mtumiaji, na kuwa muhimu sana ikiwa na credential ya pamoja ya administrator.<sup>[[2]](#references)</sup>

## Reconnaissance

### Ramani ya kila njia ya uwasilishaji na uingizaji

Anza na sehemu za uwasilishaji (web, mobile, API, email, jukwaa la chat, browser extension) na uweke proxy kwenye traffic ya client-to-backend. Kagua fields zilizofichwa na UI, vigezo vya search/autocomplete/filter, objects za conversation-state, kazi za upload na indexing, majibu ya tools, na traffic ya sub-agent. Clients za mobile pekee zinaweza kuhitaji emulator na instrumentation ili kupita certificate pinning kabla schema halisi ya ombi haijaonekana.<sup>[[2]](#references)</sup>

Kisha ramani ya stack iliyo chini ya model: orchestration framework, prompt assembly, retrieval na memory stores, runtime (kwa mfano Python, container, au WASM), mounted volumes, huduma za host, internal APIs, ufikikaji wa cloud metadata, na mitandao jirani. Defaults za framework ni muhimu kwa sababu baadhi ya “tool calls” hutekelezwa kwa kutengeneza au kutathmini code; mpaka wa runtime/sandbox huamua kama matokeo hayo yatazuiliwa ndani.<sup>[[2]](#references)</sup>

### Tambua routing kwa probes zisizoleta madhara

Linganisha ombi lililo ndani ya scope na maombi kadhaa yasiyohusiana huku ukihifadhi jibu lote, status code, latency, na tabia ya streaming. Kukataliwa kwa uthabiti kabla ya reasoning yoyote mahususi ya task kunaweza kuashiria gateway/classifier tofauti; kukataa kulikozingatia muktadha kunaashiria kuwa ombi limefika kwa model; jibu tupu au la kutoa yaliyomo pekee linaweza kuashiria keyword search au retrieval finyu. Yachukulie haya kama hypotheses na uyathibitishe kwa kutuma probe ileile kupitia fields na njia mbadala za uingizaji za API.<sup>[[2]](#references)</sup>

Recon imekamilika pale tathmini inapoweza kutaja chanzo cha mapema zaidi kinachodhibitiwa na mshambuliaji kinachobadilisha tabia ya agent **na** tools, identities, interpreters, na matokeo yanayofikiwa kutoka kwenye chanzo hicho.<sup>[[2]](#references)</sup>

## Exploitation: vuka mpaka wa uaminifu

Test channels, si namna ya kuandika prompt pekee. Anza na direct injection ili kubaini kile ambacho mlango wa mbele unaoonekana huzuia, kisha rudia nia sawia kupitia njia zisizoonekana sana hapa chini:<sup>[[2]](#references)</sup>

- **Maudhui yasiyo ya moja kwa moja:** kurasa, files, email, tickets, metadata, alt text, HTML comments, maandishi yasiyoonekana kwenye skrini, au zero-width characters. Tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) kwa mbinu za kuwasilisha payload.
- **Retrieval na memory:** weka sumu kwenye maudhui yatakayorejeshwa baadaye au state itakayopakiwa tena katika sessions za baadaye. Rekodi kama kufuta chanzo asili huondoa tabia hiyo.
- **Matokeo ya tool na agents rika:** weka marker kwenye jibu la tool au ujumbe wa agent-kwa-agent ili kupima kama traffic ya ndani hupita filters zinazotumika kwenye ingizo la mtumiaji na matokeo ya mwisho pekee.
- **Supply chain:** kagua tool descriptors, plugins, servers zilizounganishwa, skills, models, na dependencies kama vyanzo vya maelekezo vinavyoaminika. Kwa tests mahususi za MCP, tazama [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Uidhinishaji wa binadamu:** linganisha tool call halisi yenye muundo na maandishi ya uidhinishaji yaliyotengenezwa na model. Test kama ushawishi wa mshambuliaji unaweza kuondoa destination, scope, objects zilizoathiriwa, au side effects zisizoweza kutenduliwa.

Tumia marker ya kipekee isiyo na madhara kwanza. Hifadhi source artifact, muktadha uliokusanywa ikiwa unaweza kuonekana, tool call iliyochaguliwa, data ya uidhinishaji, backend request/response, na hali ya mwisho. Hii hutenganisha ushawishi na dai la kubuniwa kwamba kitendo kilifanyika.<sup>[[2]](#references)</sup>

### Maandishi yanayofanana na sera ndani ya tool-risk judge

Tool gate inayotegemea model inaweza kupokea maandishi yanayodhibitiwa na mshambuliaji ndani ya muktadha mwingine wenye manufaa wa classification. Kwa mfano, `AutoModeMiddleware` ya majaribio ya LangChain hutuma tool call inayopendekezwa, arguments zake, tool description ya hiari, na hadi jumbe 30 za hivi karibuni kwa judge wa TypeSafe `is_risky`. Huzuia tools zilizosanidiwa pale uwezekano wa Noul uliorejeshwa unapokuwa angalau `0.5`; tools ambazo hazijaorodheshwa hazifanywi classification na middleware hii.<sup>[[5]](#references)</sup> TypeSafe pia inaonya kwamba maandishi ya adversarial kwenye state yanaweza kuathiri classification hata state inapokusudiwa kuwa data.<sup>[[6]](#references)</sup>

**Sera bandia** ni tofauti na kudai tu kuwa ujumbe wa system. Huweka lebo mbadala au ufafanuzi wa risk ndani ya state yenye kiwango cha chini cha uaminifu, na kuhimiza judge kutumia ufafanuzi huo badala ya vigezo vilivyowekwa na developer. Katika test ya Datadog, `profile_description` inayoweza kuhaririwa na mtumiaji ilinakiliwa kwenye tool arguments pamoja na `can_edit:false`. Maandishi yake yanayofanana na sera yalidai kuwa jaribio la kuandika lilikuwa na risk ndogo kwa sababu ukaguzi tofauti wa ruhusa ungelikataa kabla ya mabadiliko yoyote. Katika runs 40, wastani wa alama ya `is_risky` ulipungua kutoka `0.893` hadi `0.290`, huku ulinganisho wa moja kwa moja wa kuigiza role ukiwa na wastani wa `0.905`. Wastani kushuka chini ya `0.5` hakuthibitishi kuwa kila call moja ilipita gate, na jaribio **halikuonyesha** write isiyoidhinishwa iliyokamilika.<sup>[[7]](#references)</sup>

Unapojaribu mpaka huu, tofautisha uamuzi wa classifier na matokeo halisi ya authorization ya tool. Kagua ni fields zipi zinazoweza kuhaririwa zinazofika kwa judge, linganisha action ileile inayopendekezwa ikiwa na bila maandishi yanayofanana na sera, na uthibitishe hali ya mwisho kivyake. Ukaguzi tofauti wa ruhusa lazima bado utumie mamlaka ya requester aliyeauthenticated badala ya haki za service-account ya connector.<sup>[[7]](#references)</sup> Tazama [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) kwa aina nyingine za kushindwa kwa classifier; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) zinahusu mpaka tofauti wa routing na credentials.

### Kutenga muktadha wa subagent

Subagent isiyo-fork ya Claude Agent SDK hupokea `AgentDefinition.prompt` yake yenyewe, prompt ya delegation, na tools zinazopatikana kwake, lakini si system prompt au conversation ya parent. Ikiwa `tools` imeachwa kwenye definition yake, hurithi tools zinazopatikana kwa subagents; project `CLAUDE.md` bado inaweza kupakiwa. Hii inamaanisha kuwa kizuizi cha prompt cha parent pekee si mpaka wa kuaminika pale mtoto anapoweza kutumia tools zilezile za filesystem au execution.<sup>[[4]](#references)</sup>

Test mpaka huu kwa kulinganisha ombi la moja kwa moja ambalo parent hukataa na task ileile iliyokabidhiwa kwa subagent yenye jina. NCC Group inaripoti kuwa enumeration ya faili za operating system iliyokataliwa ilifaulu ilipowasilishwa upya kwa mtoto kama “ramani ya mpangilio” isiyo na madhara.<sup>[[3]](#references)</sup>

Kagua tool calls halisi za mtoto na orodha yake ya tools inayotumika, si jibu la mwisho la parent pekee; thibitisha kama mtoto alifikia files ambazo parent hangefikia.<sup>[[4]](#references)</sup> Huku ni kushindwa kwa urithishaji wa guardrail, si uthibitisho wa [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) au container escape.<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: thibitisha athari halisi

Kuna njia mbili tofauti kutoka ushawishi hadi athari:<sup>[[2]](#references)</sup>

1. **Matumizi mabaya ya uwezo:** tool iliyoidhinishwa tayari hutekeleza lengo. Mifano ni kusoma rekodi ya tenant mmoja na kuiandika kwenye ripoti inayoonekana kwa mshambuliaji, kutuma email, kubadilisha rekodi, kufuta faili, au kuanzisha malipo. Hakuna hitilafu ya pili ya software inayohitajika.
2. **Unyonyaji wa downstream sink:** matokeo ya model yaliyoelekezwa na mshambuliaji yanakuwa syntax ya component nyingine. Kagua database queries kwa [SQL injection](../pentesting-web/sql-injection/README.md) au [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers kwa [command injection](../pentesting-web/command-injection.md), URL zilizochaguliwa kwa [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), file operations kwa traversal, template/code evaluators kwa RCE, na object parsers kwa [unsafe deserialization](../pentesting-web/deserialization/README.md).

Kwa kila uwezekano, thibitisha mnyororo huu:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Muunganisho wa read-only bado unaweza kutumiwa vibaya ikiwa kipengele chochote cha baadaye kinaweza kuchapisha kilichosomwa. Jaribu majibu ya kawaida pamoja na njia zisizo dhahiri za egress, kama vile viungo vinavyodhibitiwa na mshambuliaji, upakuaji wa picha kiotomatiki, webhooks, kumbukumbu, ripoti, counters, arifa na ujumbe kwa agents wengine.<sup>[[2]](#references)</sup>

## Vitendo vinavyolenga malengo

Baada ya kuthibitisha kitendo kimoja, tathmini wigo mzima wa athari badala ya kusimama kwenye athari ya kwanza inayoonekana:<sup>[[2]](#references)</sup>

- **Utoaji wa data:** siri, rekodi za watumiaji, faili za ndani, data ya mazungumzo au maudhui ya prompt/context hutoka kupitia njia inayoweza kuonekana.
- **Kitendo kisichoidhinishwa:** agent hutumia uwezo halali wa kuandika ili kutimiza lengo la mshambuliaji.
- **Kukatizwa kwa huduma:** zana haribifu au shughuli ghali zinazojirudia huathiri uadilifu au upatikanaji.
- **Uendelevu:** memory iliyochafuliwa, maudhui yaliyoingizwa kwenye faharasa, hali inayoaminika au mabadiliko ya runtime hudumu baada ya session au chanzo kilichosababisha kuondolewa.
- **Kuenea:** peer anayeaminika hutumia ujumbe au hali iliyoshirikiwa ya agent iliyoathiriwa, kisha kurudia kitendo hicho kwa kutumia zana na credentials zake mwenyewe.

Ukali unapaswa kutegemea data inayoweza kufikiwa, kiwango halisi cha ruhusa, uwezekano wa sink kutumiwa vibaya, egress, uendelevu na kuenea—si jinsi maandishi ya model yanavyoshangaza.<sup>[[2]](#references)</sup>

## Vidhibiti vya kuthibitisha wakati wa tathmini

Vichujio vya prompt na system prompt bora vinaweza kuongeza gharama kwa mshambuliaji, lakini havipaswi kuchukuliwa kuwa mipaka ya idhini. Thibitisha vidhibiti vilivyo hapa chini kwa kutekeleza tena chain ileile kupitia ingizo la moja kwa moja, maudhui yasiyo ya moja kwa moja, memory, tools na peer agents:<sup>[[2]](#references)</sup>

- Safu ya deterministic ya policy hukagua mtumiaji aliyeidhinishwa, tenant, object, action na destination kwenye **kila mwito wa tool**; model haiwezi kutoa au kubatilisha utambulisho wa mpigaji.
- Uwezo wa kusoma na kuandika hutumia credentials tofauti zenye ruhusa za chini kabisa na muda mfupi wa uhalali; tools zenye athari kubwa hutolewa inapohitajika tu na hazitekelezi kiotomatiki maudhui yaliyoingizwa.
- Egress ya mtandao na destinations za ndani huwekewa allowlist bila kutegemea URLs zilizochaguliwa na model; ufikiaji wa runtime kwa endpoints za metadata, secrets zilizowekwa (mounted) na huduma zilizo jirani huzuiwa isipokuwa inapohitajika.
- UI ya idhini hutengenezwa kutokana na ombi sanifu la kimuundo na huonyesha arguments halisi, utambulisho, destination, objects zitakazoathiriwa na madhara ya ziada—si muhtasari huru wa model.
- Mafanikio huthibitishwa kutoka kwenye mfumo lengwa au mfumo rasmi wa rekodi. Maelezo ya agent, ombi la kuita tool au HTTP redirect si uthibitisho wa mabadiliko ya hali yanayodaiwa.
- Entries za memory na retrieval huhifadhi chanzo na lebo za uaminifu, zinaweza kubatilishwa, na huidhinishwa upya zinapotumika kwa kitendo cha baadaye.
- Ujumbe kati ya agents huthibitishwa na kuidhinishwa kama maombi yasiyoaminika; sifa ya peer au agent card yake haikabidhi moja kwa moja tools za mpokeaji.

## References

- [1] [OWASP Top 10 kwa Programu za Agentic za 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Mwongozo wa Hacker wa Kushambulia AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Kwa Kweli Ni Vigumu Kiasi Gani Kutoa AI Agent Kwenye Sandbox Yake?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents katika SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Chanzo cha middleware ya LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Ukwaru wa modeli ya TypeSafe AI Jev: maudhui ya kinzani](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev kama hakimu: Jinsi sera bandia inavyoelekeza Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
