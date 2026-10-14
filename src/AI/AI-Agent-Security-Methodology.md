# Mbinu ya Usalama wa AI Agent

{{#include ../banners/hacktricks-training.md}}

Tathmini ya agent inapaswa kufuatilia **ingizo linalodhibitiwa na mshambuliaji hadi athari inayoweza kuonekana nje**. Jailbreaking, mabadiliko ya herufi, na kufichua system prompt huthibitisha kuwa njia ya reasoning inaweza kushawishiwa, lakini finding yenye athari kubwa ni mnyororo unaoishia kwenye ufikiaji wa data, kitendo cha tool kisichoidhinishwa, sink ya downstream injection, persistence, au agent mwingine.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ni muhimu kwa kuweka lebo za maeneo yaliyofunikwa (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust, na rogue agents). Tumia lebo hizo baada ya kujenga njia ya shambulio ya mwanzo hadi mwisho badala ya kuchukulia maandishi yasiyotarajiwa kutoka kwa model kuwa mwisho wa jaribio.<sup>[[1]](#references)[[2]](#references)</sup>

## Tengeneza ramani ya lengo

Kabla ya kuandika payloads, andika vipengele hivi vitano kwa kila mtiririko wa kazi wa agent:<sup>[[2]](#references)</sup>

| Kipengele | Vitu vya kuorodhesha | Swali la usalama |
|---|---|---|
| **Ingizo lisiloaminika** | Vigezo vya Chat/API, URLs, hati, barua pepe, tiketi, maingizo ya kalenda, vipande vilivyorejeshwa, memory, matokeo ya tool, na ujumbe kutoka kwa agent rika | Mshambuliaji anaweza kuweka maudhui wapi ili baadaye yaingie kwenye muktadha wa model? |
| **Tools** | Majina na schemas za tool, athari za vitendo, utekelezaji wa kiotomatiki, tabia ya uthibitishaji, na tools zinazopakiwa kwa wakati wa matumizi | Ni miito ipi inayosoma siri, kuandika hali, kutuma ujumbe, kufuta data, kutekeleza code, au kuhamisha thamani? |
| **Mamlaka** | Uwakilishaji wa mamlaka kutoka kwa mtumiaji, akaunti za huduma, API tokens, muda wa uhalali wa credentials, upeo wa tenant/resource, na ufikiaji wa mtandao | Kila mwito hutekelezwa kwa utambulisho upi, na je, uidhinishaji hurudiwa kwenye mpaka wa tool? |
| **Uchakataji** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, shughuli za faili, na deserializers | Data iliyotengenezwa na model inakuwa sintaksia ya interpreter nyingine wapi? |
| **Matokeo** | Majibu, Markdown/HTML iliyowasilishwa, viungo, upakuaji wa picha, webhooks, barua pepe, faili, logs, ripoti, metrics, na mawasiliano ya agent rika | Ni njia gani inayoonekana inaweza kubeba siri au kuanzisha ombi la pili? |

Usiyapunguze haya kuwa orodha ya integrations zinazotangazwa. Kitu muhimu cha kurekodi huunganisha kila chanzo na nafasi halisi ya muktadha inayofikiwa nacho, tools zinazopatikana wakati huo, credential inayotumiwa na kila tool, interpreter ya downstream, na kila njia ya egress. Tool ileile inaweza kuwa na athari ndogo ikitumia token ya kusoma ya kila mtumiaji, lakini ikawa hatari kubwa ikitumia credential ya pamoja ya msimamizi.<sup>[[2]](#references)</sup>

## Reconnaissance

### Ramani ya kila njia ya kuwasilisha na kupokea data

Anza na sehemu za kuwasilisha data (web, mobile, API, barua pepe, jukwaa la chat, browser extension) na uweke traffic ya mteja kwenda backend kupitia proxy. Kagua sehemu zilizofichwa na UI, vigezo vya search/autocomplete/filter, objects za hali ya mazungumzo, kazi za upload na indexing, majibu ya tool, na traffic ya sub-agent. Huenda wateja wa mobile pekee wakahitaji emulator na instrumentation ili kupita certificate pinning kabla schema halisi ya ombi haijaonekana.<sup>[[2]](#references)</sup>

Kisha ramani ya stack iliyo chini ya model: orchestration framework, prompt assembly, hifadhi za retrieval na memory, runtime (kwa mfano Python, container, au WASM), volumes zilizowekwa, huduma za host, APIs za ndani, ufikikaji wa cloud metadata, na mitandao ya jirani. Mipangilio chaguomsingi ya framework ni muhimu kwa sababu baadhi ya “miito ya tool” hutekelezwa kwa kutengeneza au kutathmini code; mpaka wa runtime/sandbox huamua kama matokeo hayo yatabaki yamezuiliwa.<sup>[[2]](#references)</sup>

### Tambua routing kwa probes zisizoleta madhara

Linganisha ombi lililo ndani ya upeo na maombi kadhaa yasiyohusiana huku ukihifadhi jibu lote, status code, muda wa majibu, na tabia ya streaming. Kukataliwa kwa namna thabiti kabla ya reasoning yoyote inayohusu kazi kunaweza kuashiria gateway/classifier tofauti; kukataa kwa kuzingatia muktadha kunaashiria kuwa ombi lilifika kwa model; jibu tupu au linalotoa taarifa tu linaweza kuashiria keyword search au retrieval finyu. Zichukulie hizi kama dhana na uzithibitishe kwa kutuma tena probe ileile kupitia sehemu mbadala za API na njia za kupokea data.<sup>[[2]](#references)</sup>

Recon imekamilika pale tathmini inapoweza kutaja chanzo cha mapema zaidi kinachodhibitiwa na mshambuliaji kinachobadilisha tabia ya agent **pamoja na** tools, utambulisho, interpreters, na matokeo yanayoweza kufikiwa kutoka kwenye chanzo hicho.<sup>[[2]](#references)</sup>

## Exploitation: vuka mpaka wa uaminifu

Jaribu njia za kuingiza maudhui, si maneno ya prompt pekee. Anza na direct injection ili kubaini kile ambacho sehemu ya mbele inayoonekana huzuia, kisha rudia nia ileile kupitia njia zisizoonekana sana hapa chini:<sup>[[2]](#references)</sup>

- **Maudhui yasiyo ya moja kwa moja:** kurasa, faili, barua pepe, tiketi, metadata, alt text, HTML comments, maandishi yaliyofichwa nje ya eneo la skrini, au herufi za zero-width. Tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) kwa mbinu za kuwasilisha payload.
- **Retrieval na memory:** weka maudhui yenye sumu yatakayorejeshwa baadaye au hali itakayopakiwa tena kwenye sessions zijazo. Rekodi kama kufuta chanzo asili kunasitisha tabia hiyo.
- **Matokeo ya tool na agent rika:** weka alama kwenye jibu la tool au ujumbe wa agent-kwa-agent ili kupima kama traffic ya ndani inapita filters zinazotumika kwa ingizo la mtumiaji na matokeo ya mwisho pekee.
- **Supply chain:** kagua maelezo ya tools, plugins, servers zilizounganishwa, skills, models, na dependencies kama vyanzo vya maagizo vinavyoaminika. Kwa majaribio mahususi ya MCP, tazama [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Idhini ya binadamu:** linganisha mwito halisi wa tool uliopangwa kwa muundo na maandishi ya idhini yaliyotengenezwa na model. Jaribu kama ushawishi wa mshambuliaji unaweza kuondoa lengwa, upeo, objects zilizoathiriwa, au athari zisizoweza kurekebishwa.

Tumia alama ya kipekee isiyo na madhara kwanza. Hifadhi artifact ya chanzo, muktadha uliokusanywa ikiwa unaweza kuonekana, mwito wa tool uliochaguliwa, data ya idhini, ombi/jibu la backend, na hali ya mwisho. Hii hutofautisha ushawishi halisi na dai la kubuniwa kwamba kitendo kilifanyika.<sup>[[2]](#references)</sup>

### Kutenganisha muktadha wa subagent

Subagent ya Claude Agent SDK isiyo-fork hupokea `AgentDefinition.prompt` yake, prompt ya delegation, na tools zinazopatikana kwake, lakini si system prompt au mazungumzo ya parent. Ikiwa `tools` haijawekwa kwenye definition yake, hurithi tools zinazopatikana kwa subagents; `CLAUDE.md` ya mradi inaweza bado kupakiwa. Hii inamaanisha kuwa kizuizi cha prompt cha parent pekee si mpaka wa kuaminika wakati child inaweza kutumia tools zilezile za filesystem au execution.<sup>[[4]](#references)</sup>

Jaribu mpaka huo kwa kulinganisha ombi la moja kwa moja ambalo parent hukataa na kazi ileile iliyokabidhiwa kwa subagent yenye jina. NCC Group inaripoti kuwa ombi la kuorodhesha faili za mfumo wa uendeshaji lililokataliwa lilifaulu lilipowasilishwa upya kwa child kama “ramani ya mpangilio” isiyo na madhara.<sup>[[3]](#references)</sup>

Kagua miito halisi ya tool ya child na orodha ya tools anazoruhusiwa kutumia, si jibu la mwisho la parent pekee; thibitisha kama child ilifikia faili ambazo parent isingefikia.<sup>[[4]](#references)</sup> Hii ni hitilafu ya kurithi guardrails, si uthibitisho wa [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) au container escape.<sup>[[3]](#references)[[4]](#references)</sup>

## Execution: thibitisha athari halisi

Kuna njia mbili tofauti kutoka kwenye ushawishi hadi athari:<sup>[[2]](#references)</sup>

1. **Matumizi mabaya ya uwezo:** tool iliyoidhinishwa tayari hufanya lengo. Mifano ni kusoma rekodi ya tenant mmoja na kuiandika kwenye ripoti inayoonekana kwa mshambuliaji, kutuma barua pepe, kubadilisha rekodi, kufuta faili, au kuanzisha malipo. Hakuna hitilafu ya ziada ya software inayohitajika.
2. **Unyonyaji wa sink ya downstream:** matokeo ya model yanayoongozwa na mshambuliaji yanakuwa sintaksia kwa kipengele kingine. Kagua database queries kwa [SQL injection](../pentesting-web/sql-injection/README.md) au [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers kwa [command injection](../pentesting-web/command-injection.md), URLs zilizochaguliwa kwa [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), shughuli za faili kwa traversal, template/code evaluators kwa RCE, na object parsers kwa [unsafe deserialization](../pentesting-web/deserialization/README.md).

Kwa kila uwezekano wa shambulio, thibitisha mnyororo huu:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Integration ya read-only bado inaweza kutumiwa vibaya ikiwa sehemu yoyote ya baadaye inaweza kuchapisha ilichosoma. Jaribu majibu ya kawaida pamoja na njia za egress zisizo dhahiri sana kama vile viungo vinavyodhibitiwa na mshambuliaji, upakuaji wa picha kiotomatiki, webhooks, logs, ripoti, counters, notifications, na ujumbe kwa agents wengine.<sup>[[2]](#references)</sup>

## Vitendo vinavyolenga malengo

Baada ya kuthibitisha kitendo kimoja, tathmini eneo lote la athari badala ya kusimama kwenye athari ya kwanza inayoonekana:<sup>[[2]](#references)</sup>

- **Uchujaji wa data:** siri, rekodi za watumiaji, faili za ndani, data ya mazungumzo, au maudhui ya prompt/context hutoka kupitia njia inayoweza kuonekana.
- **Kitendo kisichoidhinishwa:** agent hutumia uwezo halali wa kuandika kutimiza lengo la mshambuliaji.
- **Kunyimwa huduma:** tools za uharibifu au operesheni ghali zinazojirudia huathiri uadilifu au upatikanaji.
- **Uendelevu:** kumbukumbu iliyochafuliwa, maudhui yaliyoingizwa kwenye index, hali inayoaminika, au mabadiliko ya runtime hudumu baada ya session iliyoanzisha au chanzo kuondolewa.
- **Kuenea:** peer anayeaminika hutumia ujumbe au hali ya pamoja ya agent iliyoathiriwa na kurudia kitendo kwa kutumia tools na credentials zake mwenyewe.

Ukali unapaswa kutegemea data inayoweza kufikiwa, kiwango halisi cha ruhusa, uwezekano wa sink kutumiwa vibaya, egress, uendelevu, na kuenea—si jinsi maandishi ya model yanavyoshangaza.<sup>[[2]](#references)</sup>

## Vidhibiti vya kuthibitisha wakati wa tathmini

Vichujio vya prompt na system prompt bora zaidi vinaweza kuongeza gharama kwa mshambuliaji, lakini havipaswi kuchukuliwa kama mipaka ya uidhinishaji. Thibitisha vidhibiti vilivyo hapa chini kwa kurudia chain ileile kupitia ingizo la moja kwa moja, maudhui yasiyo ya moja kwa moja, memory, tools, na peer agents:<sup>[[2]](#references)</sup>

- Tabaka la deterministic la policy hukagua mtumiaji aliyeidhinishwa, tenant, object, action, na destination kwenye **kila ombi la tool**; model haiwezi kutoa au kubatilisha utambulisho wa mpigaji.
- Uwezo wa kusoma na kuandika hutumia credentials tofauti zenye ruhusa za kiwango cha chini na muda mfupi; tools zenye athari kubwa hutolewa kwa wakati unaohitajika tu na haziendeshwi kiotomatiki kamwe kutokana na maudhui yaliyoingizwa.
- Egress ya mtandao na destinations za ndani huwekwa kwenye allowlist kando na URLs zinazochaguliwa na model; ufikiaji wa runtime kwenye endpoints za metadata, siri zilizomountiwa, na services jirani huzuiwa isipokuwa inahitajika.
- UI ya idhini hutengenezwa kutoka kwa ombi sanifu la kikanoni na huonyesha hoja halisi, utambulisho, destination, objects zilizoathiriwa, na athari za ziada—si muhtasari wa model ulioandikwa kwa maandishi huru.
- Mafanikio huthibitishwa kutoka kwenye mfumo lengwa au mfumo rasmi wa rekodi. Maelezo ya agent, ombi la kuita tool, au HTTP redirect si uthibitisho wa mabadiliko ya hali yanayodaiwa.
- Maingizo ya memory na retrieval huhifadhi asili na lebo za uaminifu, yanaweza kubatilishwa, na huidhinishwa upya yanapotumika kwa kitendo cha baadaye.
- Ujumbe kati ya agents huthibitishwa na kuidhinishwa kama maombi yasiyoaminika; sifa ya peer au agent card yake haikabidhi moja kwa moja tools za mpokeaji.

## References

- [1] [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Mwongozo wa Mshambuliaji wa Kushambulia AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Ni Vigumu Gani Kweli Kutoa AI Agent Kwenye Sandbox Yake?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagents katika SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
