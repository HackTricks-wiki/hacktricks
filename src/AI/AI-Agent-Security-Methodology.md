# Mbinu ya Usalama wa AI Agent

{{#include ../banners/hacktricks-training.md}}

Tathmini ya agent inapaswa kufuata **ingizo linalodhibitiwa na mshambuliaji hadi athari inayoweza kuonekana kwa nje**. Jailbreaking, mabadiliko ya tabia, na ufichuaji wa system prompt huthibitisha kuwa njia ya reasoning inaweza kushawishiwa, lakini ugunduzi wenye athari kubwa ni mnyororo unaofikia ufikiaji wa data, hatua ya tool isiyoidhinishwa, sehemu ya downstream injection, persistence, au agent mwingine.<sup>[[2]](#references)</sup>

[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) ni muhimu kwa kuweka lebo za maeneo yaliyokaguliwa (kutekwa kwa malengo, matumizi mabaya ya tool, matumizi mabaya ya ruhusa, supply chain, utekelezaji wa code, kuathiriwa kwa memory, uaminifu kati ya agents, hitilafu zinazoenea, uaminifu wa binadamu, na rogue agents). Tumia lebo hizo baada ya kujenga njia ya mashambulizi ya mwanzo hadi mwisho, badala ya kuchukulia maandishi yasiyotarajiwa ya model kuwa mwisho wa jaribio.<sup>[[1]](#references)[[2]](#references)</sup>

## Tengeneza ramani ya lengo

Rekodi vipengele hivi vitano kwa kila mtiririko wa kazi wa agent kabla ya kuandika payloads:<sup>[[2]](#references)</sup>

| Kipengele | Vitu vya kuorodhesha | Swali la usalama |
|---|---|---|
| **Ingizo lisiloaminika** | Vigezo vya Chat/API, URLs, nyaraka, barua pepe, tiketi, miingizo ya kalenda, sehemu zilizorejeshwa, memory, matokeo ya tools, na ujumbe kutoka kwa agents wenzao | Mshambuliaji anaweza kuweka maudhui wapi ili baadaye yaingie kwenye muktadha wa model? |
| **Tools** | Majina na schemas za tools, athari zake, utekelezaji otomatiki, tabia ya uthibitishaji, na tools zinazopakiwa kwa nguvu | Ni miito ipi husoma siri, hubadilisha hali, hutuma ujumbe, hufuta data, hutekeleza code, au huhamisha thamani? |
| **Mamlaka** | Uwakilishaji wa ruhusa ya mtumiaji, service accounts, API tokens, muda wa uhalali wa credentials, upeo wa tenant/resource, na ufikiaji wa mtandao | Kila mwito hutekelezwa kwa utambulisho upi, na je, uidhinishaji hurudiwa kwenye mpaka wa tool? |
| **Uchakataji** | Query builders, shells, URL fetchers, template engines, interpreters, parsers, shughuli za faili, na deserializers | Data iliyotengenezwa na model inakuwa syntax ya interpreter nyingine wapi? |
| **Matokeo** | Majibu, Markdown/HTML iliyowasilishwa, links, upakuaji wa picha, webhooks, barua pepe, faili, logs, reports, metrics, na mawasiliano ya agents wenzao | Ni njia gani inayoonekana inaweza kubeba siri au kuanzisha ombi la pili? |

Usiyapunguze haya kuwa orodha ya integrations zinazotangazwa. Kazi muhimu huunganisha kila chanzo na nafasi halisi ya muktadha kinayofikia, tools zinazopatikana hapo, credential inayotumiwa na kila tool, interpreter ya downstream, na kila njia ya kutoa data nje. Tool ileile inaweza kuwa na athari ndogo ikiwa inatumia token ya kusoma ya kila mtumiaji, na athari kubwa ikiwa inatumia credential ya pamoja ya msimamizi.<sup>[[2]](#references)</sup>

## Upelelezi

### Ramani njia zote za uwasilishaji na upokeaji wa data

Anza kwa kuchunguza sehemu za uwasilishaji (web, mobile, API, barua pepe, jukwaa la chat, kiendelezi cha browser), kisha weka proxy kwenye mawasiliano ya client na backend. Kagua sehemu zilizofichwa na UI, vigezo vya utafutaji/kukamilisha kiotomatiki/kuchuja, objects za hali ya mazungumzo, kazi za kupakia na kuorodhesha, majibu ya tools, na mawasiliano ya sub-agents. Huenda wateja wa mobile pekee wakahitaji emulator na instrumentation ili kukwepa certificate pinning kabla schema halisi ya ombi haijaonekana.<sup>[[2]](#references)</sup>

Kisha ramani stack iliyo chini ya model: orchestration framework, uundaji wa prompt, hifadhi za retrieval na memory, runtime (kwa mfano Python, container, au WASM), volumes zilizowekwa, huduma za host, APIs za ndani, ufikiaji wa cloud metadata, na mitandao ya jirani. Mipangilio chaguomsingi ya framework ni muhimu kwa sababu baadhi ya “miito ya tool” hutekelezwa kwa kutengeneza au kutathmini code; mpaka wa runtime/sandbox huamua kama matokeo hayo yatazuiliwa ndani.<sup>[[2]](#references)</sup>

### Tambua uelekezaji kwa probes zisizo na athari za uharibifu

Linganisha ombi lililo ndani ya upeo na maombi kadhaa yasiyohusiana, huku ukihifadhi jibu lote, status code, muda wa majibu, na tabia ya streaming. Kukataliwa thabiti kabla ya reasoning yoyote mahususi ya kazi kunaweza kuashiria gateway/classifier tofauti; kukataa kwa kuzingatia muktadha kunaashiria kuwa ombi limefika kwa model; jibu tupu au la kutoa taarifa pekee linaweza kuashiria utafutaji wa maneno muhimu au retrieval finyu. Zichukulie hizi kama dhana na zithibitishe kwa kurudia probe ileile kupitia sehemu mbadala za API na njia za kupokea data.<sup>[[2]](#references)</sup>

Upelelezi umekamilika pale tathmini inapoweza kubainisha chanzo cha mapema zaidi kinachodhibitiwa na mshambuliaji kinachobadilisha tabia ya agent **na** tools, utambulisho, interpreters, na matokeo yanayofikiwa kutoka kwenye chanzo hicho.<sup>[[2]](#references)</sup>

## Unyonyaji: vuka mpaka wa uaminifu

Jaribu njia za kuingiza maudhui, si uandishi wa prompt pekee. Anza kwa direct injection ili kubaini kile ambacho mlango wa mbele unaoonekana huzuia, kisha rudia nia ileile kupitia njia zisizoonekana kwa urahisi zilizo hapa chini:<sup>[[2]](#references)</sup>

- **Maudhui yasiyo ya moja kwa moja:** kurasa, faili, barua pepe, tiketi, metadata, alt text, HTML comments, maandishi yaliyo nje ya skrini, au zero-width characters. Tazama [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) kwa mbinu za kuwasilisha payload.
- **Retrieval na memory:** weka maudhui yenye sumu yatakayorejeshwa baadaye, au hali itakayopakiwa tena katika session za baadaye. Rekodi kama kufuta chanzo asili huondoa tabia hiyo.
- **Matokeo ya tools na agents wenzao:** weka alama kwenye jibu la tool au ujumbe wa agent-kwa-agent ili kupima kama mawasiliano ya ndani yanakwepa vichujio vinavyotumika tu kwenye ingizo la mtumiaji na matokeo ya mwisho.
- **Supply chain:** kagua maelezo ya tools, plugins, servers zilizounganishwa, skills, models, na dependencies kama vyanzo vya maagizo vinavyoaminika. Kwa majaribio mahususi ya MCP, tazama [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Idhini ya binadamu:** linganisha mwito halisi wa tool uliopangwa kimuundo na maandishi ya idhini yaliyotengenezwa na model. Jaribu kama ushawishi wa mshambuliaji unaweza kuondoa lengwa, upeo, objects zilizoathiriwa, au athari zisizoweza kutenduliwa.

Tumia alama ya kipekee isiyo na madhara kwanza. Hifadhi artifact chanzo, muktadha uliokusanywa ikiwa unaweza kuonekana, mwito wa tool uliochaguliwa, data ya idhini, ombi/jibu la backend, na hali ya mwisho. Hii hutofautisha ushawishi halisi na madai ya kubuni kuwa hatua fulani ilitekelezwa.<sup>[[2]](#references)</sup>

## Utekelezaji: thibitisha athari halisi

Kuna njia mbili tofauti kutoka kwa ushawishi hadi athari:<sup>[[2]](#references)</sup>

1. **Matumizi mabaya ya uwezo:** tool iliyoidhinishwa tayari hutekeleza lengo. Mifano ni pamoja na kusoma rekodi ya tenant mmoja na kuiandika kwenye report inayoonekana kwa mshambuliaji, kutuma barua pepe, kubadilisha rekodi, kufuta faili, au kuanzisha malipo. Hitilafu ya pili ya programu haihitajiki.
2. **Unyonyaji wa sehemu ya downstream:** matokeo ya model yaliyoelekezwa na mshambuliaji yanakuwa syntax kwa kipengele kingine. Kagua database queries kwa [SQL injection](../pentesting-web/sql-injection/README.md) au [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers kwa [command injection](../pentesting-web/command-injection.md), URLs zilizochaguliwa kwa [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), shughuli za faili kwa path traversal, template/code evaluators kwa RCE, na object parsers kwa [unsafe deserialization](../pentesting-web/deserialization/README.md).

Kwa kila uwezekano, thibitisha mnyororo huu:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Muunganisho wa kusoma pekee bado unaweza kutumiwa vibaya ikiwa kipengele chochote cha baadaye kinaweza kuchapisha kilichosomwa. Jaribu majibu ya kawaida pamoja na njia zisizo dhahiri za kutoa data, kama vile viungo vinavyodhibitiwa na mshambuliaji, upakuaji wa picha kiotomatiki, webhooks, kumbukumbu, ripoti, vihesabio, arifa na ujumbe kwa agents wengine.<sup>[[2]](#references)</sup>

## Vitendo kwenye malengo

Baada ya kuthibitisha kitendo kimoja, tathmini wigo mzima wa athari badala ya kusimama kwenye athari ya kwanza inayoonekana:<sup>[[2]](#references)</sup>

- **Utoaji wa data:** siri, rekodi za watumiaji, faili za ndani, data ya mazungumzo au maudhui ya prompt/context yanaondoka kupitia njia inayoweza kuonekana.
- **Kitendo kisichoidhinishwa:** agent hutumia uwezo halali wa kuandika kutimiza lengo la mshambuliaji.
- **Kunyimwa huduma:** tools haribifu au operesheni ghali zinazorudiwa huathiri uadilifu au upatikanaji.
- **Uendelevu:** kumbukumbu iliyoathiriwa, maudhui yaliyowekwa kwenye faharasa, hali inayoaminika au mabadiliko ya runtime hudumu baada ya kipindi au chanzo kilichosababisha kuondolewa.
- **Kuenea:** peer anayeaminika hutumia ujumbe au hali inayoshirikiwa ya agent iliyoathiriwa na kurudia kitendo hicho kwa kutumia tools na credentials zake mwenyewe.

Ukali unapaswa kutegemea data inayoweza kufikiwa, kiwango halisi cha ruhusa, uwezekano wa sink kutumiwa vibaya, egress, uendelevu na kuenea—si jinsi maandishi ya model yanavyoshangaza.<sup>[[2]](#references)</sup>

## Vidhibiti vya kuthibitisha wakati wa tathmini

Vichujio vya prompt na system prompt bora zaidi vinaweza kuongeza gharama kwa mshambuliaji, lakini havipaswi kuchukuliwa kama mipaka ya uidhinishaji. Thibitisha vidhibiti vilivyo hapa chini kwa kuendesha tena mnyororo huo kupitia ingizo la moja kwa moja, maudhui yasiyo ya moja kwa moja, memory, tools na peer agents:<sup>[[2]](#references)</sup>

- Safu ya sera ya kubainisha huangalia mtumiaji aliyeidhinishwa, tenant, object, action na destination kwenye **kila mwito wa tool**; model haiwezi kutoa au kubatilisha utambulisho wa mpigaji.
- Uwezo wa kusoma na kuandika hutumia credentials tofauti zenye ruhusa za kiwango cha chini na muda mfupi; tools zenye athari kubwa hutolewa kwa wakati unaohitajika tu na haziendeshwi kamwe kiotomatiki kutokana na maudhui yaliyopokelewa.
- Egress ya mtandao na destinations za ndani huorodheshwa zinaruhusiwa kivyake bila kutegemea URLs zilizochaguliwa na model; ufikiaji wa runtime kwa endpoints za metadata, siri zilizowekwa kwenye mount na huduma za jirani huzuiwa isipokuwa zinahitajika.
- UI ya idhini hutengenezwa kutokana na ombi sanifu la msingi na huonyesha hoja halisi, utambulisho, destination, objects zilizoathiriwa na athari za ziada—si muhtasari wa model ulioandikwa kwa lugha huru.
- Mafanikio huthibitishwa kutoka kwenye mfumo lengwa au mfumo rasmi wa rekodi. Maelezo ya agent, ombi la mwito wa tool au uelekezaji upya wa HTTP si uthibitisho wa mabadiliko ya hali yanayodaiwa.
- Maingizo ya memory na retrieval huhifadhi chanzo na lebo za uaminifu, yanaweza kubatilishwa na huidhinishwa upya yanapotumika kwa kitendo cha baadaye.
- Ujumbe kati ya agents huthibitishwa na kuidhinishwa kama maombi yasiyoaminika; sifa ya peer au agent card yake haikabidhi moja kwa moja tools za mpokeaji.

## References

- [1] [Orodha 10 Bora za OWASP za Programu za Agentic za 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Mwongozo wa Wadukuzi wa Kushambulia AI Agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
