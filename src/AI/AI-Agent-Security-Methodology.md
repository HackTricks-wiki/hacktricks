# Sekuriteitsmetodologie vir AI-agente

{{#include ../banners/hacktricks-training.md}}

’n Agentassessering behoort **aanvallerbeheerde invoer te volg tot by ’n ekstern waarneembare effek**. Jailbreaking, karakterveranderings en openbaarmaking van stelselprompts bewys dat ’n redenasiekanaal beïnvloedbaar is, maar die bevinding met die grootste impak is die ketting na datatoegang, ’n ongemagtigde tool-aksie, ’n stroomaf-inspuitingssink, volharding of ’n ander agent.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is nuttig om dekking te benoem (doelwitkapings, toolmisbruik, voorregmisbruik, voorsieningsketting, kode-uitvoering, geheuevergiftiging, vertroue tussen agente, kettingreaksie-foute, menslike vertroue en skelm agente). Gebruik dié etikette nadat jy ’n end-tot-end-aanvalspad saamgestel het, eerder as om ’n model se onverwagte teks as die einde van die toets te beskou.<sup>[[1]](#references)[[2]](#references)</sup>

## Stel die teikenkaart saam

Teken hierdie vyf dimensies vir elke agentwerkvloei aan voordat jy payloads skryf:<sup>[[2]](#references)</sup>

| Dimensie | Wat om te inventariseer | Sekuriteitsvraag |
|---|---|---|
| **Onbetroubare invoer** | Chat/API-parameters, URLs, dokumente, e-pos, kaartjies, kalenderinskrywings, opgespoorde brokkies, geheue, tool-resultate en boodskappe van eweknie-agente | Waar kan ’n aanvaller inhoud plaas wat later die modelkonteks binnedring? |
| **Tools** | Toolname en -skemas, newe-effekte, outomatiese uitvoering, bevestigingsgedrag en dinamies gelaaide tools | Watter oproepe lees geheime, skryf toestand, stuur boodskappe, vee data uit, voer kode uit of dra waarde oor? |
| **Gesag** | Gebruikersdelegering, diensrekeninge, API-tokens, geloofsbriewe se leeftyd, tenant-/hulpbronomvang en netwerkbereik | Onder watter identiteit word elke oproep uitgevoer, en word magtiging by die toolgrens weer nagegaan? |
| **Verwerking** | Navraagbouers, shells, URL-ophalers, sjabloonenjins, interpreteerders, ontleders, lêerbewerkings en deserialiseerders | Waar word data wat deur die model gegenereer is sintaksis vir ’n ander interpreteerder? |
| **Uitvoer** | Antwoorde, weergegee Markdown/HTML, skakels, beeldophalings, webhooks, e-pos, lêers, logs, verslae, statistieke en verkeer tussen eweknie-agente | Watter waarneembare kanaal kan ’n geheim dra of ’n sekondêre versoek aktiveer? |

Moenie dit reduseer tot ’n lys geadverteerde integrasies nie. ’n Nuttige artefak koppel elke bron aan die presiese konteksposisie wat dit bereik, die tools wat op daardie punt beskikbaar is, die geloofsbrief wat elke tool gebruik, die stroomaf-interpreteerder en elke uitgaande roete. Dieselfde tool kan ’n lae impak hê met ’n leestoegangstoken per gebruiker, maar kritiek wees met ’n gedeelde administrateurgeloofsbrief.<sup>[[2]](#references)</sup>

## Verkenning

### Karteer elke aflewerings- en invoerpad

Begin by die afleweringsoppervlak (web, selfoon, API, e-pos, kletsplatform, blaaieruitbreiding) en onderskep die verkeer tussen kliënt en backend met ’n proxy. Inspekteer velde wat deur die UI versteek word, soek-/outovoltooi-/filterparameters, gesprekstoestandobjekte, oplaai- en indekseringstake, tool-antwoorde en subagentverkeer. Slegs-selfoonkliënte kan ’n emulator en instrumentasie vereis om sertifikaatpinnig te omseil voordat die werklike versoekskema sigbaar word.<sup>[[2]](#references)</sup>

Karteer dan die lae onder die model: orkestreringsraamwerk, prompt-samestelling, herwinning- en geheuebergings, looptyd (byvoorbeeld Python, container of WASM), gemonteerde volumes, gasheerdienste, interne APIs, bereikbaarheid van cloud-metadata en naburige netwerke. Raamwerkverstekwaardes maak saak omdat sommige “tool calls” geïmplementeer word deur kode te genereer of te evalueer; die looptyd-/sandboxgrens bepaal of daardie resultaat ingeperk bly.<sup>[[2]](#references)</sup>

### Vingerafdrukroetering met nie-vernietigende probes

Vergelyk ’n versoek binne die omvang met verskeie onverwante versoeke terwyl jy die volledige antwoord, statuskode, latensie en stroomgedrag behou. ’n Stabiele weiering voordat enige taakspesifieke redenasie plaasvind, kan op ’n afsonderlike gateway/klassifiseerder dui; ’n kontekstuele weiering dui daarop dat die versoek die model bereik het; ’n leë of suiwer ekstraktiewe antwoord kan op sleutelwoordsoektog of beperkte herwinning dui. Behandel dit as hipoteses en bevestig dit deur dieselfde probe via alternatiewe API-velde en invoerpaaie weer te speel.<sup>[[2]](#references)</sup>

Verkenning is voltooi wanneer die assessering die vroegste aanvallerbeheerde bron kan benoem wat agentgedrag verander **en** die tools, identiteite, interpreteerders en uitsette wat vanaf daardie bron bereik kan word.<sup>[[2]](#references)</sup>

## Eksploitasie: steek ’n vertrouensgrens oor

Toets kanale, nie net promptformulering nie. Begin met direkte inspuiting om vas te stel wat die sigbare toegangspunt blokkeer, en herhaal dan ekwivalente bedoeling deur die minder sigbare paaie hieronder:<sup>[[2]](#references)</sup>

- **Indirekte inhoud:** bladsye, lêers, e-pos, kaartjies, metadata, alt-teks, HTML-opmerkings, teks buite die skerm of nulwydtekarakters. Sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) vir tegnieke om payloads af te lewer.
- **Herwinning en geheue:** vergiftig inhoud wat later herwin sal word, of toestand wat in latere sessies herlaai sal word. Teken aan of die gedrag verdwyn wanneer die oorspronklike bron uitgevee word.
- **Tool-uitvoer en eweknie-agente:** plaas die merker in ’n tool-antwoord of ’n agent-tot-agent-boodskap om te toets of interne verkeer filters omseil wat slegs op gebruikerinvoer en finale uitvoer toegepas word.
- **Voorsieningsketting:** beskou toolbeskrywings, plugins, gekoppelde bedieners, skills, modelle en afhanklikhede as vertroude instruksiebronne. Vir MCP-spesifieke toetse, sien [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menslike goedkeuring:** vergelyk die werklike gestruktureerde tool-oproep met die goedkeuringsteks wat die model gegenereer het. Toets of aanvallerinvloed die bestemming, omvang, geraakte voorwerpe of onomkeerbare newe-effekte kan weglaat.

Gebruik eers ’n onskadelike, unieke merker. Bewaar die bronartefak, saamgestelde konteks indien waarneembaar, geselekteerde tool-oproep, goedkeuringsdata, backend-versoek/-antwoord en finale toestand. Dit onderskei beïnvloeding van ’n gehallusineerde bewering dat ’n aksie plaasgevind het.<sup>[[2]](#references)</sup>

### Beleidagtige teks in ’n toolrisiko-beoordelaar

’n Modelgebaseerde toolhek kan aanvallerbeheerde teks binne andersins nuttige klassifikasiekonteks ontvang. LangChain se eksperimentele `AutoModeMiddleware` stuur byvoorbeeld ’n voorgestelde tool-oproep, sy argumente, ’n opsionele toolbeskrywing en tot 30 onlangse boodskappe na ’n TypeSafe `is_risky`-beoordelaar. Dit blokkeer gekonfigureerde tools wanneer die teruggestuurde Noul-waarskynlikheid minstens `0.5` is; tools wat nie gelys is nie, word nie deur hierdie middleware geklassifiseer nie.<sup>[[5]](#references)</sup> TypeSafe waarsku ook dat teenstrydige teks in toestand ’n klassifikasie kan beïnvloed, selfs wanneer die toestand bedoel is om data te wees.<sup>[[6]](#references)</sup>

’n **Vervalste beleid** verskil van bloot die bewering dat iets ’n stelselboodskap is. Dit plaas alternatiewe etikette of risikodefinisies binne toestand met ’n laer vertrouensvlak en moedig die beoordelaar aan om dié definisies te gebruik in plaas van sy ontwikkelaarbepaalde kriteria. In Datadog se toets is ’n gebruikerbewerkbare `profile_description` saam met `can_edit:false` na die tool-argumente gekopieer. Die beleidagtige teks het aangevoer dat ’n skryfpoging lae risiko inhou omdat ’n afsonderlike toestemmingstoets dit behoort te verwerp voordat enige wysiging plaasvind. Oor 40 lopies het die gemiddelde `is_risky`-telling van `0.893` tot `0.290` gedaal, terwyl ’n direkte rolvervalsingsvergelyking gemiddeld `0.905` behaal het. Dat die gemiddelde onder `0.5` daal, bewys nie dat elke individuele oproep die hek geslaag het nie, en die eksperiment het **nie** ’n voltooide ongemagtigde skryfbewerking gedemonstreer nie.<sup>[[7]](#references)</sup>

Wanneer jy hierdie grens toets, onderskei die klassifiseerder se uitspraak van die tool se werklike magtigingsuitslag. Kyk watter bewerkbare velde die beoordelaar bereik, vergelyk dieselfde voorgestelde aksie met en sonder beleidagtige teks, en verifieer die finale toestand onafhanklik. ’n Afsonderlike toestemmingstoets moet steeds die geverifieerde versoeker se gesag gebruik, nie die connector se diensrekeningregte nie.<sup>[[7]](#references)</sup> Sien [prompt-filter-bypasses](AI-Prompts.md#prompt-waf-bypass) vir ander mislukkingsmodusse van klassifiseerders; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) handel oor ’n ander roeterings- en geloofsbriefgrens.

### Subagentkonteksisolasie

’n Nie-fork Claude Agent SDK-subagent ontvang sy eie `AgentDefinition.prompt`, die delegeringsprompt en sy beskikbare tools, maar nie die ouer se stelselpompt of gesprek nie. As `tools` uit sy definisie weggelaat word, erf dit die tools wat vir subagente beskikbaar is; projek-`CLAUDE.md` kan steeds gelaai word. Dit maak ’n beperking in slegs die ouer se prompt ’n onbetroubare grens wanneer die kind dieselfde lêerstelsel- of uitvoeringshulpmiddels kan gebruik.<sup>[[4]](#references)</sup>

Toets die grens deur ’n direkte versoek wat die ouer weier te vergelyk met dieselfde taak wat aan ’n benoemde subagent gedelegeer word. NCC Group berig dat ’n geweierde enumerasie van bedryfstelsellêers geslaag het toe dit vir ’n kind as ’n onskadelike “uitlegkaart” herformuleer is.<sup>[[3]](#references)</sup>

Inspekteer die kind se werklike tool-oproepe en effektiewe toelaatlys vir tools, nie net die ouer se finale antwoord nie; bevestig of die kind toegang verkry het tot lêers waartoe die ouer nie toegang sou kry nie.<sup>[[4]](#references)</sup> Dit is ’n fout met die oorerwing van beskermingsmaatreëls, nie bewys van ’n [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) of container-ontsnapping nie.<sup>[[3]](#references)[[4]](#references)</sup>

## Uitvoering: bewys werklike impak

Daar is twee afsonderlike roetes van beïnvloeding na impak:<sup>[[2]](#references)</sup>

1. **Misbruik van vermoëns:** die gemagtigde tool voer reeds die doelwit uit. Voorbeelde sluit in om een tenant se rekord te lees en dit in ’n aanvaller-sigbare verslag te skryf, e-pos te stuur, rekords te verander, ’n lêer uit te vee of ’n betaling te begin. Geen sekondêre sagtewarefout word vereis nie.
2. **Uitbuiting van stroomaf-sinks:** aanvallergerigte modeluitvoer word sintaksis vir ’n ander komponent. Gaan databas navrae na vir [SQL injection](../pentesting-web/sql-injection/README.md) of [NoSQL injection](../pentesting-web/nosql-injection.md), shell-wrappers vir [command injection](../pentesting-web/command-injection.md), gekose URLs vir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), lêerbewerkings vir padtraversering, sjabloon-/kode-evalueerders vir RCE en objekontleders vir [unsafe deserialization](../pentesting-web/deserialization/README.md).

Bewys hierdie ketting vir elke kandidaat:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

’n Read-only-integrasie kan steeds uitgebuit word wanneer enige latere komponent dit wat gelees is, kan publiseer. Toets gewone response, asook minder ooglopende uitgaande kanale soos aanvallerbeheerde skakels, outomatiese beeldherwinning, webhooks, logs, verslae, tellers, kennisgewings en boodskappe aan ander agente.<sup>[[2]](#references)</sup>

## Aksies teen doelwitte

Nadat jy een aksie bevestig het, evalueer die volledige ontploffingsradius eerder as om by die eerste sigbare uitwerking op te hou:<sup>[[2]](#references)</sup>

- **Data-eksfiltrasie:** geheime, gebruikersrekords, interne lêers, gesprekdata of prompt-/konteksinhoud verlaat die stelsel via ’n waarneembare kanaal.
- **Ongemagtigde aksie:** die agent gebruik wettige skryfvermoëns om die aanvaller se doel te bereik.
- **Diensweiering:** vernietigende nutsmiddels of herhaalde duur bewerkings beïnvloed integriteit of beskikbaarheid.
- **Volharding:** vergiftigde geheue, geïndekseerde inhoud, vertroude toestand of runtime-veranderinge bly voortbestaan nadat die oorspronklike sessie geëindig het of die bron verwyder is.
- **Verspreiding:** ’n vertroude eweknie verwerk die gekompromitteerde agent se boodskap of gedeelde toestand en herhaal die aksie met sy eie nutsmiddels en geloofsbriewe.

Erns moet bepaal word deur bereikbare data, effektiewe voorregte, die uitbuitbaarheid van die sink, uitgaande kanale, volharding en verspreiding—nie deur hoe verrassend die model se teks voorkom nie.<sup>[[2]](#references)</sup>

## Kontroles om tydens die assessering te valideer

Promptfilters en ’n beter stelselaanwysing kan die aanvaller se koste verhoog, maar moet nie as magtigingsgrense beskou word nie. Valideer die onderstaande kontroles deur dieselfde ketting weer uit te voer via direkte invoer, indirekte inhoud, geheue, nutsmiddels en eweknie-agente:<sup>[[2]](#references)</sup>

- ’n Deterministiese beleidslaag kontroleer die geverifieerde gebruiker, tenant, objek, aksie en bestemming by **elke aanroep van ’n nutsmiddel**; die model kan nie die oproeper se identiteit verskaf of oorheers nie.
- Lees- en skryfvermoëns gebruik afsonderlike, minimaal bevoorregte, kortlewende geloofsbriewe; nutsmiddels met groot impak word net betyds beskikbaar gestel en voer nooit outomaties inhoud uit wat ingeneem is nie.
- Netwerkverkeer na buite en interne bestemmings word onafhanklik van URL’s wat deur die model gekies is, tot ’n toelaatlys beperk; runtime-toegang tot metadata-eindpunte, gemonteerde geheime en naburige dienste word geblokkeer tensy dit nodig is.
- Die goedkeuringskoppelvlak word uit die kanonieke gestruktureerde versoek gegenereer en toon die presiese argumente, identiteit, bestemming, geraakte objekte en newe-effekte—nie ’n vryvormige modelsamevatting nie.
- Sukses word by die bestemmingstelsel of stelsel van rekord geverifieer. Die agent se beskrywing, ’n versoek om ’n nutsmiddel aan te roep of ’n HTTP-herleiding bewys nie dat die beweerde toestandsverandering plaasgevind het nie.
- Geheue- en herwinningsinskrywings behou herkoms- en vertrouensetikette, kan ongeldig gemaak word en word weer gemagtig wanneer dit vir ’n latere aksie gebruik word.
- Interagentboodskappe word geverifieer en gemagtig as onvertroude versoeke; ’n eweknie se reputasie of agentkaart delegeer nie implisiet die ontvanger se nutsmiddels nie.

Vir A2A-agentkaarte, taakvloeie en hul aanvaloppervlak, raadpleeg [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 vir agentiese toepassings vir 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Die hacker se gids tot die aanval op AI-agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Hoe moeilik is dit werklik om ’n AI-agent uit sy sandbox te laat ontsnap?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagente in die SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Bronkode vir LangChain TypeSafe Auto Mode-middelware](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-model se getande vermoëns: teenstrydige inhoud](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev as beoordelaar: Hoe vervalste beleid Jev stuur](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
