# AI Agent Security Methodology

{{#include ../banners/hacktricks-training.md}}

’n Agent-assessering moet **’n aanvallerbeheerde invoer tot ’n ekstern waarneembare uitwerking** volg. Jailbreaking, karakterverandering en openbaarmaking van die stelselaanwysing bewys dat ’n redenasiekanaal beïnvloed kan word, maar die hoë-impakbevinding is die ketting na datatoegang, ’n ongemagtigde tool-aksie, ’n stroomaf-inspuitingsink, volharding of ’n ander agent.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is nuttig om dekking te benoem (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust en rogue agents). Gebruik dié etikette nadat jy ’n aanvalspad van begin tot einde saamgestel het, eerder as om ’n model se onverwagte teks as die einde van die toets te beskou.<sup>[[1]](#references)[[2]](#references)</sup>

## Bou die teikenkaart

Teken hierdie vyf dimensies vir elke agent-werkvloei aan voordat jy payloads skryf:<sup>[[2]](#references)</sup>

| Dimensie | Wat om te inventariseer | Sekuriteitsvraag |
|---|---|---|
| **Onvertroude invoer** | Chat/API-parameters, URLs, dokumente, e-pos, kaartjies, kalenderinskrywings, opgespoorde brokkies, geheue, tool-resultate en boodskappe van eweknie-agents | Waar kan ’n aanvaller inhoud plaas wat later die modelkonteks binnegaan? |
| **Tools** | Tool-name en -skemas, newe-effekte, outomatiese uitvoering, bevestigingsgedrag en dinamies gelaaide tools | Watter oproepe lees geheime, skryf toestand, stuur boodskappe, verwyder data, voer kode uit of dra waarde oor? |
| **Gesag** | Gebruikersdelegering, diensrekeninge, API-tokens, geloofsbriewe se leeftyd, tenant-/hulpbronomvang en netwerkbereik | As watter identiteit loop elke oproep, en word magtiging by die tool-grens herhaal? |
| **Verwerking** | Navraagbouers, shells, URL-haalprogramme, sjabloonenjins, interpreteerders, ontleders, lêerbewerkings en deserialiseerders | Waar word modelgegenereerde data sintaksis vir ’n ander interpreteerder? |
| **Uitvoer** | Antwoorde, weergegee Markdown/HTML, skakels, beeldhaalversoeke, webhooks, e-pos, lêers, logs, verslae, maatstawwe en verkeer tussen eweknie-agents | Watter waarneembare kanaal kan ’n geheim dra of ’n sekondêre versoek aktiveer? |

Moenie dit tot ’n lys van geadverteerde integrasies reduseer nie. ’n Nuttige artefak koppel elke bron aan die presiese konteksposisie wat dit bereik, die tools wat op daardie punt beskikbaar is, die geloofsbrief wat elke tool gebruik, die stroomaf-interpreteerder en elke uitgaande roete. Dieselfde tool kan ’n lae impak hê met ’n lees-token per gebruiker en kritiek wees met ’n gedeelde administrateurgeloofsbrief.<sup>[[2]](#references)</sup>

## Verkenning

### Karteer elke aflewerings- en innamepad

Begin met die afleweringsoppervlak (web, mobiel, API, e-pos, chat-platform, blaaieruitbreiding) en onderskep die kliënt-na-agterkant-verkeer deur ’n proxy. Ondersoek velde wat deur die UI versteek word, soek-/outovoltooi-/filterparameters, gesprekstoestand-objekte, oplaai- en indekseringstake, tool-antwoorde en verkeer tussen subagents. Slegs-mobiele kliënte kan ’n emulator en instrumentasie vereis om sertifikaat-pinning te omseil voordat die werklike versoekskema sigbaar word.<sup>[[2]](#references)</sup>

Karteer dan die stapel onder die model: orkestrasieraamwerk, prompt-samestelling, herwinning- en geheuebergings, runtime (byvoorbeeld Python, container of WASM), gekoppelde volumes, gasheerdienste, interne APIs, bereikbaarheid van cloud-metadata en naburige netwerke. Raamwerkverstekwaardes is belangrik omdat sommige “tool calls” geïmplementeer word deur kode te genereer of te evalueer; die runtime/sandbox-grens bepaal of daardie resultaat ingeperk bly.<sup>[[2]](#references)</sup>

### Identifiseer roetering met nie-vernietigende probes

Vergelyk ’n binne-omvang-versoek met verskeie onverwante versoeke, terwyl jy die volledige antwoord, statuskode, latensie en stroomgedrag behou. ’n Stabiele weiering voordat enige taakspesifieke redenering plaasvind, kan op ’n afsonderlike gateway/klassifiseerder dui; ’n kontekstuele weiering dui daarop dat die versoek die model bereik het; ’n leë of suiwer ekstraktiewe antwoord kan op sleutelwoordsoektog of beperkte herwinning dui. Behandel dit as hipoteses en bevestig dit deur dieselfde probe via alternatiewe API-velde en innamepaaie te herhaal.<sup>[[2]](#references)</sup>

Verkenning is voltooi wanneer die assessering die vroegste aanvallerbeheerde bron kan benoem wat agentgedrag verander **én** die tools, identiteite, interpreteerders en uitvoere wat vanaf daardie bron bereikbaar is.<sup>[[2]](#references)</sup>

## Uitbuiting: steek ’n vertrouensgrens oor

Toets kanale, nie net prompt-bewoording nie. Begin met direkte inspuiting om vas te stel wat die sigbare voordeur blokkeer, en herhaal dan ekwivalente bedoeling via die minder sigbare paaie hieronder:<sup>[[2]](#references)</sup>

- **Indirekte inhoud:** bladsye, lêers, e-pos, kaartjies, metadata, alt-teks, HTML-kommentaar, teks buite die sigbare skermarea of zero-width-karakters. Sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) vir tegnieke om payloads af te lewer.
- **Herwinning en geheue:** vergiftig inhoud wat later herwin sal word, of toestand wat in latere sessies herlaai sal word. Teken aan of die verwydering van die oorspronklike bron die gedrag stop.
- **Tool-uitvoer en eweknie-agents:** plaas die merker in ’n tool-antwoord of ’n agent-na-agent-boodskap om te toets of interne verkeer filters omseil wat slegs op gebruikersinvoer en finale uitvoer toegepas word.
- **Voorsieningsketting:** beskou tool-beskrywings, plugins, gekoppelde bedieners, vaardighede, modelle en afhanklikhede as vertroude instruksiebronne. Sien [MCP Servers](AI-MCP-Servers.md#mcp-vulns) vir MCP-spesifieke toetse.
- **Menslike goedkeuring:** vergelyk die werklike gestruktureerde tool-oproep met die modelgegenereerde goedkeuringsteks. Toets of aanvallerinvloed die bestemming, omvang, geraakte objekte of onomkeerbare newe-effekte kan weglaat.

Gebruik eers ’n onskadelike, unieke merker. Bewaar die bronartefak, saamgestelde konteks indien waarneembaar, geselekteerde tool-oproep, goedkeuringsdata, agterkantversoek/-antwoord en finale toestand. Dit onderskei beïnvloeding van ’n gehallusineerde bewering dat ’n aksie plaasgevind het.<sup>[[2]](#references)</sup>

### Beleidsvormige teks in ’n tool-risikobeoordelaar

’n Modelgebaseerde tool-poort kan aanvallerbeheerde teks ontvang binne andersins nuttige klassifikasiekonteks. LangChain se eksperimentele `AutoModeMiddleware` stuur byvoorbeeld ’n voorgestelde tool-oproep, sy argumente, ’n opsionele tool-beskrywing en tot 30 onlangse boodskappe na ’n TypeSafe `is_risky`-beoordelaar. Dit blokkeer gekonfigureerde tools wanneer die teruggekeerde Noul-waarskynlikheid minstens `0.5` is; tools wat nie gelys is nie, word nie deur hierdie middleware geklassifiseer nie.<sup>[[5]](#references)</sup> TypeSafe waarsku ook dat teenstrydige teks in toestand ’n klassifikasie kan beïnvloed, selfs wanneer die toestand bedoel is as data.<sup>[[6]](#references)</sup>

’n **Nagemaakte beleid** verskil van bloot beweer dat jy ’n stelselboodskap is. Dit plaas alternatiewe etikette of risikodefinisies in laer-vertroue-toestand en spoor die beoordelaar aan om dié definisies te gebruik in plaas van die ontwikkelaar-gedefinieerde kriteria. In Datadog se toets is ’n gebruikerbewerkbare `profile_description` saam met `can_edit:false` na die tool-argumente gekopieer. Die beleidsagtige teks het aangevoer dat ’n skryfpoging lae risiko inhou omdat ’n afsonderlike toestemmingskontrole dit voor enige verandering behoort te verwerp. Oor 40 lopies het die gemiddelde `is_risky`-telling van `0.893` tot `0.290` gedaal, terwyl ’n direkte rolvervalsingsvergelyking gemiddeld `0.905` opgelewer het. Dat die gemiddelde onder `0.5` gedaal het, bewys nie dat elke individuele oproep die poort geslaag het nie, en die eksperiment het **nie** ’n voltooide ongemagtigde skryfbewerking gedemonstreer nie.<sup>[[7]](#references)</sup>

Wanneer jy hierdie grens toets, onderskei die klassifiseerder se uitspraak van die tool se werklike magtigingsuitslag. Kyk watter bewerkbare velde die beoordelaar bereik, vergelyk dieselfde voorgestelde aksie met en sonder beleidsagtige teks, en verifieer die finale toestand onafhanklik. ’n Afsonderlike toestemmingskontrole moet steeds die geverifieerde versoeker se gesag gebruik, nie die koppelstuk se diensrekeningregte nie.<sup>[[7]](#references)</sup> Sien [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) vir ander mislukkingsmodusse van klassifiseerders; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) handel oor ’n ander roeterings- en geloofsbriefgrens.

### Isolasie van subagentkonteks

’n Nie-fork Claude Agent SDK-subagent ontvang sy eie `AgentDefinition.prompt`, die delegeringsprompt en sy beskikbare tools, maar nie die ouer se stelselaanwysing of gesprek nie. As `tools` uit sy definisie weggelaat word, erf dit die tools wat vir subagents beskikbaar is; die projek se `CLAUDE.md` kan steeds gelaai word. Dit maak ’n beperking in die ouer se prompt ’n onbetroubare grens wanneer die kind dieselfde lêerstelsel- of uitvoerings-tools kan gebruik.<sup>[[4]](#references)</sup>

Toets die grens deur ’n direkte versoek wat die ouer weier te vergelyk met dieselfde taak wat aan ’n benoemde subagent gedelegeer word. NCC Group berig dat ’n weiering om lêers van die bedryfstelsel te inventariseer suksesvol was toe dit vir ’n kind as ’n onskadelike “uitlegkaart” herformuleer is.<sup>[[3]](#references)</sup>

Ondersoek die kind se werklike tool-oproepe en effektiewe tool-toelatingslys, nie net die ouer se finale antwoord nie; bevestig of die kind toegang verkry het tot lêers waartoe die ouer nie toegang sou kry nie.<sup>[[4]](#references)</sup> Dit is ’n mislukking in die oorerwing van veiligheidsrelings, nie bewys van ’n [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) of container-ontsnapping nie.<sup>[[3]](#references)[[4]](#references)</sup>

## Uitvoering: bewys werklike impak

Daar is twee afsonderlike roetes van beïnvloeding na impak:<sup>[[2]](#references)</sup>

1. **Misbruik van vermoëns:** die gemagtigde tool voer reeds die doel uit. Voorbeelde sluit in om een tenant se rekord te lees en dit na ’n aanvaller-sigbare verslag te skryf, e-pos te stuur, rekords te verander, ’n lêer te verwyder of ’n betaling te begin. Geen sekondêre sagtewarefout is nodig nie.
2. **Uitbuiting van ’n stroomaf-sink:** aanvallergerigte modeluitvoer word sintaksis vir ’n ander komponent. Hersien databasisnavrae vir [SQL injection](../pentesting-web/sql-injection/README.md) of [NoSQL injection](../pentesting-web/nosql-injection.md), shell-wrappers vir [command injection](../pentesting-web/command-injection.md), gekose URLs vir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), lêerbewerkings vir traversal, sjabloon-/kode-evalueerders vir RCE, en objekontleders vir [unsafe deserialization](../pentesting-web/deserialization/README.md).

Bewys hierdie ketting vir elke kandidaat:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

’n Leesalleen-integrasie kan steeds uitgebuit word wanneer enige latere komponent kan publiseer wat dit gelees het. Toets gewone antwoorde, asook minder ooglopende uitgaande verkeer soos aanvallerbeheerde skakels, outomatiese beeldophaling, webhooks, logs, verslae, tellers, kennisgewings en boodskappe aan ander agente.<sup>[[2]](#references)</sup>

## Aksies op doelwitte

Nadat een aksie bevestig is, evalueer die volle omvang van die impak eerder as om by die eerste sigbare uitwerking op te hou:<sup>[[2]](#references)</sup>

- **Data-uitsyfering:** geheime, gebruikersrekords, interne lêers, gespreksdata of prompt-/konteksinhoud word via ’n waarneembare kanaal uitgelek.
- **Ongemagtigde aksie:** die agent gebruik wettige skryfnutsmiddels vir die aanvaller se doel.
- **Diensweiering:** vernietigende nutsmiddels of herhaalde duur bewerkings beïnvloed integriteit of beskikbaarheid.
- **Volharding:** vergiftigde geheue, geïndekseerde inhoud, vertroude toestand of looptydveranderinge bly bestaan nadat die sessie of bron wat dit veroorsaak het, verby is of verwyder is.
- **Verspreiding:** ’n vertroude eweknie gebruik die gekompromitteerde agent se boodskap of gedeelde toestand en herhaal die aksie met sy eie nutsmiddels en geloofsbriewe.

Die erns moet bepaal word deur die bereikbare data, effektiewe voorregte, uitbuitbaarheid van die sink, uitgaande verkeer, volharding en verspreiding—nie deur hoe verrassend die model se teks lyk nie.<sup>[[2]](#references)</sup>

## Kontroles om tydens die assessering te valideer

Promptfilters en ’n beter stelselprompt kan die aanvaller se koste verhoog, maar moet nie as magtigingsgrense beskou word nie. Valideer die kontroles hieronder deur dieselfde ketting weer uit te voer via direkte invoer, indirekte inhoud, geheue, nutsmiddels en eweknie-agente:<sup>[[2]](#references)</sup>

- ’n Deterministiese beleidslaag kontroleer die geverifieerde gebruiker, tenant, objek, aksie en bestemming by **elke aanroeping van ’n nutsmiddel**; die model kan nie die aanroeperidentiteit verskaf of oorskryf nie.
- Lees- en skryftoegang gebruik afsonderlike, minstevoorreg- en kortlewende geloofsbriewe; nutsmiddels met groot impak word net betyds beskikbaar gestel en word nooit outomaties uitgevoer op grond van ingeneemde inhoud nie.
- Netwerkuitgaande verkeer en interne bestemmings word onafhanklik van modelgekose URL’s op toelaatlyste geplaas; toegang tydens uitvoering tot metadata-eindpunte, gemonteerde geheime en naburige dienste word geblokkeer, tensy dit nodig is.
- Die goedkeurings-UI word gegenereer uit die kanonieke gestruktureerde versoek en wys die presiese argumente, identiteit, bestemming, geraakte objekte en newe-effekte—nie ’n vryvorm-opsomming deur die model nie.
- Sukses word in die bestemmingstelsel of rekordstelsel bevestig. Die agent se beskrywing, ’n versoek om ’n nutsmiddel aan te roep of ’n HTTP-herleiding is nie bewys van die beweerde toestandverandering nie.
- Geheue- en herwinninginskrywings behou herkoms en vertrouensetikette, kan ongeldig gemaak word en word weer gemagtig wanneer dit vir ’n latere aksie gebruik word.
- Boodskappe tussen agente word geverifieer en gemagtig as onbetroubare versoeke; ’n eweknie se reputasie of agentkaart delegeer nie implisiet die ontvanger se nutsmiddels nie.

## References

- [1] [OWASP Top 10 vir agentiese toepassings vir 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Die Hacker's Gids vir aanvalle op AI-agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Hoe moeilik is dit werklik om ’n AI-agent uit sy sandbox te breek?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagente in die SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Bronkode vir LangChain TypeSafe Auto Mode-middleware](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-model se jaggedness: adversariële inhoud](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev as beoordelaar: Hoe vervalste beleid Jev stuur](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
