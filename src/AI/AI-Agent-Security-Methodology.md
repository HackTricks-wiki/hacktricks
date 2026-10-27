# AI Agent-sekuriteitsmetodologie

{{#include ../banners/hacktricks-training.md}}

’n Agent-assessering behoort **aanvaller-beheerde invoer na ’n ekstern waarneembare uitwerking** te volg. Jailbreaking, karakterveranderinge en bekendmaking van die system prompt bewys dat ’n redenasiekanaal beïnvloedbaar is, maar die bevinding met die grootste impak is die ketting na datatoegang, ’n ongemagtigde tool-aksie, ’n downstream injection-sink, volharding of ’n ander agent.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is nuttig om dekking te benoem (doelwitkaap, misbruik van tools, voorregmisbruik, voorsieningsketting, kode-uitvoering, geheuevergiftiging, inter-agent-vertroue, kaskadefoute, menslike vertroue en skelm-agente). Gebruik dié etikette nadat jy ’n end-tot-end-aanvalsroete saamgestel het, eerder as om ’n model se onverwagte teks as die einde van die toets te beskou.<sup>[[1]](#references)[[2]](#references)</sup>

## Stel die teikenkaart saam

Teken hierdie vyf dimensies vir elke agent-werkvloei aan voordat jy payloads skryf:<sup>[[2]](#references)</sup>

| Dimensie | Wat om te inventariseer | Sekuriteitsvraag |
|---|---|---|
| **Onvertroude invoer** | Chat/API-parameters, URL’s, dokumente, e-pos, kaartjies, kalenderinskrywings, opgespoorde stukke, geheue, tool-resultate en eweknie-agentboodskappe | Waar kan ’n aanvaller inhoud plaas wat later die model se konteks binnegaan? |
| **Tools** | Tool-name en skemas, newe-effekte, outomatiese uitvoering, bevestigingsgedrag en dinamies gelaaide tools | Watter oproepe lees geheime, skryf data, stuur boodskappe, vee data uit, voer kode uit of dra waarde oor? |
| **Gesag** | Gebruikersdelegering, diensrekeninge, API-tokens, geloofsbriewe se leeftyd, tenant-/hulpbronomvang en netwerkbereik | As watter identiteit word elke oproep uitgevoer, en word magtiging by die tool-grens herhaal? |
| **Verwerking** | Query-bouers, shells, URL-fetchers, template-enjins, interpreteerders, parsers, lêerbewerkings en deserialiseerders | Waar word modelgegenereerde data sintaksis vir ’n ander interpreteerder? |
| **Uitvoer** | Antwoorde, gerenderde Markdown/HTML, skakels, beeld-fetches, webhooks, e-pos, lêers, logs, verslae, maatstawwe en eweknie-agentverkeer | Watter waarneembare kanaal kan ’n geheim dra of ’n sekondêre versoek aktiveer? |

Moenie dit reduseer tot ’n lys van geadverteerde integrasies nie. ’n Nuttige artefak karteer elke bron na die presiese konteksposisie wat dit bereik, die tools wat op daardie punt beskikbaar is, die geloofsbrief wat elke tool gebruik, die downstream-interpreteerder en elke egress-roete. Dieselfde tool kan ’n lae impak hê met ’n lees-token per gebruiker en kritiek wees met ’n gedeelde administrateurgeloofsbrief.<sup>[[2]](#references)</sup>

## Verkenning

### Karteer elke aflewerings- en innamepad

Begin by die afleweringsoppervlak (web, mobiel, API, e-pos, chat-platform, blaaieruitbreiding) en proxy die kliënt-na-backend-verkeer. Ondersoek velde wat deur die UI versteek word, soek-/outovoltooi-/filterparameters, gesprekstoestand-objekte, oplaai- en indekseringstake, tool-antwoorde en subagent-verkeer. Slegs-mobiele kliënte kan ’n emulator en instrumentering vereis om certificate pinning te omseil voordat die werklike versoekskema sigbaar word.<sup>[[2]](#references)</sup>

Karteer vervolgens die stack onder die model: orkestrasieraamwerk, prompt-samestelling, herwinning- en geheuestore, runtime (byvoorbeeld Python, container of WASM), gemonteerde volumes, gasheerdienste, interne API’s, bereikbaarheid van cloud-metadata en naburige netwerke. Raamwerkstandaarde maak saak omdat sommige “tool calls” geïmplementeer word deur kode te genereer of te evalueer; die runtime-/sandbox-grens bepaal of die resultaat beperk bly.<sup>[[2]](#references)</sup>

### Bepaal roetering met nie-vernietigende probes

Vergelyk ’n versoek binne die omvang met verskeie onverwante versoeke, terwyl jy die volledige antwoord, statuskode, latency en streaming-gedrag behou. ’n Stabiele weiering voordat enige taakspesifieke redenasie plaasvind, kan op ’n aparte gateway/classifier dui; ’n kontekstuele weiering dui daarop dat die versoek die model bereik het; ’n leë of suiwer ekstraktiewe antwoord kan op sleutelwoordsoektog of beperkte herwinning dui. Behandel dit as hipoteses en bevestig dit deur dieselfde probe via alternatiewe API-velde en innamepaaie te herhaal.<sup>[[2]](#references)</sup>

Verkenning is voltooi wanneer die assessering die vroegste aanvaller-beheerde bron kan benoem wat agentgedrag verander **en** die tools, identiteite, interpreteerders en uitsette wat vanaf daardie bron bereikbaar is.<sup>[[2]](#references)</sup>

## Exploitasie: oorbrug ’n vertrouensgrens

Toets kanale, nie net prompt-bewoording nie. Begin met direkte injection om vas te stel wat die sigbare voordeur blokkeer, en herhaal dan ’n ekwivalente bedoeling deur die minder sigbare paaie hieronder:<sup>[[2]](#references)</sup>

- **Indirekte inhoud:** bladsye, lêers, e-pos, kaartjies, metadata, alt-teks, HTML-kommentaar, teks buite die skerm of zero-width-karakters. Sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) vir tegnieke om payloads af te lewer.
- **Herwinning en geheue:** vergiftig inhoud wat later herwin sal word, of toestand wat in latere sessies herlaai sal word. Teken aan of die gedrag verdwyn wanneer die oorspronklike bron uitgevee word.
- **Tool-uitvoer en eweknie-agente:** plaas die merker in ’n tool-antwoord of agent-na-agent-boodskap om te toets of interne verkeer filters omseil wat slegs op gebruikersinvoer en finale uitvoer toegepas word.
- **Voorsieningsketting:** beoordeel tool-deskriptors, plugins, gekoppelde bedieners, skills, modelle en afhanklikhede as vertroude instruksiebronne. Vir MCP-spesifieke toetse, sien [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Menslike goedkeuring:** vergelyk die werklike gestruktureerde tool-oproep met die modelgegenereerde goedkeuringsteks. Toets of aanvallerinvloed die bestemming, omvang, geaffekteerde objekte of onomkeerbare newe-effekte kan weglaat.

Gebruik eers ’n onskadelike, unieke merker. Bewaar die bronartefak, saamgestelde konteks indien waarneembaar, geselekteerde tool-oproep, goedkeuringsdata, backend-versoek/antwoord en finale toestand. Dit onderskei beïnvloeding van ’n gehallusineerde bewering dat ’n aksie plaasgevind het.<sup>[[2]](#references)</sup>

### Beleidsvormige teks in ’n tool-risikobeoordelaar

’n Modelgebaseerde tool-gateway kan aanvaller-beheerde teks binne andersins nuttige klassifikasiekonteks ontvang. LangChain se eksperimentele `AutoModeMiddleware` stuur byvoorbeeld ’n voorgestelde tool-oproep, sy argumente, ’n opsionele tool-beskrywing en tot 30 onlangse boodskappe na ’n TypeSafe `is_risky`-beoordelaar. Dit blokkeer gekonfigureerde tools wanneer die teruggekeerde Noul-waarskynlikheid minstens `0.5` is; tools wat nie gelys is nie, word nie deur hierdie middleware geklassifiseer nie.<sup>[[5]](#references)</sup> TypeSafe waarsku ook dat adversariële teks in toestand ’n klassifikasie kan beïnvloed, selfs wanneer die toestand bedoel is om data te wees.<sup>[[6]](#references)</sup>

’n **Vervalste beleid** verskil daarvan om bloot voor te gee dat ’n boodskap ’n system message is. Dit plaas alternatiewe etikette of risikodefinisies binne laer-vertroue toestand en moedig die beoordelaar aan om dié definisies te gebruik in plaas van die kriteria wat die ontwikkelaar gedefinieer het. In Datadog se toets is ’n gebruikerbewerkbare `profile_description` saam met `can_edit:false` na die tool-argumente gekopieer. Die beleidagtige teks het aangevoer dat ’n skryfpoging lae risiko inhou omdat ’n aparte toestemmingkontrole dit sou verwerp voordat enige verandering plaasvind. Oor 40 lopies het die gemiddelde `is_risky`-telling van `0.893` tot `0.290` gedaal, terwyl ’n direkte rol-vervalsing-vergelyking gemiddeld `0.905` behaal het. Dat die gemiddelde onder `0.5` val, bewys nie dat elke individuele oproep die gateway geslaag het nie, en die eksperiment het **nie** ’n voltooide ongemagtigde skryfbewerking gedemonstreer nie.<sup>[[7]](#references)</sup>

Wanneer jy hierdie grens toets, onderskei die classifier se uitspraak van die tool se werklike magtigingsresultaat. Gaan na watter bewerkbare velde die beoordelaar bereik, vergelyk dieselfde voorgestelde aksie met en sonder beleidagtige teks, en verifieer die finale toestand onafhanklik. ’n Aparte toestemmingkontrole moet steeds die geverifieerde versoeker se gesag gebruik, nie die connector se diensrekeningregte nie.<sup>[[7]](#references)</sup> Sien [prompt-filter-omseilings](AI-Prompts.md#prompt-waf-bypass) vir ander classifier-foutmodusse; [LLM-gateway-vertrouensgrense](AI-LLM-Gateway-Security.md) handel oor ’n ander roeterings- en geloofsbriefgrens.

### Subagent-konteksisolasie

’n Nie-fork Claude Agent SDK-subagent ontvang sy eie `AgentDefinition.prompt`, die delegeringsprompt en sy beskikbare tools, maar nie die ouer se system prompt of gesprek nie. As `tools` uit sy definisie weggelaat word, erf dit die tools wat vir subagente beskikbaar is; die projek se `CLAUDE.md` kan steeds gelaai word. Dit maak ’n beperking in die ouer se prompt alleen ’n onbetroubare grens wanneer die kind dieselfde lêerstelsel- of uitvoerings-tools kan gebruik.<sup>[[4]](#references)</sup>

Toets die grens deur ’n direkte versoek wat die ouer weier te vergelyk met dieselfde taak wat aan ’n benoemde subagent gedelegeer word. NCC Group berig dat ’n weiering om lêers van die bedryfstelsel te inventariseer, geslaag het toe dit vir ’n kind herformuleer is as ’n onskadelike “uitlegkaart”.<sup>[[3]](#references)</sup>

Ondersoek die kind se werklike tool-oproepe en effektiewe tool-toelatingslys, nie net die ouer se finale antwoord nie; bevestig of die kind toegang verkry het tot lêers waartoe die ouer nie toegang sou verkry het nie.<sup>[[4]](#references)</sup> Dit is ’n mislukking in guardrail-erwing, nie bewys van ’n [Python-sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) of container-ontsnapping nie.<sup>[[3]](#references)[[4]](#references)</sup>

### Mobiele GUI-agente: skerminstruksies en aksieherbinding

’n Telefoon-GUI-agent kan elke skermskoot na ’n cloud-model stuur voordat dit die volgende kruis-app-aksie kies. Om **indirekte visuele injection** te toets, plaas aanvaller-beheerde teks in ’n SMS, e-pos of bladsy wat die agent tydens ’n gemagtigde taak sal ondersoek. Vergelyk ’n direkte taakprompt met dieselfde instruksie wat slegs in die skermskoot sigbaar is, en ondersoek dan die volgende aksie en enige besluit oor ’n hoërisiko-bewerking. In die geassesseerde assistent het die kliëntkant-`checkPrompt` direkte taaktekste gekeur, maar nie ekwivalente filtering op skermskootinhoud toegepas nie. Dit is ’n mobiele kruis-app-variant van [agentic-browser-skermskoot-injection](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), nie ’n manier om Android-komponentverifikasie te omseil nie.<sup>[[9]](#references)</sup>

’n Illustratiewe newe-effektoets gebruik ’n aanvaller-beheerde vorm wat die agent vra om sensitiewe velde in te vul en dan ’n menslike klik op “upload” vra, terwyl die bladsy die ingevulde velde indien sodra hulle verander. Die menslike oorhandiging kan nie data beskerm wat reeds deur bladsykode gestuur is nie; verifieer die werklike indiening eerder as om die agent se beskrywing as bewys te beskou. Die bron stel dit voor as ’n moontlike patroon, nie as ’n gedemonstreerde kompromittering van elke assistent nie.<sup>[[9]](#references)</sup>

**GUI TOCTOU / aksieherbinding** is ’n afsonderlike foutmodus: die agent beplan ’n invoer op grond van ’n skerm wat by `t0` waargeneem is, maar die voorgrond-UI verander voordat die invoer by `t1` ingespuit word.<sup>[[8]](#references)</sup> ’n Latere skermskoot by `t2` kan nie ’n aksie wat reeds uitgevoer is, ongedaan maak nie.<sup>[[9]](#references)</sup> In ’n gemagtigde Android-toets is die herbruikbare werkvloei:<sup>[[8]](#references)</sup>

1. Profileer die teikenkontrole se skermkoördinate en vertoon ’n onskadelike kontrole op dieselfde plek in ’n beheerde app.
2. Hou dié draer sigbaar totdat die agent dit waarneem, en aktiveer dan ’n normale voorgrondoorgang gedurende die gaping tussen waarneming en aksie.
3. Kyk of die beplande tik op die nuwe app se kontrole beland en verifieer die gevolglike toestand in die teiken-app, eerder as om op die agent se beskrywing staat te maak.

Die oorspronklike aksieherbindingstudie demonstreer dit met ’n app wat geen gevaarlike toestemmings het nie; dit beskryf ook hoe om die oorgang deur die agent se taakherstel-lus te herhaal vir meerstap-vloeie.<sup>[[8]](#references)</sup>

**Moenie** aanvaar dat die primitief onveranderd teen elke assistent werk nie. In die Doubao-assessering het `OpClickUI` klikke oorgeslaan as die topvlak-Activity verander het en skermskote vergelyk wanneer `OpOpenApp` in die voorafgaande drie stappe verskyn het. Enkele tikke, langdrukke en dubbeltikke het daarom min betroubare aanvaller-beheerde tydsberekening gebied. `OpTypeText`, `OpSwipeUI` en `OpScrollWheelAction` het nie ekwivalente beveiligingsmaatreëls gehad nie, maar die verslag het hul praktiese impak as meer beperk beoordeel.<sup>[[9]](#references)</sup>

## Uitvoering: bewys werklike impak

Daar is twee afsonderlike roetes van beïnvloeding na impak:<sup>[[2]](#references)</sup>

1. **Misbruik van vermoëns:** die gemagtigde tool voer reeds die doelwit uit. Voorbeelde sluit in om een tenant se rekord te lees en dit na ’n aanvaller-sigbare verslag te skryf, e-pos te stuur, rekords te verander, ’n lêer uit te vee of ’n betaling te begin. Geen sekondêre sagtewarefout is nodig nie.
2. **Exploitasie van downstream-sinks:** aanvaller-gestuurde modeluitvoer word sintaksis vir ’n ander komponent. Ondersoek databasisnavrae vir [SQL-injection](../pentesting-web/sql-injection/README.md) of [NoSQL-injection](../pentesting-web/nosql-injection.md), shell-wrappers vir [command injection](../pentesting-web/command-injection.md), gekose URL’s vir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), lêerbewerkings vir traversal, template-/kode-evalueerders vir RCE en objekparsers vir [unsafe deserialization](../pentesting-web/deserialization/README.md).

Bewys vir elke kandidaat hierdie ketting:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

’n Leesalleen-integrasie kan steeds uitgebuit word wanneer enige latere komponent dit wat gelees is, kan publiseer. Toets gewone response sowel as minder ooglopende egress, soos aanvallerbeheerde skakels, outomatiese beeldherwinning, webhooks, logs, verslae, tellers, kennisgewings en boodskappe aan ander agente.<sup>[[2]](#references)</sup>

## Aksies op doelwitte

Nadat een aksie bevestig is, evalueer die volledige omvang van die impak eerder as om by die eerste sigbare effek te stop:<sup>[[2]](#references)</sup>

- **Exfiltration:** geheime, gebruikersrekords, interne lêers, gesprekdata of prompt-/konteksinhoud verlaat die stelsel deur ’n waarneembare kanaal.
- **Unauthorized action:** die agent gebruik wettige skryfvermoëns om die aanvaller se doelwit te bereik.
- **Denial of service:** vernietigende nutsmiddels of herhaalde duur bewerkings beïnvloed integriteit of beskikbaarheid.
- **Persistence:** vergiftigde geheue, geïndekseerde inhoud, vertroude toestand of runtime-veranderinge bly behoue nadat die oorspronklike sessie of bron verwyder is.
- **Propagation:** ’n vertroude eweknie verbruik die gekompromitteerde agent se boodskap of gedeelde toestand en herhaal die aksie met sy eie nutsmiddels en geloofsbriewe.

Erns moet bepaal word deur bereikbare data, effektiewe voorregte, sink-uitbuitbaarheid, egress, persistence en propagation—nie deur hoe verrassend die model se teks voorkom nie.<sup>[[2]](#references)</sup>

## Kontroles om tydens die assessering te valideer

Prompt-filters en ’n beter system prompt kan die aanvaller se koste verhoog, maar moet nie as magtigingsgrense beskou word nie. Valideer die kontroles hieronder deur dieselfde ketting weer uit te voer met direkte invoer, indirekte inhoud, geheue, nutsmiddels en eweknie-agente:<sup>[[2]](#references)</sup>

- ’n Deterministiese beleidslaag kontroleer die geverifieerde gebruiker, tenant, objek, aksie en bestemming by **elke nutsmiddel-aanroep**; die model kan nie die oproeper se identiteit verskaf of oorskryf nie.
- Lees- en skryfvermoëns gebruik afsonderlike, minimaal bevoorregte, kortlewende geloofsbriewe; nutsmiddels met ’n groot impak word net betyds beskikbaar gestel en voer nooit outomaties aksies uit op grond van ingeneemde inhoud nie.
- Netwerk-egress en interne bestemmings word onafhanklik van modelgekose URL’s toegelaat; runtime-toegang tot metadata-eindpunte, gemonteerde geheime en naburige dienste word geblokkeer tensy dit nodig is.
- Die goedkeurings-UI word uit die kanonieke gestruktureerde versoek gegenereer en toon presiese argumente, identiteit, bestemming, geraakte objekte en newe-effekte—nie ’n vryvorm-modelopsomming nie.
- Sukses word vanaf die bestemmingstelsel of stelsel van rekord geverifieer. Agentvertelling, ’n nutsmiddeloproepversoek of ’n HTTP-aanstuur is nie bewys van die beweerde toestandverandering nie.
- Geheue- en herwinningsinskrywings behou herkoms- en vertrouensetikette, kan ongeldig gemaak word en word weer gemagtig wanneer dit vir ’n latere aksie gebruik word.
- Boodskappe tussen agente word geverifieer en gemagtig as onvertroude versoeke; ’n eweknie se reputasie of agentkaart delegeer nie implisiet die ontvanger se nutsmiddels nie.

Vir A2A-agentkaarte, taakvloeie en hul aanvalsoppervlak, raadpleeg [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [OWASP Top 10 vir Agentic Applications vir 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Die Hacker se gids vir die aanval op AI-agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Hoe moeilik is dit werklik om ’n AI-agent uit sy sandbox te laat ontsnap?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagente in die SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Bronkode vir LangChain TypeSafe Auto Mode-middleware](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [TypeSafe AI Jev-model se oneweredigheid: teenstrydige inhoud](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev as ’n beoordelaar: Hoe vervalste beleid Jev stuur](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulasie sonder toestemmings: Kan ons groot multimodale model-aangedrewe GUI-agente vertrou?](https://arxiv.org/html/2601.12349v1)
- [9] [Wanneer ’n AI-assistent deel word van die Hacker se aanvalsketting | Sekuriteitsontleding van Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
