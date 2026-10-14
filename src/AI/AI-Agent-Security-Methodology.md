# AI Agent-sekuriteitsmetodologie

{{#include ../banners/hacktricks-training.md}}

'n Agent-assessering behoort **aanvaller-beheerde invoer tot 'n ekstern waarneembare effek** te volg. Jailbreaking, karakterveranderinge en bekendmaking van die system prompt bewys dat 'n redenasiekanaal beïnvloedbaar is, maar die bevinding met die grootste impak is die ketting na datatoegang, 'n ongemagtigde tool-aksie, 'n downstream injection sink, volharding of 'n ander agent.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is nuttig om dekking te benoem (doelwitkapings, tool-misbruik, voorregmisbruik, voorsieningsketting, kode-uitvoering, geheuevergiftiging, vertroue tussen agents, kaskadefoute, menslike vertroue en rogue agents). Gebruik dié benamings nadat jy 'n end-tot-end-aanvalspad saamgestel het, eerder as om 'n model se onverwagte teks as die einde van die toets te beskou.<sup>[[1]](#references)[[2]](#references)</sup>

## Bou die teikenkaart

Teken hierdie vyf dimensies vir elke agent-werkvloei aan voordat jy payloads skryf:<sup>[[2]](#references)</sup>

| Dimensie | Wat om te lys | Sekuriteitsvraag |
|---|---|---|
| **Onvertroude invoer** | Chat/API-parameters, URLs, dokumente, e-pos, kaartjies, kalenderinskrywings, opgehaalde teksdele, geheue, tool-resultate en boodskappe van peer agents | Waar kan 'n aanvaller inhoud plaas wat later die model se konteks binnegaan? |
| **Tools** | Tool-name en -skemas, newe-effekte, outomatiese uitvoering, bevestigingsgedrag en dinamies gelaaide tools | Watter oproepe lees geheime, skryf toestand, stuur boodskappe, vee data uit, voer kode uit of dra waarde oor? |
| **Gesag** | Gebruikersdelegering, diensrekeninge, API-tokens, geldigheidsduur van geloofsbriewe, tenant-/hulpbronbestek en netwerkbereik | As watter identiteit loop elke oproep, en word magtiging by die tool-grens herhaal? |
| **Verwerking** | Query-bouers, shells, URL-fetchers, template-enjins, interpreters, parsers, lêerbewerkings en deserialiseerders | Waar word modelgegenereerde data sintaksis vir 'n ander interpreter? |
| **Uitvoer** | Antwoorde, gerenderde Markdown/HTML, skakels, beeld-fetches, webhooks, e-pos, lêers, logs, verslae, metrieke en peer-agent-verkeer | Watter waarneembare kanaal kan 'n geheim dra of 'n sekondêre versoek aktiveer? |

Moenie dit reduseer tot 'n lys van geadverteerde integrasies nie. 'n Nuttige artefak karteer elke bron na die presiese konteksposisie wat dit bereik, die tools wat op daardie punt beskikbaar is, die geloofsbrief wat elke tool gebruik, die downstream interpreter en elke egress-roete. Dieselfde tool kan lae impak hê met 'n lees-token per gebruiker, maar kritieke impak met 'n gedeelde administrateur-geloofsbrief.<sup>[[2]](#references)</sup>

## Verkenning

### Karteer elke aflewerings- en innamepad

Begin by die afleweringsoppervlak (web, selfoon, API, e-pos, chat-platform, browser extension) en onderskep die verkeer tussen die kliënt en backend. Inspekteer velde wat deur die UI versteek word, search/autocomplete/filter-parameters, gesprekstoestand-objekte, oplaai- en indekseringstake, tool-antwoorde en sub-agent-verkeer. Slegs-selfoonkliënte kan 'n emulator en instrumentation vereis om certificate pinning te omseil voordat die werklike versoekskema sigbaar word.<sup>[[2]](#references)</sup>

Karteer dan die stack onder die model: orchestration framework, prompt-samestelling, retrieval- en geheuestores, runtime (byvoorbeeld Python, container of WASM), gemonteerde volumes, gasheerdienste, interne APIs, bereikbaarheid van cloud metadata en naburige netwerke. Framework-verstekwaardes is belangrik omdat sommige “tool calls” geïmplementeer word deur kode te genereer of te evalueer; die runtime/sandbox-grens bepaal of die resultaat ingeperk bly.<sup>[[2]](#references)</sup>

### Identifiseer roetering met nie-destruktiewe probes

Vergelyk 'n versoek binne omvang met verskeie onverwante versoeke, terwyl jy die volledige antwoord, statuskode, latency en streaming-gedrag behou. 'n Stabiele verwerping voordat enige taakspesifieke redenering plaasvind, kan op 'n aparte gateway/classifier dui; 'n kontekstuele weiering dui daarop dat die versoek die model bereik het; 'n leë of suiwer ekstraktiewe antwoord kan op keyword search of beperkte retrieval dui. Behandel dit as hipoteses en bevestig dit deur dieselfde probe via alternatiewe API-velde en innamepaaie weer te speel.<sup>[[2]](#references)</sup>

Verkenning is voltooi wanneer die assessering die vroegste aanvaller-beheerde bron kan benoem wat agentgedrag verander **en** die tools, identiteite, interpreters en uitvoere kan identifiseer wat vanaf daardie bron bereikbaar is.<sup>[[2]](#references)</sup>

## Exploitasie: kruis 'n vertrouensgrens

Toets kanale, nie net prompt-bewoording nie. Begin met direkte injection om vas te stel wat die sigbare toegangspunt blokkeer, en herhaal dan ekwivalente bedoeling via die minder sigbare paaie hieronder:<sup>[[2]](#references)</sup>

- **Indirekte inhoud:** bladsye, lêers, e-pos, kaartjies, metadata, alt-teks, HTML-opmerkings, teks buite die skerm of zero-width-karakters. Sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) vir payload-afleweringstegnieke.
- **Retrieval en geheue:** vergiftig inhoud wat later opgehaal sal word, of toestand wat in latere sessies herlaai sal word. Teken aan of die verwydering van die oorspronklike bron die gedrag laat verdwyn.
- **Tool-uitvoer en peer agents:** plaas die merker in 'n tool-antwoord of agent-tot-agent-boodskap om te toets of interne verkeer filters omseil wat net op gebruikersinvoer en finale uitvoer toegepas word.
- **Voorsieningsketting:** beoordeel tool-descriptors, plugins, gekoppelde servers, skills, models en dependencies as vertroude instruksiebronne. Sien [MCP Servers](AI-MCP-Servers.md#mcp-vulns) vir MCP-spesifieke toetse.
- **Menslike goedkeuring:** vergelyk die werklike gestruktureerde tool-oproep met die modelgegenereerde goedkeuringsteks. Toets of aanvallerinvloed die bestemming, bestek, geraakte objekte of onomkeerbare newe-effekte kan weglaat.

Gebruik eers 'n skadelose, unieke merker. Bewaar die bronartefak, saamgestelde konteks indien waarneembaar, geselekteerde tool-oproep, goedkeuringsdata, backend-versoek/-antwoord en finale toestand. Dit onderskei invloed van 'n gehallusineerde bewering dat 'n aksie plaasgevind het.<sup>[[2]](#references)</sup>

### Subagent-konteksisolasie

'n Nie-fork Claude Agent SDK-subagent ontvang sy eie `AgentDefinition.prompt`, die delegeringsprompt en sy beskikbare tools, maar nie die ouer se system prompt of gesprek nie. As `tools` uit sy definisie weggelaat word, erf dit die tools wat vir subagents beskikbaar is; projek-`CLAUDE.md` kan steeds gelaai word. Dit maak 'n beperking wat net in die ouer se prompt voorkom, 'n onbetroubare grens wanneer die kind dieselfde lêerstelsel- of uitvoerings-tools kan gebruik.<sup>[[4]](#references)</sup>

Toets die grens deur 'n direkte versoek wat die ouer weier, te vergelyk met dieselfde taak wat aan 'n benoemde subagent gedelegeer word. NCC Group berig dat 'n geweierde enumerasie van bedryfstelsellêers suksesvol was toe dit vir 'n kind as 'n onskadelike "layout map" herformuleer is.<sup>[[3]](#references)</sup>

Inspekteer die kind se werklike tool-oproepe en effektiewe tool-allowlist, nie net die ouer se finale antwoord nie; bevestig of die kind toegang verkry het tot lêers waartoe die ouer nie toegang sou hê nie.<sup>[[4]](#references)</sup> Dit is 'n mislukking in die oorerwing van guardrails, nie bewys van 'n [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) of container-ontsnapping nie.<sup>[[3]](#references)[[4]](#references)</sup>

## Uitvoering: bewys werklike impak

Daar is twee afsonderlike roetes van invloed na impak:<sup>[[2]](#references)</sup>

1. **Misbruik van vermoëns:** die gemagtigde tool voer reeds die doelwit uit. Voorbeelde sluit in die lees van een tenant se rekord en die skryf daarvan na 'n verslag wat vir 'n aanvaller sigbaar is, die stuur van e-pos, die verandering van rekords, die uitvee van 'n lêer of die inisieer van 'n betaling. Geen sekondêre sagtewarekwesbaarheid word vereis nie.
2. **Uitbuiting van 'n downstream sink:** aanvaller-gestuurde modeluitvoer word sintaksis vir 'n ander komponent. Gaan databas navrae na vir [SQL injection](../pentesting-web/sql-injection/README.md) of [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers na vir [command injection](../pentesting-web/command-injection.md), gekose URLs na vir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), lêerbewerkings na vir traversal, template-/kode-evalueerders na vir RCE, en objekparsers na vir [unsafe deserialization](../pentesting-web/deserialization/README.md).

Bewys vir elke kandidaat hierdie ketting:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

’n Leesalleen-integrasie is steeds uitbuitbaar wanneer enige latere komponent kan publiseer wat dit gelees het. Toets gewone antwoorde sowel as minder voor die hand liggende egress, soos aanvaller-beheerde skakels, outomatiese beeldophaling, webhooks, logs, verslae, tellers, kennisgewings en boodskappe aan ander agente.<sup>[[2]](#references)</sup>

## Aksies op doelwitte

Nadat jy een aksie bevestig het, evalueer die volledige impakgebied eerder as om by die eerste sigbare uitwerking te stop:<sup>[[2]](#references)</sup>

- **Data-eksfiltrasie:** geheime, gebruikerrekords, interne lêers, gespreksdata of prompt-/konteksinhoud verlaat die stelsel deur ’n waarneembare kanaal.
- **Ongemagtigde aksie:** die agent gebruik wettige skryfbevoegdhede om die aanvaller se doel te bereik.
- **Diensweiering:** vernietigende nutsmiddels of herhaalde duur bewerkings beïnvloed integriteit of beskikbaarheid.
- **Volharding:** vergiftigde geheue, geïndekseerde inhoud, vertroude toestand of runtime-veranderinge oorleef die oorspronklike sessie of die verwydering van die bron.
- **Verspreiding:** ’n vertroude eweknie verwerk die gekompromitteerde agent se boodskap of gedeelde toestand en herhaal die aksie met sy eie nutsmiddels en geloofsbriewe.

Erns behoort te berus op bereikbare data, effektiewe voorregte, sink-uitbuitbaarheid, egress, volharding en verspreiding—nie op hoe verrassend die model se teks lyk nie.<sup>[[2]](#references)</sup>

## Kontroles om tydens die assessering te valideer

Prompt-filters en ’n beter system prompt kan die aanvaller se koste verhoog, maar moet nie as magtigingsgrense beskou word nie. Valideer die kontroles hieronder deur dieselfde ketting weer uit te voer via direkte invoer, indirekte inhoud, geheue, nutsmiddels en eweknie-agente:<sup>[[2]](#references)</sup>

- ’n Deterministiese beleidslaag kontroleer die geverifieerde gebruiker, tenant, objek, aksie en bestemming by **elke nutsmiddel-aanroep**; die model kan nie die oproeper se identiteit verskaf of oorskryf nie.
- Lees- en skryfbevoegdhede gebruik afsonderlike, minimaal bevoorregte geloofsbriewe met ’n kort geldigheidstyd; hoë-impaknutsmiddels word net betyds beskikbaar gestel en voer nooit outomaties uit op grond van ingeneemde inhoud nie.
- Netwerk-egress en interne bestemmings word onafhanklik van modelgekose URL’s geallowlys; runtime-toegang tot metadata-eindpunte, gemonteerde geheime en naburige dienste word geblokkeer tensy dit nodig is.
- Die goedkeuringskoppelvlak word uit die kanonieke gestruktureerde versoek gegenereer en wys presiese argumente, identiteit, bestemming, geraakte objekte en newe-effekte—nie ’n vryvorm-opsomming deur die model nie.
- Sukses word by die bestemmingstelsel of die stelsel van rekord geverifieer. Die agent se beskrywing, ’n nutsmiddel-aanvraag of ’n HTTP-herleiding is nie bewys van die beweerde toestandsverandering nie.
- Geheue- en herwinningsinskrywings behou herkoms- en vertrouensetikette, kan ongeldig verklaar word en word weer gemagtig wanneer dit vir ’n latere aksie gebruik word.
- Boodskappe tussen agente word as ongeverifieerde versoeke geverifieer en gemagtig; ’n eweknie se reputasie of agentkaart delegeer nie implisiet die ontvanger se nutsmiddels nie.

## References

- [1] [OWASP Top 10 vir Agentiese Toepassings vir 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Die Hacker se Gids vir Aanvalle op AI-agente](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Hoe Moeilik Is Dit Werklik om ’n AI-agent uit Sy Sandbox te Breek?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Subagente in die SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
