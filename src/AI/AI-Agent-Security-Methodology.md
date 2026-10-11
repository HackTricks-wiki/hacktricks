# AI Agent-sekuriteitsmetodologie

{{#include ../banners/hacktricks-training.md}}

’n Agent-assessering behoort **’n aanvaller-beheerde invoer na ’n ekstern waarneembare effek** te volg. Jailbreaking, karakterveranderings en openbaarmaking van system prompts bewys dat ’n redeneerkanaal beïnvloed kan word, maar die bevinding met die grootste impak is die ketting na datatoegang, ’n ongemagtigde tool-aksie, ’n downstream injection sink, volharding of ’n ander agent.<sup>[[2]](#references)</sup>

Die [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) is nuttig om dekking te benoem (goal hijacking, tool misuse, privilege abuse, supply chain, code execution, memory poisoning, inter-agent trust, cascading failures, human trust en rogue agents). Gebruik daardie benamings nadat jy ’n end-to-end-aanvalspad saamgestel het, eerder as om ’n model se onverwagte teks as die einde van die toets te beskou.<sup>[[1]](#references)[[2]](#references)</sup>

## Bou die teikenkaart

Teken hierdie vyf dimensies vir elke agent-werkvloei aan voordat jy payloads skryf:<sup>[[2]](#references)</sup>

| Dimensie | Wat om te inventariseer | Sekuriteitsvraag |
|---|---|---|
| **Onbetroubare invoer** | Chat/API-parameters, URLs, dokumente, e-pos, tickets, kalenderinskrywings, opgehaalde brokkies, geheue, tool-resultate en boodskappe van ander agents | Waar kan ’n aanvaller inhoud plaas wat later die model se konteks binnegaan? |
| **Tools** | Tool-name en -skemas, newe-effekte, outo-uitvoering, bevestigingsgedrag en dinamies gelaaide tools | Watter oproepe lees geheime, skryf toestand, stuur boodskappe, vee data uit, voer kode uit of dra waarde oor? |
| **Gesag** | Gebruikersdelegering, diensrekeninge, API-tokens, geloofsbriewe se leeftyd, huurder-/hulpbronbestek en netwerkbereik | As watter identiteit word elke oproep uitgevoer, en word magtiging by die tool-grens herhaal? |
| **Verwerking** | Query-bouers, shells, URL-fetchers, template engines, interpreters, parsers, lêerbewerkings en deserializers | Waar word modelgegenereerde data sintaksis vir ’n ander interpreter? |
| **Uitvoer** | Antwoorde, weergegewe Markdown/HTML, skakels, beeldfetches, webhooks, e-pos, lêers, logs, verslae, metrics en verkeer tussen agents | Watter waarneembare kanaal kan ’n geheim dra of ’n sekondêre versoek aktiveer? |

Moenie dit reduseer tot ’n lys van geadverteerde integrasies nie. ’n Nuttige artefak karteer elke bron na die presiese posisie in die konteks wat dit bereik, die tools wat op daardie punt beskikbaar is, die geloofsbrief wat elke tool gebruik, die downstream-interpreter en elke egress-roete. Dieselfde tool kan lae impak hê met ’n leestoegangstoken per gebruiker, maar kritieke impak met ’n gedeelde administrateurgeloofsbrief.<sup>[[2]](#references)</sup>

## Verkenning

### Karteer elke aflewerings- en innamepad

Begin by die afleweringsoppervlak (web, mobiel, API, e-pos, chat-platform, blaaieruitbreiding) en ondersoek die verkeer tussen die kliënt en backend met ’n proxy. Inspekteer velde wat deur die UI versteek word, soek-/outovoltooi-/filterparameters, gesprekstoestandobjekte, oplaai- en indekseringstake, tool-antwoorde en sub-agent-verkeer. Slegs-mobiele kliënte kan ’n emulator en instrumentasie vereis om certificate pinning te omseil voordat die werklike versoekskema sigbaar word.<sup>[[2]](#references)</sup>

Karteer vervolgens die stack onder die model: orkestreringsraamwerk, prompt-samestelling, retrieval- en geheuestores, runtime (byvoorbeeld Python, container of WASM), gemonteerde volumes, gasheerdienste, interne APIs, bereikbaarheid van cloud metadata en naburige netwerke. Raamwerkverstekwaardes is belangrik, want sommige “tool calls” word geïmplementeer deur kode te genereer of te evalueer; die runtime-/sandbox-grens bepaal of die resultaat beperk bly.<sup>[[2]](#references)</sup>

### Vingerafdruk-roetering met nie-vernietigende probes

Vergelyk ’n versoek binne die bestek met verskeie onverwante versoeke, terwyl die volledige antwoord, statuskode, latency en streaminggedrag behoue bly. ’n Stabiele verwerping voordat enige taakspesifieke redenering plaasvind, kan op ’n aparte gateway/classifier dui; ’n kontekstuele weiering dui daarop dat die versoek die model bereik het; ’n leë of suiwer ekstraktiewe antwoord kan op keyword search of beperkte retrieval dui. Behandel dit as hipoteses en bevestig dit deur dieselfde probe via alternatiewe API-velde en innamepaaie weer te speel.<sup>[[2]](#references)</sup>

Verkenning is voltooi wanneer die assessering die vroegste aanvaller-beheerde bron kan benoem wat agentgedrag verander **én** die tools, identiteite, interpreters en uitvoere wat vanaf daardie bron bereikbaar is.<sup>[[2]](#references)</sup>

## Uitbuiting: steek ’n vertrouensgrens oor

Toets kanale, nie net prompt-bewoording nie. Begin met direkte injection om vas te stel wat die sigbare voordeur blokkeer, en herhaal dan ekwivalente bedoeling via die minder sigbare paaie hieronder:<sup>[[2]](#references)</sup>

- **Indirekte inhoud:** bladsye, lêers, e-pos, tickets, metadata, alt-teks, HTML-kommentaar, teks buite die skerm of zero-width characters. Sien [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) vir payload-afleweringstegnieke.
- **Retrieval en geheue:** vergiftig inhoud wat later opgehaal sal word, of toestand wat in latere sessies herlaai sal word. Teken aan of die uitvee van die oorspronklike bron die gedrag verwyder.
- **Tool-uitvoer en ander agents:** plaas die merker in ’n tool-antwoord of ’n agent-tot-agent-boodskap om te toets of interne verkeer filters omseil wat slegs op gebruikersinvoer en finale uitvoer toegepas word.
- **Supply chain:** ondersoek tool-beskrywings, plugins, gekoppelde servers, skills, models en dependencies as vertroude instruksiebronne. Sien [MCP Servers](AI-MCP-Servers.md#mcp-vulns) vir MCP-spesifieke toetse.
- **Menslike goedkeuring:** vergelyk die werklike gestruktureerde tool-oproep met die modelgegenereerde goedkeuringsteks. Toets of aanvallerinvloed die bestemming, bestek, geraakte objekte of onomkeerbare newe-effekte kan weglaat.

Gebruik eers ’n onskadelike, unieke merker. Bewaar die bronartefak, saamgestelde konteks indien dit waarneembaar is, geselekteerde tool-oproep, goedkeuringsdata, backend-versoek/-antwoord en finale toestand. Só kan jy invloed onderskei van ’n hallusinasie dat ’n aksie plaasgevind het.<sup>[[2]](#references)</sup>

## Uitvoering: bewys werklike impak

Daar is twee afsonderlike roetes van invloed na impak:<sup>[[2]](#references)</sup>

1. **Misbruik van vermoëns:** die gemagtigde tool voer reeds die doel uit. Voorbeelde sluit in die lees van een huurder se rekord en die skryf daarvan na ’n verslag wat vir ’n aanvaller sigbaar is, die stuur van e-pos, die verandering van rekords, die uitvee van ’n lêer of die inisieer van ’n betaling. Geen sekondêre sagtewarekwesbaarheid word vereis nie.
2. **Uitbuiting van downstream sinks:** aanvaller-gestuurde modeluitvoer word sintaksis vir ’n ander komponent. Ondersoek database queries vir [SQL injection](../pentesting-web/sql-injection/README.md) of [NoSQL injection](../pentesting-web/nosql-injection.md), shell wrappers vir [command injection](../pentesting-web/command-injection.md), gekose URLs vir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), lêerbewerkings vir traversal, template-/code-evaluators vir RCE en objekparsers vir [unsafe deserialization](../pentesting-web/deserialization/README.md).

Bewys hierdie ketting vir elke kandidaat:<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

’n Leesalleen-integrasie is steeds uitbuitbaar wanneer enige latere komponent dit wat dit gelees het, kan publiseer. Toets gewone response sowel as minder ooglopende egress, soos skakels wat deur ’n aanvaller beheer word, outomatiese beeldherwinning, webhooks, logs, verslae, tellers, kennisgewings en boodskappe aan ander agents.<sup>[[2]](#references)</sup>

## Aksies op doelwitte

Nadat een aksie bevestig is, evalueer die volledige impakradius eerder as om by die eerste sigbare effek te stop:<sup>[[2]](#references)</sup>

- **Exfiltration:** geheime, gebruikersrekords, interne lêers, gesprekdata of prompt-/konteksinhoud verlaat die stelsel via ’n waarneembare kanaal.
- **Ongemagtigde aksie:** die agent gebruik wettige skryfvermoëns om die aanvaller se doel te bereik.
- **Denial of service:** vernietigende tools of herhaalde, duur bewerkings beïnvloed integriteit of beskikbaarheid.
- **Persistence:** vergiftigde geheue, geïndekseerde inhoud, vertroude toestand of runtime-veranderinge bly bestaan nadat die oorspronklike sessie of bron verwyder is.
- **Propagation:** ’n vertroude eweknie verwerk die gekompromitteerde agent se boodskap of gedeelde toestand en herhaal die aksie met sy eie tools en credentials.

Erns behoort bepaal te word deur bereikbare data, effektiewe voorregte, sink-uitbuitbaarheid, egress, persistence en propagation—nie deur hoe verrassend die model se teks lyk nie.<sup>[[2]](#references)</sup>

## Kontroles om tydens die assessering te valideer

Prompt filters en ’n beter system prompt kan die aanvaller se koste verhoog, maar moet nie as magtigingsgrense beskou word nie. Valideer die kontroles hieronder deur dieselfde ketting weer deur direkte invoer, indirekte inhoud, geheue, tools en eweknie-agents te laat loop:<sup>[[2]](#references)</sup>

- ’n Deterministiese beleidslaag kontroleer die geverifieerde gebruiker, tenant, objek, aksie en bestemming by **elke tool-aanroep**; die model kan nie die oproeper se identiteit verskaf of oorheers nie.
- Lees- en skryfvermoëns gebruik afsonderlike, minstevoorreg-, kortlewende credentials; tools met groot impak word net betyds beskikbaar gestel en voer nooit outomaties inhoud uit wat ingeneem is nie.
- Netwerk-egress en interne bestemmings word onafhanklik van modelgeselekteerde URL’s geallowlys; runtime-toegang tot metadata-endpoints, gemonteerde geheime en naburige dienste word geblokkeer tensy dit nodig is.
- Die goedkeurings-UI word uit die kanonieke gestruktureerde versoek gegenereer en toon die presiese argumente, identiteit, bestemming, geraakte objekte en newe-effekte—nie ’n vryvorm-modelopsomming nie.
- Sukses word by die bestemmingstelsel of stelsel van rekord geverifieer. Die agent se vertelling, ’n tool-aanroepversoek of ’n HTTP-redirect is nie bewys van die beweerde toestandsverandering nie.
- Geheue- en herwinningsinskrywings behou herkoms- en vertrouensetikette, kan ongeldig gemaak word en word weer gemagtig wanneer dit vir ’n latere aksie gebruik word.
- Boodskappe tussen agents word geverifieer en gemagtig as onvertroude versoeke; ’n eweknie se reputasie of agentkaart delegeer nie implisiet die ontvanger se tools nie.

## References

- [1] [OWASP Top 10 vir Agentic Applications vir 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Die Hacker se gids vir die aanval op AI-agents](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
