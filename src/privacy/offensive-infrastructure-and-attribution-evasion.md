# Aanvallende Infrastruktuur en Toeskrywingsontwyking

'n Operateur verkry selde betekenisvolle anonimiteit van 'n enkele proxy. Werklike veldtogte bou 'n **skeidingsgrafiek**: die operateur bereik 'n toegangsnodus, deurkruisingsnodusse verberg daardie nodus van die uitgangspunt, redirectors beskerm die werklike C2, en weggooibare name wys na die publieke rand.

Gebruik die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) vir 'n genormaliseerde oorsig van die voordele/nadele, ontplooiing en opsporing van elke pad. Hierdie bladsy gaan dieper in op die samestelling van teenstanders se infrastruktuur.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Die laaste address wat deur ’n target gesien word, is dus bewys van ’n pad, nie bewys van wie die keyboard beheer het nie. MITRE koppel die hoofkomponente aan Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) en Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastruktuurklasse

| Klas | Waarom ’n actor dit gebruik | Duursame blootstelling | Beste pivot vir die verdediger |
|---|---|---|---|
| Gehuurde VPS/cloud | Vinnig, voorspelbaar, routeerbaar en maklik om te herbou | tenant-, billing-, console-, source-login- en image-geskiedenis | account/control-plane-events en herhaalde server fingerprint |
| Commercial VPN/Tor | Groot gedeelde egress-stel; geen serveradministrasie nie | provider/guard-sigbaarheid en end-to-end-timing | destination behavior, endpoint-bewyse en flow-korrelasie |
| Residential/mobile proxy | Consumer ASN en geografiese geloofwaardigheid | broker/customer-rekords; proxyware- of infected-host-gedrag | impossible travel, proxy-protokolle en address churn per session |
| Compromised server/router/IoT | Leen die victim se reputation en jurisdiction | implant, management flow en herhaalde upstream controller | device telemetry en ORB-topologie, nie een exit IP nie |
| CDN/redirector | Skei public edge van back-end C2 | TLS/HTTP-grammatika, certificate, routing en cloud-account-artefakte | edge-to-origin-korrelasie en request-shape-clustering |
| Legitimate web service | Meng met toegelate GitHub/cloud/social-verkeer | API-token, tenant/object-identifiers en ongewone process lineage | endpoint-process plus service/API-semantics |
| Fisiese/cellular/satellite-pad | Verander die skynbare fisiese oorsprong | RF-, carrier-, subscriber-, device- en location-rekords | radio/fisiese en netwerkbewyse gekombineer |

## Operational relay box-netwerke

’n **ORB network** is ’n bestuurde proxy-vloot wat as ’n intermediêre diens gebruik word. Mandiant verdeel hulle in provisioned networks van gehuurde servers, non-provisioned networks van compromised routers/IoT, en hybrids. ’n Volwasse topologie het vier logiese rolle:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** onderhou inventory, credentials, health en routing policy.
2. **Access/relay node:** authenticate customers of operators; dit is die stabiele ingang na ’n veranderende mesh.
3. **Traversal nodes:** een of meer gehuurde of compromised systems relay opaque connections.
4. **Exit/staging node:** bied die finale source address aan reconnaissance-, exploitation- of C2-targets.

Die mesh kan exits volgens country, ASN, latency of availability kies en unhealthy nodes roteer. Verskeie threat groups kan dieselfde network huur. Mandiant het waargeneem dat ’n IPv4-address vir so min as 31 dae met sommige ORBs geassosieer gebly het; dit beveel dus aan dat die **network as ’n ontwikkelende actor-agtige entiteit** behandel word, eerder as om ’n verouderde lys IPs te blokkeer.<sup>[[2]](#references)</sup>

### Wat dit bied—en wat dit leak

- Die target sien ’n exit wat geografies naby en oënskynlik residential kan wees.
- Die exit sien die target en die voorafgaande hop, nie noodwendig die operator nie.
- Die access service sien die customer en die route request. ’n Onafhanklik bestuurde mesh kan die customer van die exits geskei hou, maar dit skep ’n kragtige teenpartyrekord.
- Herhaalde ports, handshake order, server banners, certificates, uptime windows en controller relationships kan die fleet blootlê selfs terwyl IPs roteer.
- ’n Compromised router het dikwels nie endpoint telemetry nie, maar sy ISP het steeds subscriber- en flow-data; ’n beslaglegging stel implant/configuration-artefakte bloot.

{% hint style="info" %}
Vir ’n gemagtigde oefening, reproduseer die topologie met organisasie-besitte VMs of routers en hou die controller se attribution map. Moenie open proxies of third-party devices werf nie. Die [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) skep dieselfde defender-sigbare hop-struktuur sonder om ’n intermediary te viktimiseer.
{% endhint %}

## Residential en mobile proxy-netwerke

Residential proxy-dienste ken sessions aan consumer broadband-addresses toe; mobile proxies egress deur carrier NAT-pools. Die aanbod kan afkomstig wees van uitdruklik ingeskrewe appliances, SDK/proxyware wat in consumer applications ingebou is, resellers of malware. Hierdie oorspronge is nie ekwivalent nie: ’n gebrek aan ingeligte consent verander ’n privacy-diens in compromised infrastructure.

Rotation modes beïnvloed detection:

- **per-request rotation** produseer vinnige IP- en ASN/geography-diskontinuïteite terwyl higher-layer identity stabiel bly;
- **sticky sessions** hou ’n exit vir minute of ure, wat soos ’n gewone subscriber lyk;
- **backconnect gateways** stel een broker endpoint aan die customer bloot en kies exits intern;
- **mobile pools** plaas baie genuine subscribers agter ’n klein stel carrier NAT-addresses, wat ’n IP-block duur maak.

Defenders moet die IP met authenticated session, TLS/client fingerprint, HTTP-ordering, device cookie en behavior korreleer. ’n Vermoedelik plaaslike residential-login wat deur ’n ander country gevolg word terwyl al die higher-layer features identies bly, is sterker as reputation alleen. Omgekeerd veroorsaak address sharing en mobile handoff legitieme churn, dus moet residential/proxy-classification nooit as ’n verdict behandel word nie.

## Multi-hop proxy-kettings

MITRE onderskei external proxies van **multi-hop proxies (T1090.003)**. Die belangrike eienskap is nie die aantal hops nie, maar die skeiding van kennis en administrasie.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
As een party A en B bedryf, kan gedeelde logs of die tydsberekening van verkeersvloei die circuit rekonstrueer. Die byvoeging van opeenvolgende kommersiële VPNs vanaf dieselfde endpoint/account kan latency verhoog, terwyl dit steeds gemeenskaplike identiteits-, betalings- en tydsberekeningsbewyse laat. Tor verminder hierdie probleem met onafhanklik geselekteerde relays en ’n gedeelde client-ontwerp, maar ’n lae-latency interaktiewe netwerk kan nie weerstand belowe teen ’n waarnemer wat albei kante meet nie.

Algemene mislukkings is DNS- of IPv6-omseiling, toepassings wat hul eie sockets open, management-verkeer wat relays direk bereik, gesinchroniseerde aktiwiteit, hergebruikte SSH keys, en aanmelding by identifiseerbare accounts. Die korrekte verifikasie is ’n fouttoets: stop elke relay om die beurt en toon dat die workload nie na ’n onbeskermde pad kan terugval nie.

## Redirector-lae en verkeersvorming

’n Publieke **redirector** aanvaar verkeer wat by ’n operasie-spesifieke grammar pas en stuur dit aan na ’n beskermde team server. Enigiets anders kan verwerp word of onskadelike inhoud bedien word.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Veelvuldige vlakke beperk blootstelling: die afbrand van 'n publieke domain hoef nie die span se server bloot te stel nie. CDNs voeg anycast-kapasiteit en 'n gerespekteerde outer domain by, maar die CDN-account en edge logs word attribution-punte. TLS-fingerprints, certificate histories, kenmerkende paths/header-order, response-groottes, redirect-gedrag en origin-allowlists kan sogenaamd onverwante fronts saam groepeer.

Vir detection, teken reverse-proxy-velde aan voordat normalisering plaasvind, vergelyk SNI/Host/authority, ondersoek seldsame header-kombinasies, groepeer response bodies en TLS-fingerprints, en soek cloud/CDN audit logs vir configuration-overlap. Vir gemagtigde red teams, vermy dit om 'n werklike brand na te boots of credential collection agter 'n onverwante third party te plaas.

## Domain fronting and domainless fronting

Met klassieke **domain fronting (T1090.004)** adverteer die TLS-verbinding 'n toegelate front domain in SNI, terwyl die encrypted HTTP `Host` of HTTP/2 `:authority` 'n ander back-end domain versoek. 'n Samewerkende CDN routeer op grond van die innerlike waarde. 'n Network observer sonder TLS-decryption sien die front; die CDN sien albei waardes en die origin. In domainless-variante kan SNI leeg wees, terwyl 'n ander routing field die bestemming kies.<sup>[[4]](#references)</sup>

Dit is nie magiese impersonation nie: dit werk slegs wanneer die intermediary die mismatch opsetlik of per ongeluk toelaat en weet hoe om die innerlike naam te routeer. Groot providers het cross-account fronting beperk. Encrypted ClientHello (ECH) verander wat 'n on-path observer kan sien, maar verwyder nie CDN-, endpoint- of application-records nie.

Detection-punte sluit in:

- endpoint process ancestry en 'n destination wat nie vir daardie application verwag word nie;
- SNI teenoor HTTP-authority mismatch waar TLS-inspection wettig en beskikbaar is;
- CDN-logs wat wys dat een tenant/front na 'n ander authority/origin routeer;
- ongewone langlewende of periodieke sessions na 'n diens wat normaalweg interaktief is;
- stabiele encrypted flow-groottes en cadence oor veranderende front domains.

Die veilige lab simuleer die routing-mismatch op 'n reverse proxy wat besit word; dit misbruik nie 'n publieke CDN nie.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution ontkoppel 'n logiese diens van vaste infrastructure:

- **DDNS:** 'n authenticated client werk 'n stabiele naam op nadat sy address verander.
- **DGA:** beide endpoint en controller lei candidate domain names van 'n time/key seed af; die operator registreer 'n klein subset.
- **Fast flux:** 'n naam gee 'n vinnig veranderende stel compromised/proxy addresses terug, dikwels met lae TTLs.
- **Double flux:** beide service addresses en authoritative name-server addresses roteer, wat die control layer ook verberg.

Fast flux is 'n load-distribution pattern wat adversarial gebruik word, nie bloot “many DNS answers” nie. Sterker evidence kombineer lae TTL, 'n hoë unique-address count, wye ASN/geography-dispersie, kort node lifetime, herhaalde application behavior en verdagte registration history. CDNs deel verskeie van hierdie eienskappe wettiglik. MITRE beveel aan dat DNS-gedrag met die process en daaropvolgende connections gekorreleer word.<sup>[[5]](#references)</sup>

'n DGA kan deur lexical entropy, consonant/digit patterns, NXDOMAIN-bursts, synchronized first-seen domains en process context opgespoor word. Wordlist-DGAs en generative models omseil eenvoudige entropy-reëls, wat fleet-wide temporal clustering en endpoint lineage belangriker maak.

## Compromised domains and domain shadowing

'n Actor kan 'n registrar/DNS-account kaap, 'n dangling subdomain oorneem, of records onder 'n andersins gerespekteerde domain byvoeg. **Domain shadowing** behou die legitimate apex terwyl groot getalle attacker-controlled subdomains na veranderende delivery- of C2-hosts wys. Dit benut ouderdom en reputation en kan domain-wide blocking ontduik.<sup>[[6]](#references)</sup>

Defenders benodig registrar- en authoritative-DNS-audit logs, MFA, registry/registrar locks, alerts vir nuwe delegations/API tokens/name servers, certificate-transparency monitoring, en 'n inventory van cloud resources waarna DNS verwys. Ondersoek 'n subdomain se resolution- en certificate history onafhanklik van die apex se reputation.

## Web services and dead-drop resolvers

'n **dead-drop resolver (T1102.001)** stoor 'n encoded pointer na huidige C2 binne 'n legitimate post, profile, document, repository, cloud object of blockchain field. Malware haal die public object, decodeer 'n domain/IP en kontak die volgende stage. Bidirectional variants ruil commands of files deur service APIs uit.<sup>[[7]](#references)</sup>

Dit bied resilience en verberg back-end C2 teenoor static binary analysis. Dit skep ook stabiele object-, tenant-, repository-, API- en access-pattern-identifiers. Defenders behoort die volgende te koppel:

1. die process wat die service gekontak het;
2. presiese API path/object en response hash;
3. decoding- of string-processing-aktiwiteit;
4. die nuwe outbound connection kort daarna; en
5. identiese behavior elders in die fleet.

Om alle GitHub, cloud storage of social media te blokkeer, is selde lewensvatbaar. Service-aware egress policy en process-level correlation presteer beter as domain-only blocking.

## Personas, accounts and procurement compartments

Infrastructure anonymity misluk wanneer 'n persona, recovery email, phone, payment, browser of admin IP compartments verbind. State-linked operations het social profiles, email identities en cloud accounts lank voor gebruik opgebou; ATT&CK teken dit aan as Establish Accounts (T1585), insluitend social-, email- en cloud-subtechniques.<sup>[[8]](#references)</sup>

'n Defender of investigator bou 'n graph uit:

- creation- en first-login-tyd, locale, time zone en working schedule;
- recovery fields, MFA-devices, identity documents en payment instruments;
- browser/TLS-fingerprints en source-network history;
- avatar reuse, image provenance, writing style en social-graph growth;
- gedeelde domain registrant, name server, certificate, analytics ID of repository commit;
- management-plane actions wat die publieke relay-architecture omseil.

Vir 'n gemagtigde red team moet synthetic personas aan die exercise controller gedokumenteer word, organization-owned recovery/payment channels gebruik, impersonation van werklike onverwante mense vermy, en 'n beplande retirement hê. Die SOC mag blind bly; die operation mag nie onaccountable word nie.

## Emerging compound patterns to threat-model

Die volgende is **defender-driven compositions**, nie bewerings dat 'n genoemde actor elke presiese design ontplooi het nie. Hulle kombineer primitives wat reeds waargeneem is en is nuttige purple-team hypotheses.

### Asymmetric one-way tasking

Commands arriveer deur 'n public, broadcast- of append-only source, terwyl results ná 'n vertraging deur 'n onverwante channel uitgaan. Voorbeelde van die primitive sluit web-service one-way communication en dead drops in. Separation voorkom dat 'n enkele flow bidirectional lyk en bemoeilik eenvoudige request/response-correlation.<sup>[[9]](#references)</sup>

**Detection:** behou object-level reads, en korreleer daarna process state changes en latere outbound transfers oor 'n wyer window. Hunt vir 'n seldsame process wat dieselfde public object lees, selfs wanneer geen onmiddellike reply volg nie.

### Multi-stage channel promotion

'n Stil eerste stage doen inventory en promoteer slegs geselekteerde systems na 'n onverwante second-stage channel. Die tweede endpoint, protocol en process deel moontlik geen infrastructure met die eerste nie. Dit beperk blootstelling van capable infrastructure en word uitdruklik as ATT&CK T1104 gemodelleer.<sup>[[10]](#references)</sup>

**Detection:** koppel `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; moenie die incident afsluit nadat die eerste domain geblokkeer is nie.

### Cross-protocol relay translation

Verskillende hops vertaal HTTPS, QUIC, WebSocket, DNS, SSH of 'n message-queue API eerder as om packets deursigtig aan te stuur. Translation verwyder 'n enkele end-to-end protocol fingerprint, maar skep gateways met kenmerkende timing, buffering en semantic conversion. Protocol tunneling (T1572) kan met proxies en service impersonation gekombineer word.<sup>[[11]](#references)</sup>

**Detection:** soek gateway hosts wat een protocol ontvang en 'n ander een begin, met nou gekoppelde byte/time behavior; vergelyk endpoint intent met die protocol wat werklik gedra word.

### Passive activation on edge devices

In plaas daarvan om te beacon, monitor 'n implant traffic wat reeds 'n router/VPN bereik en aktiveer slegs op 'n magic value, source-port pattern of authenticated token. Normal traffic gaan voort na die werklike diens. ATT&CK noem dit Traffic Signaling (T1205), met gedokumenteerde network-device- en APT-voorbeelde.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture tydens 'n gemagtigde hunt, onverwagte socket filters en differential service behavior. Die afwesigheid van 'n periodieke beacon bewys nie dat 'n edge device skoon is nie.

### Serverless and ephemeral origin rotation

'n Front behou 'n stabiele logiese identity terwyl kortlewende functions/containers individuele stages in verskeie regions/accounts hanteer. Dit verminder disk lifetime en vaste origin IPs, maar control-plane creation, image/layer, role, secret, request ID en billing telemetry word die duursame graph.

**Detection:** behou cloud audit- en invocation-logs buite die workload; groepeer deployment templates, roles, environment keys en front-to-origin relationships.

### Privacy-layer diversity

'n Operation kan doelbewus een homogene chain vermy: byvoorbeeld, een channel gebruik 'n leased relay, tasking gebruik 'n public object, 'n exit kom van 'n owned lab cellular link, en administration gebruik 'n aparte organization network. Dit verminder die waarde daarvan om een provider te kompromitteer, maar verhoog cross-layer timing- en operational-error-risiko.

**Detection:** bou campaign timelines oor identity-, DNS-, SaaS-, network- en cloud-sensors. Soek synchronized state transitions eerder as identiese indicators.

### Decentralized or transparency-log dead drops

'n Actor kan 'n klein encrypted pointer in enige durable public append-only system, content-addressed store of transparency-like feed plaas. Die public object is resilient, maar sy presiese index/content hash en die client se polling behavior word stabiele identifiers.

**Detection:** teken volledige API/object-identifiers en response hashes aan; alert op nonstandard processes wat immutable objects poll, gevolg deur decoding of nuwe connections.

### Delayed store-and-forward operations

Interactive C2 skep sterk timing-correlation. 'n Store-and-forward design bondel encrypted jobs en stuur results minute of ure later deur 'n ander queue of physical transfer terug. Dit offer responsiveness op vir swakker end-to-end timing.

**Detection:** verleng correlation windows, model periodic queue access en ondersoek endpoint staging. Batching verskuif die signal van packet timing na scheduled process/file behavior; dit verwyder dit nie.

## Design review: think in observers

Vir elke path, vul hierdie tabel voor deployment en ná collection in:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

As een ordinary provider elke kolom kan invul, bied die architecture concealment teenoor die target, maar nie robuuste separation nie. As geen interne controller activity na 'n engagement kan terugkarteer nie, is dit ongeskik vir professionele red teaming.

## References

- [1] [MITRE ATT&CK — Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), and Proxy (T1090)](https://attack.mitre.org/techniques/T1584/)
- [2] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [3] [MITRE ATT&CK — Multi-hop Proxy (T1090.003)](https://attack.mitre.org/techniques/T1090/003/)
- [4] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [5] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [6] [MITRE ATT&CK — Compromise Infrastructure: Domains (T1584.001)](https://attack.mitre.org/techniques/T1584/001/)
- [7] [MITRE ATT&CK — Web Service: Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [8] [MITRE ATT&CK — Establish Accounts (T1585)](https://attack.mitre.org/techniques/T1585/)
- [9] [MITRE ATT&CK — Web Service: One-Way Communication (T1102.003)](https://attack.mitre.org/techniques/T1102/003/)
- [10] [MITRE ATT&CK — Multi-Stage Channels (T1104)](https://attack.mitre.org/techniques/T1104/)
- [11] [MITRE ATT&CK — Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [12] [MITRE ATT&CK — Traffic Signaling (T1205)](https://attack.mitre.org/techniques/T1205/)
