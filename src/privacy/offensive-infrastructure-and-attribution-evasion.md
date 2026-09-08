# Aanstootlike Infrastruktuur en Toeskrywingontduiking

{{#include ../banners/hacktricks-training.md}}

’n Operator verkry selde betekenisvolle anonimiteit van ’n enkele proxy. Werklike veldtogte bou ’n **skeidingsgrafiek**: die operator bereik ’n toegangnodus, traversa nodusse versteek daardie nodus vir die uitgang, redirectors beskerm die werklike C2, en weggooibare name wys na die publieke rand.

Gebruik die [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) vir ’n genormaliseerde oorsig van die voordele/nadele, ontplooiing en opsporing van elke pad. Hierdie bladsy gaan dieper in op die samestelling van adversariële infrastruktuur.
```text
operator -> access relay -> traversal mesh -> exit/redirector -> target
|                 |                |
account/provider   relay operator   target telemetry
```
Die laaste adres wat deur 'n teiken gesien word, is dus bewys van 'n pad, nie bewys van wie die sleutelbord beheer het nie. MITRE koppel die belangrikste komponente aan Acquire Infrastructure (T1583), Compromise Infrastructure (T1584), Proxy (T1090), Dynamic Resolution (T1568) en Web Service (T1102).<sup>[[1]](#references)</sup>

## Infrastructure classes

| Klas | Waarom 'n actor dit gebruik | Duursame blootstelling | Verdediger se beste pivots |
|---|---|---|---|
| Gehuurde VPS/cloud | Vinnig, voorspelbaar, routeerbaar en maklik om herbou te word | huurder-, fakturering-, console-, source-login- en image-geskiedenis | account/control-plane-gebeurtenisse en herhaalde server fingerprint |
| Commercial VPN/Tor | Groot gedeelde egress-stel; geen serveradministrasie nie | provider/guard-sigbaarheid en end-to-end-tydsberekening | bestemminggedrag, endpoint-bewyse en flow-korrelasie |
| Residential/mobile proxy | Consumer ASN en geografiese geloofwaardigheid | broker-/kliënterekords; proxyware- of infected-host-gedrag | onmoontlike reis, proxy-protokolle en adreswisseling per sessie |
| Compromised server/router/IoT | Leen die slagoffer se reputasie en jurisdiksie | implant, management flow en herhaalde upstream controller | device telemetry en ORB-topologie, nie een exit IP nie |
| CDN/redirector | Skei publieke edge van back-end C2 | TLS/HTTP-grammatika, certificate, routing- en cloud-account-artefakte | edge-to-origin-korrelasie en groepering volgens request-shape |
| Legitimate web service | Meng met toegelate GitHub/cloud/social-verkeer | API-token, tenant/object-identifiers en ongewone process lineage | endpoint-process plus service/API-semantiek |
| Physical/cellular/satellite path | Verander die oënskynlike fisiese oorsprong | RF-, carrier-, subscriber-, device- en location-rekords | radio/fisiese en netwerkbewyse gekombineer |

## Operational relay box networks

'n **ORB network** is 'n bestuurde proxy-vloot wat as 'n intermediêre diens gebruik word. Mandiant verdeel hulle in provisioned networks van gehuurde servers, non-provisioned networks van compromised routers/IoT, en hybrids. 'n Volwasse topologie het vier logiese rolle:<sup>[[2]](#references)</sup>

1. **Administration server (ACOS):** handhaaf inventory, credentials, health en routing policy.
2. **Access/relay node:** autentiseer customers of operators; dit is die stabiele toegang tot 'n veranderende mesh.
3. **Traversal nodes:** een of meer gehuurde of compromised systems relay opaque connections.
4. **Exit/staging node:** bied die finale source address aan reconnaissance-, exploitation- of C2-targets.

Die mesh kan exits volgens country, ASN, latency of availability kies en ongesonde nodes roteer. Veelvuldige threat groups kan dieselfde network huur. Mandiant het waargeneem dat 'n IPv4-adres vir so min as 31 dae met sommige ORBs geassosieerd gebly het; daarom beveel dit aan dat die **network as 'n ontwikkelende actor-like entity behandel word**, eerder as om 'n verouderde lys IPs te blokkeer.<sup>[[2]](#references)</sup>

### Wat dit bied — en wat dit lek

- Die target sien 'n exit wat geografies naby en oënskynlik residential kan wees.
- Die exit sien die target en die voorafgaande hop, maar nie noodwendig die operator nie.
- Die access service sien die customer en die route request. 'n Onafhanklik bestuurde mesh kan die customer van die exits geskei hou, maar dit skep 'n kragtige counterparty-record.
- Herhaalde poorte, handshake-volgorde, server banners, certificates, uptime windows en controller relationships kan die vloot blootlê selfs terwyl IPs roteer.
- 'n Compromised router het dikwels nie endpoint telemetry nie, maar sy ISP het steeds subscriber- en flow-data; beslaglegging stel implant-/configuration-artefakte bloot.

{% hint style="info" %}
Vir 'n gemagtigde oefening, reproduseer die topologie met organisasie-besitte VMs of routers en hou die controller se attribution map. Moenie open proxies of third-party devices werf nie. Die [lab guide](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) skep dieselfde defender-visible hop-structure sonder om 'n intermediary te viktimiseer.
{% endhint %}

## Residential and mobile proxy networks

Residential proxy-dienste ken sessies aan consumer broadband-addresses toe; mobile proxies egress deur carrier NAT-pools. Aanbod kan afkomstig wees van uitdruklik ingeskrewe appliances, SDK/proxyware wat in consumer applications gebundel is, resellers of malware. Hierdie origins is nie gelykwaardig nie: 'n gebrek aan ingeligte toestemming verander 'n privacy service in compromised infrastructure.

Rotation modes beïnvloed detection:

- **per-request rotation** veroorsaak vinnige IP- en ASN/geography-diskontinuïteite terwyl die hoërlaag-identiteit stabiel bly;
- **sticky sessions** hou 'n exit vir minute of ure, wat soos 'n gewone subscriber lyk;
- **backconnect gateways** stel een broker endpoint aan die customer bloot en kies exits intern;
- **mobile pools** plaas baie egte subscribers agter 'n klein stel carrier NAT-addresses, wat 'n IP-block duur maak.

Defenders behoort die IP met authenticated session, TLS/client fingerprint, HTTP-ordering, device cookie en gedrag te korreleer. 'n Sogenaamd local residential login wat deur 'n ander country gevolg word terwyl alle hoërlaag-features identies bly, is sterker as reputation alleen. Omgekeerd skep address sharing en mobile handoff wettige churn, dus moet residential/proxy-classification nooit as 'n verdict behandel word nie.

## Multi-hop proxy chains

MITRE onderskei external proxies van **multi-hop proxies (T1090.003)**. Die belangrike eienskap is nie die aantal hops nie, maar die skeiding van kennis en administration.<sup>[[3]](#references)</sup>
```text
operator --encrypted--> entry A --encrypted/relayed--> exit B --> target
sees source                         sees destination
```
As een party A en B bedryf, kan gedeelde logs of vloeitydberekening die circuit rekonstrueer. Deur opeenvolgende kommersiële VPNs vanaf dieselfde endpoint/account by te voeg, kan latency verhoog word terwyl gemeenskaplike identiteit-, betalings- en tydsberekeningbewyse behoue bly. Tor verminder hierdie probleem met onafhanklik geselekteerde relays en ’n gedeelde client-ontwerp, maar ’n interactive netwerk met lae latency kan nie weerstand teen ’n waarnemer belowe wat albei kante meet nie.

Algemene mislukkings is DNS- of IPv6-bypass, toepassings wat hul eie sockets oopmaak, management-verkeer wat relays direk bereik, gesinchroniseerde aktiwiteit, hergebruikte SSH keys en aanmelding by identifiseerbare accounts. Die korrekte verifikasie is ’n failure test: stop elke relay om die beurt en toon dat die workload nie na ’n clear path kan terugval nie.

## Redirector tiers and traffic shaping

’n Publieke **redirector** aanvaar verkeer wat by ’n operasie-spesifieke grammatika pas en stuur dit aan na ’n beskermde team server. Enigiets anders kan verwerp word of onskadelike inhoud bedien word.
```text
implant/browser -> CDN or redirector -> relay -> team server
|
request policy
host + path + method + header + time
```
Veelvuldige vlakke beperk blootstelling: die verbranding van 'n publieke domain hoef nie die spanbediener bloot te stel nie. CDN's voeg anycast-kapasiteit en 'n gerespekteerde buitenste domain by, maar die CDN-rekening en edge-logs word attribution-punte. TLS-fingerprints, sertifikaatgeskiedenisse, kenmerkende paaie/header-volgorde, response-groottes, redirect-gedrag en origin-allowlists kan sogenaamd onverwante fronts groepeer.

Vir opsporing, teken reverse-proxy-velde aan voordat normalisering plaasvind, vergelyk SNI/Host/authority, ondersoek seldsame header-kombinasies, groepeer response-liggame en TLS-fingerprints, en soek in cloud/CDN-audit-logs na konfigurasie-oorvleueling. Vir gemagtigde red teams, vermy die kopiëring van 'n werklike handelsmerk of die plasing van credential collection agter 'n onverwante derde party.

## Domain fronting and domainless fronting

Met klassieke **domain fronting (T1090.004)** adverteer die TLS-verbinding 'n toegelate front domain in SNI, terwyl die geënkripteerde HTTP `Host` of HTTP/2 `:authority` 'n ander back-end domain versoek. 'n Samewerkende CDN roeteer op grond van die innerlike waarde. 'n Netwerkwaarnemer sonder TLS-dekripsie sien die front; die CDN sien beide waardes en die origin. In domainless-variante kan SNI leeg wees terwyl 'n ander routing-veld die bestemming kies.<sup>[[4]](#references)</sup>

Dit is nie magiese impersonation nie: dit werk slegs wanneer die intermediary die mismatch opsetlik of per ongeluk toelaat en weet hoe om die innerlike naam te roeteer. Groot providers het cross-account fronting beperk. Encrypted ClientHello (ECH) verander wat 'n on-path-waarnemer kan sien, maar verwyder nie CDN-, endpoint- of application-rekords nie.

Opsporingspunte sluit in:

- endpoint-proses-ancestry en bestemming wat nie vir daardie application verwag word nie;
- SNI teenoor HTTP-authority-mismatch waar TLS-inspeksie wettig en beskikbaar is;
- CDN-logs wat toon dat een tenant/front na 'n ander authority/origin roeteer;
- ongewone langdurige of periodieke sessies na 'n normaalweg interaktiewe diens;
- stabiele geënkripteerde vloei-groottes en cadence oor veranderende front domains.

Die veilige lab simuleer die routing-mismatch op 'n reverse proxy wat besit word; dit misbruik nie 'n publieke CDN nie.

## Dynamic resolution: DDNS, DGA and fast flux

Dynamic resolution ontkoppel 'n logiese diens van vaste infrastruktuur:

- **DDNS:** 'n geauthentiseerde kliënt werk 'n stabiele naam op nadat sy adres verander.
- **DGA:** beide endpoint en controller lei kandidaat-domainname van 'n tyd/sleutel-seed af; die operator registreer 'n klein subset.
- **Fast flux:** 'n naam gee 'n vinnig veranderende stel gekompromitteerde/proxy-adresse terug, dikwels met lae TTL's.
- **Double flux:** beide diensadresse en authoritative name-server-adresse roteer, wat die control layer ook verberg.

Fast flux is 'n load-distribution-patroon wat adversarial gebruik word, nie bloot “baie DNS-antwoorde” nie. Sterker bewys kombineer lae TTL, 'n hoë aantal unieke adresse, wye ASN/geografie-verspreiding, kort node-leeftyd, herhaalde application-gedrag en verdagte registrasiegeskiedenis. CDN's deel wettiglik verskeie van hierdie eienskappe. MITRE beveel aan dat DNS-gedrag met die proses en daaropvolgende verbindings gekorreleer word.<sup>[[5]](#references)</sup>

'n DGA kan deur lexical entropy, konsonant/syfer-patrone, NXDOMAIN-uitbarstings, gesinchroniseerde first-seen domains en proses-konteks opgespoor word. Wordlist-DGA's en generative models verslaan eenvoudige entropy-reëls, wat vlootwye temporale groepering en endpoint-lineage belangriker maak.

## Compromised domains and domain shadowing

'n Actor kan 'n registrar/DNS-rekening kaap, 'n dangling subdomain oorneem, of rekords onder 'n andersins gerespekteerde domain byvoeg. **Domain shadowing** behou die legitieme apex terwyl groot getalle attacker-beheerde subdomains na veranderende delivery- of C2-hosts wys. Dit leen ouderdom en reputasie en kan domain-wide blocking omseil.<sup>[[6]](#references)</sup>

Defenders benodig registrar- en authoritative-DNS-audit-logs, MFA, registry/registrar-locks, alerts vir nuwe delegations/API-tokens/name servers, certificate-transparency-monitering, en 'n inventaris van cloud-resources waarna DNS verwys. Ondersoek 'n subdomain se resolution- en certificate history onafhanklik van die apex se reputasie.

## Web services and dead-drop resolvers

'n **dead-drop resolver (T1102.001)** stoor 'n geënkodeerde pointer na huidige C2 binne 'n legitieme post, profiel, dokument, repository, cloud object of blockchain-veld. Malware haal die publieke object op, decodeer 'n domain/IP en kontak die volgende stage. Bidirectional-variante ruil commands of files deur service API's uit.<sup>[[7]](#references)</sup>

Dit bied resilience en verberg back-end C2 vir statiese binary analysis. Dit skep ook stabiele object-, tenant-, repository-, API- en access-pattern-identifiers. Defenders behoort die volgende te koppel:

1. die proses wat die diens gekontak het;
2. presiese API-pad/object en response-hash;
3. decoding- of string-processing-aktiwiteit;
4. die nuwe outbound connection kort daarna; en
5. identiese gedrag elders in die vloot.

Om alle GitHub, cloud storage of social media te blokkeer, is selde uitvoerbaar. Service-aware egress policy en process-level correlation presteer beter as domain-only blocking.

## Personas, accounts and procurement compartments

Infrastructure anonymity faal wanneer 'n persona, recovery email, phone, payment, browser of admin IP compartments verbind. State-linked operations het social profiles, email identities en cloud accounts lank voor gebruik opgebou; ATT&CK teken dit aan as Establish Accounts (T1585), insluitend social-, email- en cloud-subtechniques.<sup>[[8]](#references)</sup>

'n Defender of investigator bou 'n graph vanaf:

- creation- en first-login-tyd, locale, time zone en werkskedule;
- recovery fields, MFA-devices, identity documents en payment instruments;
- browser/TLS-fingerprints en source-network history;
- avatar-hergebruik, beeldprovenance, writing style en social-graph-groei;
- gedeelde domain registrant, name server, certificate, analytics ID of repository commit;
- management-plane actions wat die publieke relay-architecture omseil.

Vir 'n gemagtigde red team behoort synthetic personas aan die exercise controller gedokumenteer te word, organization-owned recovery/payment channels te gebruik, impersonation van werklike onverwante mense te vermy, en 'n beplande retirement te hê. Die SOC mag blind bly; die operasie mag nie onaccountable word nie.

## Emerging compound patterns to threat-model

Die volgende is **defender-driven compositions**, nie bewerings dat 'n genoemde actor elke presiese ontwerp ontplooi het nie. Hulle kombineer reeds waargenome primitives en is nuttige purple-team-hipoteses.

### Asymmetric one-way tasking

Commands arriveer deur 'n publieke, broadcast- of append-only-bron, terwyl results na 'n vertraging deur 'n onverwante kanaal uitgaan. Voorbeelde van die primitive sluit web-service one-way communication en dead drops in. Skeiding verhoed dat 'n enkele flow bidirectional lyk en bemoeilik eenvoudige request/response-correlation.<sup>[[9]](#references)</sup>

**Detection:** behou object-level reads, en korreleer dan process state changes en latere outbound transfers oor 'n breër venster. Hunt vir 'n seldsame proses wat dieselfde publieke object lees, selfs wanneer geen onmiddellike reply volg nie.

### Multi-stage channel promotion

'n Stil eerste stage voer inventory uit en promoveer slegs geselekteerde systems na 'n onverwante second-stage channel. Die tweede endpoint, protocol en proses mag geen infrastruktuur met die eerste deel nie. Dit beperk blootstelling van capable infrastructure en word uitdruklik as ATT&CK T1104 gemodelleer.<sup>[[10]](#references)</sup>

**Detection:** koppel `first network process -> downloaded/configured state -> new process or injection -> unrelated destination`; moenie die incident afsluit nadat die eerste domain geblokkeer is nie.

### Cross-protocol relay translation

Verskillende hops vertaal HTTPS, QUIC, WebSocket, DNS, SSH of 'n message-queue API eerder as om packets deursigtig aan te stuur. Translation verwyder 'n enkele end-to-end protocol fingerprint, maar skep gateways met kenmerkende timing, buffering en semantic conversion. Protocol tunneling (T1572) kan met proxies en service impersonation gekombineer word.<sup>[[11]](#references)</sup>

**Detection:** soek gateway-hosts wat een protocol ontvang en 'n ander begin, met nou gekoppelde byte/time-gedrag; vergelyk endpoint-intent met die protocol wat werklik gedra word.

### Passive activation on edge devices

In plaas van beaconing monitor 'n implant verkeer wat reeds 'n router/VPN bereik en aktiveer slegs op 'n magic value, source-port pattern of authenticated token. Normale verkeer gaan voort na die werklike diens. ATT&CK noem dit Traffic Signaling (T1205), met gedokumenteerde network-device- en APT-voorbeelde.<sup>[[12]](#references)</sup>

**Detection:** firmware/file integrity, raw packet capture tydens 'n gemagtigde hunt, onverwagte socket filters en differential service behavior. Die afwesigheid van 'n periodieke beacon bewys nie dat 'n edge device skoon is nie.

### Serverless and ephemeral origin rotation

'n Front behou 'n stabiele logiese identiteit terwyl short-lived functions/containers individuele stages in verskeie regions/accounts hanteer. Dit verminder disk lifetime en vaste origin IP's, maar control-plane creation, image/layer, role, secret, request ID en billing telemetry word die duursame graph.

**Detection:** behou cloud-audit- en invocation-logs buite die workload; groepeer deployment templates, roles, environment keys en front-to-origin relationships.

### Privacy-layer diversity

'n Operasie kan doelbewus een homogene chain vermy: byvoorbeeld, een channel gebruik 'n gehuurde relay, tasking gebruik 'n publieke object, 'n exit kom van 'n besitte lab-cellular link, en administration gebruik 'n aparte organization network. Dit verminder die waarde daarvan om een provider te kompromitteer, maar verhoog cross-layer timing- en operational-error-risiko.

**Detection:** bou campaign timelines oor identity-, DNS-, SaaS-, network- en cloud-sensors. Soek na gesinchroniseerde state transitions eerder as identiese indicators.

### Decentralized or transparency-log dead drops

'n Actor kan 'n klein geënkripteerde pointer in enige duursame publieke append-only-stelsel, content-addressed store of transparency-like feed plaas. Die publieke object is resilient, maar sy presiese index/content hash en die client se polling behavior word stabiele identifiers.

**Detection:** teken volledige API/object-identifiers en response hashes aan; alert op nonstandard processes wat immutable objects poll, gevolg deur decoding of nuwe connections.

### Delayed store-and-forward operations

Interactive C2 skep sterk timing-correlation. 'n Store-and-forward-ontwerp bondel encrypted jobs en stuur results minute of ure later deur 'n ander queue of fisiese oordrag terug. Dit offer responsiveness op vir swakker end-to-end timing.

**Detection:** verleng correlation windows, modelleer periodieke queue access en ondersoek endpoint staging. Batching verskuif die signal van packet timing na scheduled process/file behavior; dit verwyder dit nie.

## Design review: think in observers

Vir elke path, voltooi hierdie tabel voor deployment en ná collection:

| Layer | Sees source? | Sees destination? | Sees content? | Stable identifiers | Retention/legal owner |
|---|---:|---:|---:|---|---|
| local network/carrier | | | | | |
| entry/access service | | | | | |
| traversal operator(s) | | | | | |
| exit/redirector/CDN | | | | | |
| authoritative DNS/registrar | | | | | |
| target | | | | | |
| account/payment provider | | | | | |

As een gewone provider elke kolom kan invul, bied die architecture concealment teenoor die target, maar nie robuuste separation nie. As geen interne controller activity na 'n engagement kan terugkarteer nie, is dit ongeskik vir professionele red teaming.

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
{{#include ../banners/hacktricks-training.md}}
