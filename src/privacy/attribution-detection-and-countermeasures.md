# Attribution, Detection en Countermeasures

{{#include ../banners/hacktricks-training.md}}

Infrastruktuur vir attribution-evasion is ontwerp om individuele indicators weggooibaar te maak. Defenders behoort rou evidence te bewaar, verhoudings te modelleer en te soek na gedrag wat 'n verandering van IP, domain of persona oorleef.

## Evidence-hiërargie

| Evidence | Nuttig vir | Belangrikste caveat |
|---|---|---|
| Source IP/ASN/geolocation | om die sigbare exit en provider te lokaliseer | exit kan 'n relay, NAT of victim wees; geolocation is benaderd |
| Passive DNS/registration | infrastruktuurgeskiedenis en co-hosting | privacy/redaction en shared hosting skep gapings |
| Certificate/TLS/HTTP fingerprint | om herhaalde deployments te cluster | algemene software en mimicry skep false positives |
| Flow timing en byte shape | om relay-stages en herhalende beacons te koppel | CDNs/NAT en beperkte sigbaarheid verminder sekerheid |
| Endpoint process/identity | om te verduidelik waarom 'n connection plaasgevind het | nie op edge/IoT teenwoordig nie; attacker kan native tools gebruik |
| Cloud/CDN/API audit | om tenant en beheer oor infrastruktuur te identifiseer | retention en provider/legal access verskil |
| Payment/account/device | om procurement aan 'n persoon/entity te koppel | nominee, compromise en gedeelde devices moet oorweeg word |
| Seized implant/configuration | om keys, peers, controllers en build links bloot te lê | collection integrity en die tyd van seizure is belangrik |
| Human/physical evidence | om digital event aan plek/operator te koppel | indringend, jurisdiction-dependent, en vereis streng hantering |

Geen enkele ry behoort alleen 'n hoevertroue-state attribution te dra nie. Gebruik competing hypotheses en noem watter observation elkeen sou falsifiseer.

## Minimum telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver en timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags en sensor location.
3. **TLS/HTTP:** SNI wanneer sigbaar, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status en byte count. Beskerm sensitiewe volledige URLs.
4. **Identity:** authentication result, factor/certificate/device, source, application, session ID en risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash en destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface en flow logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token en result.
8. **Wireless/NAC:** station, randomized-MAC flag, AP, signal, EAP identity/certificate, assigned VLAN/IP en posture.

Synchroniseer clocks, behou oorspronklike time zones, dokumenteer NAT/proxy boundaries en behou genoeg history om 'n 31-day ORB node te oorleef.

## Bou 'n attribution graph

Stel observations voor as getikte nodes en edges:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Nuttige nodes sluit IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, email, persona, payment instrument en physical device in. Elke edge benodig `first_seen`, `last_seen`, sensor/source, confidence en of dit observed of inferred is.

Graph density alleen is misleidend: ’n CDN of certificate authority verbind baie onverwante actors. Ken meer gewig toe aan skaars operator-controlled relationships—dieselfde API account, SSH key, origin allowlist, unieke response body of control protocol—as aan algemene hosting.

## ORB en compromised-router hunting

### Vanaf ’n waargenome exit

1. Bepaal of die address hosting, residential, mobile, education of business is; moenie residential sources weggooi nie.
2. Trek historiese DNS, services/certificates, oop ports en waargenome scan/exploitation behavior vir ’n afgebakende periode.
3. Soek na peers wat skaars service fingerprints, controller destinations, certificate material of rotation timing deel.
4. Klassifiseer waarskynlike roles: access, traversal, exit/staging of administration.
5. Kontroleer of verskeie onverwante intrusion clusters dieselfde pool gebruik het; multi-tenancy verswak direkte actor attribution, maar versterk ’n ORB-hypothesis.
6. Volg nuwe nodes wat by die role profile pas nadat ou IPs verdwyn.

### By die network owner

- Stel alerts op vir nuwe Internet-exposed management en default/legacy authentication.
- Stuur router/firewall/VPN configuration changes en admin authentication off-device.
- Stel ’n baseline op vir outbound connections vanaf infrastructure wat normaalweg min sessions inisieer.
- Detect nuwe proxy/listener processes, tunnels, scheduled tasks, firmware changes en onverwagte DNS.
- Vervang end-of-life devices; ’n reboot wat volatile malware verwyder, herstel nie die exposure nie.
- Beperk management tot ’n authenticated administration plane en bekende sources.

Mandiant beveel aan dat ORB infrastructure as ’n ontwikkelende entity opgespoor word, omdat kortstondige IP blocking nie topology en lifecycle vasvang nie.<sup>[[1]](#references)</sup>

## Fast-flux en dynamic-DNS analytics

Aggregateer volgens registered domain en ’n sliding window. ’n Praktiese score kan die volgende kombineer:
```text
score =
2 * low_median_ttl
+ 2 * unique_answer_count
+ 2 * unique_asn_count
+ geographic_dispersion
+ nxdomain_or_answer_churn
+ first_seen_recently
+ suspicious_process_or_follow_on
```
Ondersoek domains met verskeie onafhanklike kenmerke, nie net een drempelwaarde nie. Vergelyk dit met ’n CDN/anti-DDoS allow-model en kontroleer authoritative name-server-rotasie om single flux van double flux te onderskei. Vir DGAs, voeg NXDOMAIN-uitbarstings per kliënt, lengte-/karakterverspreiding, gesinchroniseerde navrae oor hosts heen, en die proses wat dit genereer, by. MITRE se huidige leiding beklemtoon eweneens hoëfrekwensie-veranderinge, lae TTL en proses-/netwerkkorrelasie.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Waar die enterprise-endpoint of ’n gemagtigde inspection point albei identiteite het, vergelyk:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Verhoog vertroue wanneer SNI en authority aan onverwante tenants behoort, die proses nie ’n goedgekeurde client is nie, die sessie periodiek/langdurig is, en die inner origin skaars is. ’n Leë SNI is ’n kenmerk om aan te teken, nie outomaties kwaadwillig nie. ECH kan SNI op die wire verberg, dus word endpoint-, DNS- en provider/CDN-logs belangriker. MITRE dokumenteer beide mismatched- en blank-SNI-variante.<sup>[[3]](#references)</sup>

## Opsporing van dead-drop resolver-volgorde

Die hoë-sein-gedrag is ’n volgorde eerder as ’n geblokkeerde domein:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Soek vlootwyd na identiese objekpaaie, response-hashes, API-identifiseerders en daaropvolgende bestemmings. Bewaar die opgehaalde inhoud, omdat die actor dit kan wysig of uitvee. Beperk onnodige diens-API's en vereis dat goedgekeurde toepassings enterprise proxies gebruik, maar neem developer tools en automation in ag. MITRE lys GitHub, forums, dokumente en social/web services in werklike prosedures.<sup>[[4]](#references)</sup>

## Redirector- en herbruikbare-deployment-klustering

Selfs wanneer domeine en adresse verander, ontplooi operators dikwels dieselfde automation weer. Kluster op kombinasies van:

- sertifikaatvelde/key reuse en uitreikingstydsberekening;
- TLS-weergawe/cipher/extension-volgorde en servergedrag;
- identiese HTTP-status, header-volgorde, cache-gedrag, ikoon/body en foutbladsy;
- ongewone poortpare en redirect-kettings;
- DNS-provider/name-server-patroon en TTL-skedule;
- deployment-tyd, uptime en instandhoudingsvenster;
- blootstelling van back-end-origin of identiese allowlists.

'n Enkele generiese Nginx-bladsy is swak bewys. Verskeie seldsame, onafhanklike ooreenkomste plus temporale kontinuïteit kan 'n infrastruktuur-klusterhipotese regverdig.

## Residential proxy- en impossible-session-detection

Handhaaf die sessie-identiteit bo die IP-laag. Merk kombinasies soos:

- een sessie/device fingerprint verander lande/ASN's vinniger as wat reis toelaat;
- 'n consumer IP verander met elke versoek terwyl cookies en TLS/browser-identiteit konstant bly;
- die beweerde plaaslike device het latency/time-zone/taal wat nie met die uitgangspunt ooreenstem nie;
- 'n adres wissel tussen onverwante rekeningpopulasies of toon backconnect proxy-gedrag;
- 'n bevoorregte sessie verskyn vanaf residential access sonder die organisasie se device certificate.

Carrier NAT, accessibility tools, corporate VPNs en reis veroorsaak goedaardige anomalieë. Vereis step-up authentication of ondersoek eerder as onomkeerbare blocking wat uitsluitlik op “residential proxy”-etikette gebaseer is.

## Wireless- en covert-device-detection

Koppel RADIUS/NAC aan AP- en fisiese konteks:

1. vind rekening–device–AP-kombinasies wat die eerste keer gesien word;
2. identifiseer credentials wat sonder 'n managed EAP certificate/posture gebruik word;
3. vergelyk gelyktydige sessies en badge-/gebouteenwoordigheid;
4. ondersoek buitengewoon swak/grenssein en beweging tussen AP's;
5. soek op nabygeleë managed endpoints na wireless scanning, 'n nuut geaktiveerde interface bridge/NAT, virtual adapters of tunnels;
6. inventariseer nuwe switchport-, DHCP-, USB-network- en PoE-aktiwiteit;
7. voer 'n gemagtigde RF-/fisiese sweep uit wanneer die bewyse dit ondersteun.

Dit vang sowel 'n APT28-styl nearest-neighbor path as 'n exercise drop op. MAC-randomization moet nie as identiteit of skuld beskou word nie.

## Financial-attribution-detection

- Bewaar die presiese chain, token, address, transaction en block-identifiers.
- Volg waarde deur change, peel chains, fan-out/in, mixers, bridges en service deposits terwyl heuristieke gemerk word.
- Korrelleer tyd, bedrag minus fees, contract event, liquidity en withdrawal op die destination-chain.
- Verkry of bewaar wettige exchange-, bridge-, merchant-, account-, device- en delivery-rekords.
- Sift huidige sanctioned entities/addresses en derivatives onder die toepaslike program; moenie op 'n ou statiese lys staatmaak nie.
- Behandel die gebruik van privacy protocols as 'n risk-context-inset, nie as bewys van oortreding nie.

FATF se red flags is uitdruklik kontekstueel: ongewone patroon, bedrag/frekwensie, geografie, bron van fondse en anonymity-enhancing services word saam betekenisvol.<sup>[[5]](#references)</sup>

## Deception en canaries

Defenders kan hoëvertroue-seine skep sonder om gewone gebruikers te probeer deanonymize:

- unieke credentials of dokumente wat nooit een stelsel behoort te verlaat nie;
- fake administrative endpoints en decoy shares;
- instrumented DNS-name wat slegs in beheerde artifacts ingebed is;
- canary cloud keys sonder enige legitimate use;
- 'n decoy Wi-Fi-identiteit wat geen managed device besit nie.

Baken en beheer deception sorgvuldig. 'n Canary behoort misbruik van die defender se eie asset te identifiseer, nie onverwante derdeparty-verkeer te versamel nie.

## Countermeasure-prioriteite

1. Verwyder routers, VPNs en appliances wat nie deur die Internet ondersteun behoort te word nie.
2. Vereis phishing-resistant MFA en device-bound certificates, insluitend interne/wireless access.
3. Sentraliseer genoegsaam immutable identity-, endpoint-, DNS-, flow-, proxy-, cloud- en network-device-logs.
4. Beperk management en egress; inventariseer elke externally reachable service.
5. Monitor DNS, certificate transparency en cloud configuration vir ongemagtigde assets.
6. Bewaar process-to-network- en object-level SaaS-visibility.
7. Oefen cross-layer investigations en koördinering met neighbouring providers.
8. Volg infrastructure clusters en gedrag, nie slegs IP-blocklists nie.

## Analitiese dissipline

Gebruik confidence-taal:

- **Observed:** sensor/provider-rekord toon die verhouding direk.
- **Strongly supported:** verskeie onafhanklike waarnemings ondersteun dit bo alternatiewe.
- **Assessed:** afleiding gebaseer op vermelde aannames en bewyse.
- **Unknown:** ontbrekende visibility voorkom 'n gevolgtrekking.

Hou altyd minstens twee hipoteses: actor-operated infrastructure teenoor 'n compromised/shared intermediary; een actor teenoor 'n multi-tenant service; doelbewuste evasion teenoor legitimate privacy/CDN behavior. Die vermoë om onsekerheid te verduidelik is deel van korrekte detection.

## References

- [1] [Google Cloud/Mandiant — China-nexus espionage actors use ORB networks](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Virtual Assets Red Flag Indicators](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC actors compromise and maintain persistent access](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Enhanced visibility and hardening guidance for communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
{{#include ../banners/hacktricks-training.md}}
