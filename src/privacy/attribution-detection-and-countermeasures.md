# Attribution, Detection en Countermeasures

Attribution-evasion-infrastruktuur is ontwerp om individuele indicators weggooibaar te maak. Verdedigers moet rou evidence behou, verhoudings modelleer en jag na gedrag wat ’n verandering van IP, domain of persona oorleef.

## Evidence-hiërargie

| Evidence | Nuttig vir | Belangrikste voorbehoud |
|---|---|---|
| Source IP/ASN/geolocation | om die sigbare uitgang en provider op te spoor | uitgang kan ’n relay, NAT of slagoffer wees; geolocation is benaderd |
| Passiewe DNS/registrasie | infrastruktuurgeskiedenis en co-hosting | privacy/redaction en shared hosting skep gapings |
| Certificate/TLS/HTTP-fingerprint | om herhaalde deployments te groepeer | algemene software en mimicry veroorsaak false positives |
| Flow-timing en byte-shape | om relay-stadia en herhalende beacons te verbind | CDNs/NAT en beperkte sigbaarheid verminder sekerheid |
| Endpoint-proses/identiteit | om te verduidelik waarom ’n verbinding plaasgevind het | nie op edge/IoT teenwoordig nie; aanvaller kan native tools gebruik |
| Cloud/CDN/API-audit | om tenant en beheer oor infrastruktuur te identifiseer | retensie en provider/legal access wissel |
| Betaling/account/device | om procurement aan ’n persoon/entity te koppel | nominee, compromise en shared devices moet oorweeg word |
| Seized implant/configuration | om keys, peers, controllers en build-links bloot te lê | collection-integrity en tyd van seizure is belangrik |
| Human/physical evidence | om ’n digitale gebeurtenis aan ’n plek/operator te verbind | indringend, jurisdiction-dependent, vereis streng hantering |

Geen enkele ry behoort ’n high-confidence state attribution te dra nie. Gebruik mededingende hypotheses en stel watter waarneming elkeen daarvan sou falsify.

## Minimum telemetry

1. **DNS:** client, question, type, answers, TTL, response code, resolver en timestamp.
2. **Network flow:** source/destination/port, start/end, packets/bytes, TCP flags en sensor location.
3. **TLS/HTTP:** SNI wanneer sigbaar, certificate, negotiated protocol, client/server fingerprint, method, authority/path category, status en byte count. Beskerm sensitiewe volledige URLs.
4. **Identity:** authentication-resultaat, factor/certificate/device, source, application, session ID en risk decision.
5. **Endpoint:** initiating process, parent, user, binary signature/hash en destination.
6. **Edge/network device:** configuration diff, admin login, process/file/firmware integrity, interface- en flow-logs.
7. **Cloud/SaaS/CDN:** actor, tenant/project, API action, source, object/resource, token en result.
8. **Wireless/NAC:** station, randomized-MAC-flag, AP, signal, EAP-identity/certificate, assigned VLAN/IP en posture.

Sinkroniseer clocks, behou oorspronklike time zones, dokumenteer NAT/proxy-grense en behou genoeg geskiedenis om ’n 31-day ORB-node te oorleef.

## Bou ’n attribution-grafiek

Verteenwoordig waarnemings as getipeerde nodes en edges:
```text
[persona]--created-->[cloud account]--deployed-->[VPS]
|                       |                     |
recovery               login-from             TLS fingerprint
|                       |                     |
[email]                [access relay]-------->[redirector]--seen-by-->[target]
```
Nuttige nodes sluit IP, prefix, ASN, domain, DNS account, certificate/key, JA3/JA4-like fingerprint, HTTP grammar, file/config hash, cloud tenant, API token, e-pos, persona, payment instrument en fisiese toestel in. Elke edge benodig `first_seen`, `last_seen`, sensor/source, confidence en of dit waargeneem of afgelei is.

Graph density alleen is misleidend: ’n CDN of certificate authority verbind baie onverwante akteurs. Weeg seldsame operator-beheerde verhoudings—dieselfde API account, SSH key, origin allowlist, unieke response body of control protocol—swaarder as algemene hosting.

## ORB en opsporing van gekompromitteerde routers

### Vanaf ’n waargenome exit

1. Bepaal of die address hosting, residential, mobile, education of business is; moenie residential sources weggooi nie.
2. Haal historiese DNS, services/certificates, open ports en waargenome scan/exploitation behavior vir ’n afgebakende tydperk op.
3. Soek na peers wat seldsame service fingerprints, controller destinations, certificate material of rotation timing deel.
4. Klassifiseer waarskynlike rolle: access, traversal, exit/staging of administration.
5. Kontroleer of veelvuldige onverwante intrusion clusters dieselfde pool gebruik het; multi-tenancy verswak direkte actor attribution, maar versterk ’n ORB-hipotese.
6. Volg nuwe nodes wat ná ou IPs verdwyn het by die rolprofiel pas.

### By die network owner

- Stel waarskuwings op vir nuwe Internet-exposed management en default/legacy authentication.
- Stuur router/firewall/VPN configuration changes en admin authentication off-device.
- Stel ’n baseline op van outbound connections vanaf infrastructure wat gewoonlik min sessions begin.
- Detect new proxy/listener processes, tunnels, scheduled tasks, firmware changes en unexpected DNS.
- Vervang end-of-life devices; ’n reboot wat volatile malware verwyder, herstel nie die exposure nie.
- Beperk management tot ’n authenticated administration plane en bekende sources.

Mandiant beveel aan dat ORB infrastructure as ’n ontwikkelende entiteit opgespoor word, omdat kortstondige IP blocking nie topology en lifecycle vasvang nie.<sup>[[1]](#references)</sup>

## Fast-flux en dynamic-DNS-analise

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
Ondersoek domains met verskeie onafhanklike kenmerke, nie net een drempelwaarde nie. Vergelyk met ’n CDN/anti-DDoS allow-model en kontroleer authoritative name-server-rotasie om single flux van double flux te onderskei. Voeg vir DGA’s per-client NXDOMAIN-uitbarstings, lengte-/karakterverspreiding, gesinchroniseerde navrae oor hosts heen, en die proses wat dit genereer, by. MITRE se huidige guidance beklemtoon eweneens hoëfrekwensie-veranderings, lae TTL en proses-/network-korrelasie.<sup>[[2]](#references)</sup>

## Domain-fronting detection

Waar die enterprise-endpoint of ’n gemagtigde inspection point albei identiteite het, vergelyk:
```text
TLS SNI / ECH state
HTTP/1 Host or HTTP/2 :authority
certificate SAN and CDN tenant/origin
initiating process and expected service
```
Verhoog vertroue wanneer SNI en authority aan onverwante tenants behoort, die proses nie ’n goedgekeurde client is nie, die sessie periodiek/langdurig is, en die inner origin skaars is. ’n Leë SNI is ’n kenmerk om aan te teken, nie outomaties kwaadwillig nie. ECH kan SNI op die draad verberg, dus word endpoint-, DNS- en provider/CDN-logs belangriker. MITRE dokumenteer beide mismatched- en blank-SNI-variante.<sup>[[3]](#references)</sup>

## Dead-drop resolver-volgordeopsporing

Die gedrag met ’n hoë seinwaarde is ’n volgorde eerder as ’n geblokkeerde domain:
```text
unusual process
-> reads one stable public object/profile/post
-> receives small encoded-looking content
-> decodes/parses it
-> contacts a new domain or address within a short interval
```
Soek oor die hele vloot na identiese objekpaaie, response-hashes, API-identifiseerders en opvolgbestemmings. Bewaar die fetched content omdat die actor dit kan wysig of uitvee. Beperk onnodige service-API's en vereis dat goedgekeurde toepassings enterprise-proxies gebruik, maar neem developer tools en outomatisering in ag. MITRE lys GitHub, forums, dokumente en social/web-services in werklike prosedures.<sup>[[4]](#references)</sup>

## Clustering van redirectors en herbruikbare deployments

Selfs wanneer domeine en adresse verander, herdeploy operators dikwels dieselfde outomatisering. Cluster op kombinasies van:

- sertifikaatvelde/key-hergebruik en uitreikingstydsberekening;
- TLS-weergawe/cipher/extension-volgorde en servergedrag;
- identiese HTTP-status, header-volgorde, cache-gedrag, ikoon/body en error page;
- ongewone poortpare en redirect-kettings;
- DNS-provider/name-server-patroon en TTL-skedule;
- deployment-tyd, uptime en onderhoudsvenster;
- back-end origin-blootstelling of identiese allowlists.

'n Enkele generiese Nginx-bladsy is swak bewys. Verskeie skaars, onafhanklike ooreenkomste plus temporale kontinuïteit kan 'n infrastruktuur-cluster-hipotese regverdig.

## Opsporing van residential proxies en onmoontlike sessies

Handhaaf die sessie-identiteit bo die IP-laag. Merk kombinasies soos:

- een sessie/device fingerprint verander lande/ASN's vinniger as wat reis toelaat;
- 'n consumer-IP verander met elke request terwyl cookies en TLS/browser-identiteit konstant bly;
- die beweerde plaaslike device het latency/tydsone/taal wat nie met die exit ooreenstem nie;
- 'n adres wissel tussen onverwante rekeningpopulasies of toon backconnect-proxy-gedrag;
- 'n geprivilegieerde sessie verskyn vanaf residential access sonder die organisasie se device certificate.

Carrier NAT, accessibility tools, corporate VPN's en reis veroorsaak benign anomalies. Vereis step-up authentication of ondersoek in plaas daarvan om onomkeerbaar te blokkeer slegs op grond van “residential proxy”-etikette.

## Wireless- en covert-device-opsporing

Koppel RADIUS/NAC aan AP- en fisiese konteks:

1. vind eerste-waargenome account–device–AP-kombinasies;
2. identifiseer credentials wat sonder 'n managed EAP certificate/posture gebruik word;
3. vergelyk gelyktydige sessies en badge/gebou-teenwoordigheid;
4. ondersoek buitengewoon swak/grenssein en beweging tussen AP's;
5. soek nabygeleë managed endpoints vir wireless scanning, 'n nuut-geaktiveerde interface bridge/NAT, virtual adapters of tunnels;
6. inventariseer nuwe switchport-, DHCP-, USB-network- en PoE-aktiwiteit;
7. voer 'n gemagtigde RF/fisiese sweep uit wanneer die bewys dit ondersteun.

Dit vang beide 'n APT28-styl nearest-neighbor-pad en 'n oefening-drop op. MAC-randomisering moet nie as identiteit of skuld beskou word nie.

## Opsporing van financial attribution

- Bewaar die presiese chain, token, address, transaction en block identifiers.
- Volg waarde deur change, peel chains, fan-out/in, mixers, bridges en service deposits terwyl heuristieke gemerk word.
- Korrelleer tyd, bedrag minus fees, contract event, liquidity en withdrawal op die destination-chain.
- Verkry of bewaar wettige exchange-, bridge-, merchant-, account-, device- en delivery-records.
- Kontroleer huidige sanctioned entities/addresses en derivatives onder die toepaslike program; moenie op 'n ou statiese lys staatmaak nie.
- Behandel gebruik van privacy-protocols as 'n risiko-konteksinset, nie as bewys van oortreding nie.

FATF se red flags is uitdruklik kontekstueel: ongewone patroon, bedrag/frekwensie, geografie, bron van fondse en anonymity-enhancing services word saam betekenisvol.<sup>[[5]](#references)</sup>

## Deception en canaries

Defenders kan hoë-vertroue-seine skep sonder om gewone gebruikers te probeer deanonymize:

- unieke credentials of dokumente wat nooit een stelsel behoort te verlaat nie;
- vals administratiewe endpoints en decoy shares;
- instrumented DNS-name wat slegs in beheerde artefakte ingebed is;
- canary cloud keys met geen legitieme gebruik nie;
- 'n decoy Wi-Fi-identiteit wat geen managed device besit nie.

Beperk en beheer deception noukeurig. 'n Canary behoort misbruik van die defender se eie asset te identifiseer, nie onverwante third-party traffic te versamel nie.

## Prioriteite vir countermeasures

1. Verwyder routers, VPN's en appliances wat aan die Internet blootgestel is sonder ondersteuning.
2. Vereis phishing-resistant MFA en device-bound certificates, insluitend interne/wireless access.
3. Sentreer immutable-enough identity-, endpoint-, DNS-, flow-, proxy-, cloud- en network-device-logs.
4. Beperk management en egress; inventariseer elke ekstern bereikbare service.
5. Monitor DNS, certificate transparency en cloud configuration vir ongemagtigde assets.
6. Bewaar process-to-network- en object-level SaaS-visibility.
7. Oefen cross-layer investigations en koördinering met naburige providers.
8. Volg infrastructure clusters en behaviors, nie slegs IP-blocklists nie.

## Analitiese dissipline

Gebruik confidence-taal:

- **Observed:** sensor/provider-record wys die verhouding direk.
- **Strongly supported:** verskeie onafhanklike waarnemings bevoordeel dit bo alternatiewe.
- **Assessed:** inferensie gebaseer op verklaarde aannames en bewys.
- **Unknown:** ontbrekende visibility voorkom 'n gevolgtrekking.

Hou altyd minstens twee hipoteses: actor-operated infrastructure teenoor compromised/shared intermediary; een actor teenoor multi-tenant service; doelbewuste evasion teenoor legitieme privacy/CDN-gedrag. Die vermoë om onsekerheid te verduidelik, is deel van korrekte detection.

## References

- [1] [Google Cloud/Mandiant — Chinese-nexus-spioenasie-akteurs gebruik ORB-netwerke](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks)
- [2] [MITRE ATT&CK — Fast Flux DNS (T1568.001)](https://attack.mitre.org/techniques/T1568/001/)
- [3] [MITRE ATT&CK — Domain Fronting (T1090.004)](https://attack.mitre.org/techniques/T1090/004/)
- [4] [MITRE ATT&CK — Dead Drop Resolver (T1102.001)](https://attack.mitre.org/techniques/T1102/001/)
- [5] [FATF — Rooi-vlag-aanwysers vir Virtual Assets](https://www.fatf-gafi.org/en/publications/Methodsandtrends/Virtual-assets-red-flag-indicators.html)
- [6] [CISA AA24-038A — PRC-akteurs kompromitteer en handhaaf volgehoue toegang](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [7] [NSA — Verbeterde visibility- en hardening-riglyne vir communications infrastructure](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/3982793/guidance-urges-visibility-and-device-hardening-against-prc-affiliated-threat-ac/)
