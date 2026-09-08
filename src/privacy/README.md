# Aanstootlike privaatheid, toeskrywing-ontwyking en OPSEC

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling bestudeer privaatheid vanuit die oogpunt van 'n red team, 'n intrusion operator en die verdediger wat daardie operator probeer rekonstrueer. **Anonymity is nie bloot die wegsteek van 'n IP-adres nie.** Volwasse operasies skei die mense, endpoints, accounts, infrastructure, network paths, payloads en betalings wat in 'n attribution graph verbind kan word.

Die materiaal sluit doelbewus tegnieke in wat in regerings- en APT-operasies aangemeld is: operational-relay-box (ORB)-netwerke, gekompromitteerde edge devices, residential exits, redirector tiers, fast flux, domain fronting, dead-drop resolvers, nearby wireless pivots, covert drop devices, satellite-link abuse, false personas en financial layering. Elke tegniek word aangebied as:

1. die operasionele doelwit en ATT&CK-kartering;
2. die meganisme en trust boundaries;
3. wat elke waarnemer steeds kan aanteken;
4. die foute en stabiele artefakte wat dit verydel;
5. defensive telemetry, analytics en mitigations; en
6. 'n gemagtigde emulation met behulp van besitte of uitdruklik afgebakende infrastructure.

Dit is dus beide 'n offensive tradecraft-verwysing en 'n defender se attribution manual. Die doel is om gevorderde gedrag verstaanbaar en toetsbaar te maak, nie om voor te gee dat een kommersiële diens 'n operator onsigbaar maak nie.

**Navorsingsafsnydatum:** 8 September 2026. Provider-beskikbaarheid, produkgedrag, sanksies, kontant-/prepaid-drempels, SIM-registrasiereëls en crypto-regulering verander gereeld; verifieer dit weer voordat jy daarop staatmaak.

{% hint style="danger" %}
Om 'n tegniek te verstaan, is nie magtiging om dit uit te voer nie. Die bladsye verduidelik kriminele misbruik soos gekompromitteerde routers, 'n buurman se Wi-Fi, versteekte devices, gesteelde identities en laundering op die meganisme-en-detection-vlak. Reproduction-stappe gebruik slegs besitte lab-stelsels, sintetiese identities en toetsassets. Moet nooit toegang tot 'n derde party verkry, KYC of sanksies ontduik, of kriminele opbrengste verberg nie. Unauthorized access is in baie jurisdiksies gekriminaliseer, insluitend ingevolge die US CFAA, die UK Computer Misuse Act en EU-lidstaatwette wat Directive 2013/40/EU implementeer.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>
{% endhint %}

## Adversary-doelwitkaart

| Adversary-doelwit | Tegniekfamilies | Belangrikste defensive vraag |
|---|---|---|
| Verberg die operator se oorsprong | VPN/Tor, eksterne en multi-hop proxies, residential/mobile exits, ORBs, satellite links | Is die laaste-hop-adres 'n actor asset, 'n onwetende slagoffer of 'n kortstondige relay? |
| Hou die werklike C2 onontdekbaar | redirectors, CDNs, domain fronting, dead-drop resolvers, dynamic DNS, fast flux | Watter stabiele gedrag oorleef IP/domain-rotasie? |
| Leen trust en reputasie | gekompromitteerde servers, routers, cloud- en web-service accounts, domain shadowing | Tree 'n gerespekteerde asset anders as sy historiese baseline op? |
| Kruis 'n fisiese of netwerkgrens | nearest-neighbor Wi-Fi pivots, on-site drops, rogue peripherals, cellular backhaul | Watter nuwe radio, device, switchport of outbound tunnel het verskyn? |
| Skeí die mens van die operasie | personas, account/device-compartmentation, cover communications, procurement separation | Watter recovery field, browser, skedule, taal, betaling of admin-event verbind die personas? |
| Verduister funding en cash-out | mules/nominees, prepaid value, mixers, CoinJoin, peel chains, chain hopping, OTC brokers | Waar verbind on-chain- en off-chain-identity records weer? |

Die naaste ATT&CK-resource-development- en C2-konsepte is **Acquire Infrastructure (T1583)**, **Compromise Infrastructure (T1584)**, **Establish/Compromise Accounts (T1585/T1586)**, **Proxy (T1090)**, **Dynamic Resolution (T1568)** en **Web Service (T1102)**.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

## Privaatheid, pseudonymity, anonymity en security

| Doel | Betekenis | Tipiese mislukking |
|---|---|---|
| **Confidentiality** | Buitestanders kan nie die inhoud lees nie | Metadata identifiseer steeds die partye |
| **Privacy** | Inligtingsopenbaarmaking is beperk tot wat nodig is | 'n Provider behou meer data as wat verwag is |
| **Pseudonymity** | Activity gebruik 'n stabiele identity wat nie publiek aan 'n legal identity gekoppel is nie | Recovery email, betaling, IP, foto of writing style verbind dit |
| **Anonymity** | 'n Waarnemer kan die actor nie van 'n betekenisvolle stel ander actors onderskei nie | Login, fingerprint, timing, location of transaction correlation verklein die stel |
| **Unlinkability** | Twee actions kan nie betroubaar aan dieselfde actor toegeskryf word nie | Hergebruikte identifiers, gelyktydige activity of gedeelde infrastructure verbind hulle |
| **Security** | Systems weerstaan compromise | 'n Secure maar geïdentifiseerde account bly nie-anoniem |

Hierdie eienskappe is observer-specific. 'n Merchant sien moontlik nie 'n card number nie, terwyl die issuer steeds die customer en transaction ken. 'n Website sien dalk 'n Tor exit eerder as 'n home IP, terwyl 'n account login die user onmiddellik identifiseer.

## Begin by die observer

Voordat jy tools kies, skryf die volgende neer:

1. **Assets:** identity, location, browsing destinations, message contents, social graph, payment details, client name, red-team source infrastructure of stored evidence.
2. **Observers:** local Wi-Fi operator, ISP/mobile carrier, VPN, Tor entry/exit, DNS resolver, website, ad network, cloud host, payment issuer, merchant, exchange, counterparties, employer of government.
3. **Correlation handles:** IP address, account/recovery fields, phone number, device identifiers, cookies, browser fingerprint, time zone, payment instrument, shipping address, writing style, transaction graph, physical presence en cameras.
4. **Capability and time:** passiewe commercial tracking verskil van 'n targeted observer wat providers kan subpoena, endpoints kan seiseer of albei kante van 'n connection kan monitor.
5. **Failure cost:** verleentheid, account suspension, client harm, financial loss, physical danger of legal exposure.

Kies daarna die kleinste volhoubare controls. 'n Ingewikkelde plan wat gereeld omseil word, is swakker as 'n eenvoudiger plan wat konsekwent gebruik word.

## Vinnige besluitnemingstabel

| Behoefte | Verstandige beginpunt | Wat dit **nie** oplos nie |
|---|---|---|
| Verberg browsing metadata van 'n ISP/local network | Reputable VPN of Tor Browser | Accounts, cookies, device fingerprint, endpoint compromise |
| Sterker web-anonymity | Tor Browser; Tails vir 'n amnesic session | Global traffic correlation, personal disclosures, physical observation |
| Volgehoue gecompartmenteerde werk | Whonix of Qubes-Whonix; aparte qubes/profiles | Hypervisor/host compromise, behavior linking identities |
| Vinnige gemagtigde red-team-egress | Client-provided jump host of engagement-specific VPS/VPN | Provider/customer attribution; scope- en cloud-policy-verpligtinge |
| Verminder merchant-blootstelling van 'n card number | Issuer virtual card of tokenized wallet | Issuer/network knowledge, shipping, account- en device-data |
| Minimaliseer point-of-sale payment data | Wettig verkrygde kontant waar aanvaar | CCTV, receipts, withdrawal trail, cash limits |
| Verbeter public-chain crypto privacy | Own wallet/node, new addresses, coin control, Tor, supported PayJoin | Exchange/KYC, counterparty records, permanent-chain analysis |
| Verstek-on-chain amount/receiver/sender confidentiality | Monero met aparte wallet contexts en network privacy | Acquisition/off-ramp records, endpoint compromise, merchant/shipping data |

## Kernreëls

- **Skei contexts voordat activity begin.** Om separation terugwerkend in te stel nadat accounts, devices en betalings reeds verbind is, maak selde die geskiedenis ongedaan.
- **Moenie jouself in uniqueness aanpas nie.** Browser fingerprinting kan activity korreleer selfs nadat cookies skoongemaak of 'n IP verander is; standaardkonfigurasies met groter anonymity sets is gewoonlik verkieslik.<sup>[[5]](#references)</sup>
- **Beskerm die endpoint.** Network anonymity kan nie 'n unlocked, infected of seized device red nie.
- **Encrypt content en minimaliseer metadata.** End-to-end encryption beskerm message content, maar nie noodwendig wie gekommunikeer het, wanneer, vanwaar of met watter device nie.
- **Behandel providers as observers.** VPNs, email services, cloud hosts, exchanges, payment issuers en alias forwarders sien verskillende dele van die activity.
- **Verkies verifieerbare claims.** Soek protocol documentation, reproducible software, public audits, retention details en transparency reports eerder as “military-grade”-bemarking.
- **Herassesseer periodiek.** Services, wette, threat actors en defaults verander.

## Offensive-first-afdelingskaart

- [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) — 48 access-path-families met voordele, nadele, deployment/emulation-stappe, detection, capture exposure en controller-side discovery monitoring.
- [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) — 48 payment-families met voordele, nadele, lawful workflows, detection, capture exposure en compromise monitoring.
- [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) — stabiele outbound rendezvous, dual-uplink recovery, secret minimization, capture drills en discovery/compromise monitoring vir owner-approved drops.
- [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) — ORBs, multi-hop/residential relays, redirectors, fronting, fast flux, domain shadowing, web services en persona infrastructure.
- [Covert Physical and Wireless Access](covert-physical-wireless-access.md) — nearest-neighbor attacks, public access, drop devices, cellular backhaul en satellite abuse.
- [Government and APT Case Studies](government-and-apt-case-studies.md) — gerekonstrueerde openbare cases en die telemetry wat dit blootgelê het.
- [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) — hoe payment layering werk, waarom dit misluk en hoe investigators dit volg.
- [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) — 'n cross-layer detection model en praktiese hunting logic.
- [Authorized Adversary-Emulation Labs](authorized-adversary-emulation-labs.md) — reproducible exercises met besitte networks en synthetic data.

## Operator-fundamentals en ondersteunende gidse

- [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md)
- [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md)
- [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md)
- [Privacy Operating Systems](privacy-operating-systems.md)
- [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md)
- [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md)
- [Private Digital Payments](private-digital-payments.md)
- [Cryptocurrency Privacy](cryptocurrency-privacy.md)
- [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md)
- [Reproducible Privacy Testing](reproducible-privacy-testing.md)
- [Operational Privacy Playbooks](operational-privacy-playbooks.md)

## Gids- en verifikasie-indeks

| Tegniek | Deployment guide | Verification/failure test |
|---|---|---|
| Alle Internet-access-tegniekfamilies | [Anonymous Internet Access Technique Catalog](anonymous-internet-access-techniques.md) | Per-tegniek-detection plus [reproducible labs](authorized-adversary-emulation-labs.md) |
| Alle payment-tegniekfamilies | [Anonymous Payment Technique Catalog](anonymous-payment-techniques.md) | Per-tegniek-detection plus [synthetic payment lab](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Owner-approved physical field node | [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) | Capture drill, off-device state monitoring en suspected-discovery runbook |
| ORBs, residential relays, fronting, fast flux en dead drops | [Offensive Infrastructure and Attribution Evasion](offensive-infrastructure-and-attribution-evasion.md) | [Owned emulation labs](authorized-adversary-emulation-labs.md#lab-1-owned-orb-and-redirector-chain) |
| Nearest-neighbor Wi-Fi, drops, cellular en satellite paths | [Covert Physical and Wireless Access](covert-physical-wireless-access.md) | [Owned wireless-pivot lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) |
| Cross-layer infrastructure en operator attribution | [Attribution, Detection and Countermeasures](attribution-detection-and-countermeasures.md) | [Exercise report template](authorized-adversary-emulation-labs.md#exercise-report-template) |
| Peel chains, mixers, chain hopping, nominees en OTC conversion | [Financial Obfuscation Tradecraft](financial-obfuscation-tradecraft.md) | [Synthetic transaction graph](authorized-adversary-emulation-labs.md#lab-6-synthetic-peel-chain-and-bridge-graph) |
| Identity/browser-compartment | [Threat Modeling & Identity Separation](threat-modeling-and-identity-separation.md) | [Browser and OS tests](reproducible-privacy-testing.md#browser-compartment-test) |
| VPN, Tor, guest Wi-Fi, travel router, cellular | [Network Privacy & Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md) | [Network-path test](reproducible-privacy-testing.md#network-path-test) |
| Split relays, OHTTP, namespaces, bridges, onions, I2P | [Advanced Network Privacy Architectures](advanced-network-privacy-architectures.md) | [Tor/onion and route tests](reproducible-privacy-testing.md#tor-and-onion-service-test) |
| Tails, Whonix en Qubes | [Privacy Operating Systems](privacy-operating-systems.md) | [OS isolation test](reproducible-privacy-testing.md#operating-system-isolation-test) |
| Signal, SimpleX, Briar, OnionShare en encrypted files | [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) | [Communications/file tests](reproducible-privacy-testing.md#communications-metadata-test) |
| Authorized red-team-egress/drop nodes | [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) | [Accountability drill](reproducible-privacy-testing.md#authorized-red-team-accountability-drill) |
| Cash, prepaid en virtual cards | [Private Digital Payments](private-digital-payments.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Bitcoin, PayJoin/CoinJoin, Lightning en Monero | [Cryptocurrency Privacy](cryptocurrency-privacy.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |
| Silent Payments, Zcash, Taler en federated e-cash | [Privacy-Preserving Payment Protocols](privacy-preserving-payment-protocols.md) | [Payment privacy test](reproducible-privacy-testing.md#payment-privacy-test) |

## References

- [1] [EFF Surveillance Self-Defense — Your Security Plan](https://ssd.eff.org/module/your-security-plan)
- [2] [US Code, 18 USC §1030 — Fraud and related activity in connection with computers](https://uscode.house.gov/view.xhtml?req=title:18%20section:1030%20edition:prelim)
- [3] [UK Computer Misuse Act 1990, section 1](https://www.legislation.gov.uk/ukpga/1990/18/section/1)
- [4] [EUR-Lex — Directive 2013/40/EU on attacks against information systems](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32013L0040)
- [5] [W3C — Mitigating Browser Fingerprinting in Web Specifications](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [MITRE ATT&CK — Acquire Infrastructure (T1583) and Compromise Infrastructure (T1584)](https://attack.mitre.org/techniques/T1584/)
- [7] [MITRE ATT&CK — Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
{{#include ../banners/hacktricks-training.md}}
