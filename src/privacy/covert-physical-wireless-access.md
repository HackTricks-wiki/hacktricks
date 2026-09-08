# Bedekte fisiese en draadlose toegang

{{#include ../banners/hacktricks-training.md}}

Vir 'n gedetailleerde, eienaar-goedgekeurde implementering wat uitgaande rendezvous, herstel van krag/uplink, minimale geheime wat deur die toestel gehou word, capture-toetsing en monitering vir moontlike ontdekking dek, sien [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Die verandering van die netwerkpad kan ook die oënskynlike fisiese oorsprong verander. 'n Gesofistikeerde akteur kan 'n nabygeleë gekompromitteerde stelsel, 'n versteekte toestel, publieke toegang, sellulêre backhaul of 'n satellietontvanger gebruik sodat teikenlogs weg van die operateur wys. Nie een hiervan verwyder fisiese, radio- of verskafferbewyse nie; dit verskuif attributie na verskillende datastelle.

## Tegniekmatriks

| Tegniek | Oënskynlike oorsprong | Noodsaaklike voorwaarde | Bewyse met hoë waarde |
|---|---|---|---|
| Nabygeleë wireless pivot | 'n besigheid/huis langs die teiken | gekompromitteerde dual-homed host en toegang tot die teiken se Wi-Fi | endpoint-logs van die naburige host, RF-assosiasie en teiken se RADIUS/DHCP |
| Publieke/gasnetwerk | venue-NAT of tunnel-exit | wettige toegang of omseiling van toegangsbeheer | captive portal, DHCP, AP-assosiasie, CCTV en betalings-/liggingsrekords |
| Covert drop device | bedrade, Wi-Fi- of sellulêre adres by of naby die teiken | fisiese plasing of aflewering | switchport/USB, RF, voorraad, krag en telemetrie van die uitgaande tunnel |
| Sellulêre router/eSIM | draer-NAT of toegewyde APN | modem/SIM/subskripsie | IMEI/IMSI/eSIM, selfoonsektor, draerrekening en tydsberekening van verkeer |
| Satellite-link abuse | intekenaaradres binne die straal se dekkingsgebied | protokol- en diensspesifieke swakheid | RF-ligging, uplink-vloei, onmoontlike RTT/routing en verskafferrekords |

## Nearest-neighbor attack

Volexity het 'n APT28/GRU-operasie uit 2022 gedokumenteer waarin die akteur op afstand van sy uiteindelike teiken was. Dit het die teiken se publieke diens met password spraying geteiken om geldige credentials te verkry, maar MFA het direkte Internet-aanmelding verhoed. Die teiken se enterprise Wi-Fi het daardie credentials sonder MFA aanvaar. Die akteur het organisasies fisies naby die teiken gekompromitteer, 'n dual-homed system met draadlose bereik gevind en daardie stelsel gebruik om by die teiken se Wi-Fi te authenticateer. Volexity het dit die **Nearest Neighbor Attack** genoem.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Die nuutheid lê in die samestelling. Geen operator reis na die teiken nie, en die Internet-gerigte diens se MFA werk steeds. Die gekompromitteerde buurman verskaf fisiese nabyheid; die gesteelde teikencredential verskaf logiese toegang; die teiken-Wi-Fi word die pad wat die grens oorsteek.

### Voorvereistes en sigbaarheid

- ’n Nabygeleë stelsel moet op afstand beheerbaar wees en ’n versoenbare radio hê, of toegang tot ’n ander nabygeleë pivot hê.
- Die teiken-SSID moet daardie stelsel bereik, en Wi-Fi-toelating moet ’n herbruikbare credential/sertifikaat/toesteltoestand aanvaar.
- Die pivot benodig dikwels twee gelyktydige paaie: een terug na die operator en een na die teiken-WLAN.
- Die teiken kan ’n nuwe stasie-MAC en ’n wettige gebruikersnaam sien, maar geen ooreenstemmende bestuurde-toestelsertifikaat, posture, geskiedenis of verwagte gebou-inskrywing nie.
- Logs van die buurman se endpoint kan wireless scans, nuwe profiele, interface-veranderinge, tunneling en remote-control-aktiwiteit toon.

### Opsporing en voorkoming

1. Vereis certificate-backed EAP-TLS en managed-device posture vir enterprise-Wi-Fi; moenie ’n wagwoord wat op die Internet aan MFA gefaal het, bloot omdat dit oor radio aankom, as voldoende beskou nie.
2. Korrelleer RADIUS-authentication met MDM/NAC-identiteit, historiese stasie-/toestelbinding, AP-ligging, fisiese-toegangsgebeure en gelyktydige sessies.
3. Stel ’n alert wanneer ’n rekening vir die eerste keer assosieer, vanaf ’n ongewone AP-edge, sonder ’n bestuurde sertifikaat, of terwyl dieselfde identiteit elders aktief is.
4. Monitor endpoints wat interfaces kan bridge. Ondersoek op Windows, Linux en network appliances onverwagte WLAN-profiele, forwarding/NAT-konfigurasie, virtuele adapters en persistente tunnels.
5. Verminder onnodige seinlekkasie met sinvolle AP-plasing en kragbeplanning. Dit is ’n ondersteunende beheermaatreël, nie authentication nie.
6. Koördineer incident response met naburige huurders: die finale radiobron kan self ’n slagoffer wees.

Die [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduseer hierdie waarneembare eienskappe sonder om ’n buurman aan te val.

## Openbare venues en third-party Wi-Fi

Die gebruik van café-, hotel-, lughawe- of munisipale Wi-Fi verander die IP wat aan ’n bestemming vertoon word. Dit skep nie anonymity nie. Die venue of sy provider kan AP-assosiasie, device MAC, DHCP-lease, captive-portal-rekening, SMS/e-pos-validasie en flow logs behou. Fisiese toegang, CCTV, aankope, mobiele-ligging- en reisrekords kan die digitale gebeurtenis aan ’n persoon koppel.

’n Actor kan probeer om een identifiseerder te verminder deur gerandomiseerde MAC-adresse, ’n aparte toestel, kontant of ’n tunnel te gebruik. Cross-layer-korrelasie bly moontlik deur aankomstyd, herhaalde venue-patrone, radiofingerprints, portalgedrag, verkeersiming, kamerabeelde en die tunnelprovider. ’n VPN verskuif ook die bestemming van venue-logs na VPN-logs; dit verwyder nie die venue se kennis dat die toestel teenwoordig was nie.

Verdedigers van openbare toegang behoort clients te isoleer, laterale verkeer te blokkeer, WPA2/3-Enterprise of per-device keys te gebruik waar haalbaar, proporsionele DHCP/RADIUS/security logs te behou, captive portals te beskerm en ’n abuse-proses te publiseer. Red teams behoort so ’n venue slegs te gebruik wanneer die bepalings daarvan en die engagement dit toelaat; die omseiling van ’n portal, diefstal van toegang of teikening van ander gaste is nie ’n gemagtigde testing-shortcut nie.

## Covert drop devices en warshipping

’n Drop is ’n klein stelsel wat in ’n terrein geplaas of daarheen afgelewer word en daarna deur outbound Ethernet, Wi-Fi of cellular beheer word. “Warshipping” verpak die toestel sodat gewone aflewering dit binne die radioperimeter dra. Moontlike hardware wissel van ’n single-board computer tot ’n aangepaste charger, USB-peripheral, network appliance of battery-powered modem.

Operasionele argitektuur:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Die toestel kan ’n remote foothold verskaf, wireless measurements uitvoer, ’n gemagtigde exercise peripheral emuleer, of traffic relay. Die oënskynlike oorsprong daarvan is plaaslik, maar dit skep fisiese artefakte: reeksnommers, verpakking, fingerprints, kameras, toegangslogs, kragverbruik, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions en herhalende rendezvous connections.

### Defensive controls

- Handhaaf prosedures vir die ontvangskamer en asset inventory; inspekteer onverwagte elektronika en pakkette wat aan niebestaande personeel geadresseer is.
- Gebruik 802.1X/NAC op wired en wireless access, deaktiveer ongebruikte poorte, en plaas onbekende toestelle in ’n beperkte remediation VLAN.
- Genereer alerts vir nuwe DHCP fingerprints, lokaal-geadministreerde MACs wat voortduur, nuwe USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth en langdurige outbound tunnels.
- Stel ’n baseline vir switchport-, power-over-Ethernet-, DNS- en TLS-gedrag. ’n Klein host sonder ’n inventory record wat periodieke encrypted connections maak, is ’n sterker signal as slegs “Raspberry Pi OUI”.
- Tydens ’n exercise moet die organisasie toestelle inventariseer, label, scope en encrypt, ’n remote kill voorsien, ’n retrieval deadline stel en verseker dat verlies nie reusable credentials kan blootstel nie.

## Cellular and eSIM backhaul

’n Cellular modem vermy die target se Internet gateway en kan ’n drop bereikbaar hou agter carrier NAT deur middel van ’n outbound rendezvous. Mobile addresses kan roteer of gedeel word; die cellular operator het steeds sterk subscriber- en network evidence: SIM/eSIM identity, IMSI, device IMEI, toegewyde addresses/ports, cell/sector timing, account/payment- en roaming records.

Vanuit die enterprise se perspektief moet onverwagte modems en personal hotspots opgespoor word met wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring en fisiese inspeksie. ’n Drop wat cellular vir control gebruik, kan steeds deur sy plaaslike Ethernet/Wi-Fi behavior en radio emissions opgespoor word.

Vir gemagtigde exercises behoort die organisasie die subscription en modem te besit, identifiers by die controller aan te teken en te valideer dat carrier/provider terms die traffic toelaat. ’n Prepaid label of cryptocurrency-aankoop verwyder nie tower-, device- of retail records nie.

## MAC randomization and device fingerprinting

Moderne systems kan ’n locally administered random MAC per network gebruik. Dit verminder passiewe langtermyn-tracking deur ’n stabiele factory MAC; dit verberg nie:

- probe/association timing en die stel aangevraagde network capabilities nie;
- 802.11 information elements, supported rates en vendor-specific behavior nie;
- DHCP options/hostname, IPv6 identifiers en captive-portal/browser fingerprint nie;
- authenticated 802.1X identity of certificate nie;
- hoërlaag-account-, tunnel- en traffic pattern nie; of
- fisiese observation nie.

Defenders behoort nie MAC allowlists as authentication te gebruik nie. Koppel radio identity aan certificate/device posture en behandel veranderende MACs as normaal, tensy ander context anomalous is.

## Satellite-link hijacking

Kaspersky het gedokumenteer dat Turla weaknesses in ouer eenrigting-DVB-S satellite Internet gebruik het. In die gerapporteerde model het ’n legitieme remote subscriber outbound requests oor ’n terrestrial link gestuur, maar downstream data via ’n unencrypted wide-area satellite broadcast ontvang. ’n Actor binne die satellite footprint kon die downlink observeer, ’n aktiewe subscriber IP kies en reël dat C2 replies aan daardie IP geadresseer word. Sowel die legitieme subscriber as die actor het die broadcast ontvang; die actor het traffic vir die geselekteerde port onttrek, terwyl die legitieme subscriber unsolicited packets weggegooi het. Die C2 operator het daarna blykbaar ’n satellite-provider address in ’n ander geografiese ligging gebruik.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Dit was spesifiek vir ’n protokol/diens, deur bandwydte beperk en nie gelykstaande aan die kompromittering van ’n moderne tweerigting-geënkripteerde satellietterminal nie. Dit het ook nie die actor se uitgaande versoekpad vir ’n voldoende bekwame waarnemer versteek nie. Opsporingsgeleenthede sluit in asimmetriese/onmoontlike roetering, verkeer na ’n subscriber wat nie die vloei geïnisieer het nie, ongewone bestemmingpoorte, provider-telemetrie, ondersoek van die ontvanger se ligging/RF en malware-konfigurasie. Gebruik hierdie geval om die aanname uit te daag dat geolokalisering van ’n C2-IP-adres die ligging van sy beheerder bepaal—nie as ’n bouresep nie.

## Fisiek-na-digitaal-korrelasiewerkblad

Wanneer ’n oënskynlik plaaslike bron verdag is, bou een tydlyn:

1. normaliseer AP-, RADIUS-, DHCP-, DNS-, proxy-, VPN-, EDR-, switch- en fisiese-toegangs-klokke;
2. identifiseer die eerste radio-assosiasie of link-up, nie net die eerste alert nie;
3. karteer die station aan sertifikaat, device posture, DHCP-fingerprint en switch/AP-ligging;
4. soek gelyktydige remote-control-/tunnel-aktiwiteit op nabygeleë stelsels;
5. hersien aflewerings, besoekers, voorraaduitsonderings, kameras en RF-bevindings ingevolge toepaslike beleid/wetgewing;
6. bewaar die vermoedelike toestel en vlugtige netwerktoestand; moenie blindelings die krag af- en aanskakel nie;
7. bepaal of die oënskynlike bron actor-beheerde infrastruktuur of ’n ander slagoffer is.

## References

- [1] [Volexity — Die Nearest Neighbor Attack: Hoe ’n Russiese APT nabygeleë Wi-Fi-netwerke vir geheime toegang gewapen het](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in die lug](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Riglyne vir die beveiliging van Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}
