# Bedekte Fisiese en Draadlose Toegang

Vir 'n gedetailleerde, eienaar-goedgekeurde implementering wat outbound rendezvous, krag/uplink-herwinning, minimale geheime wat deur die toestel gehou word, capture-toetsing en monitering vir moontlike ontdekking dek, sien [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Deur die netwerkpad te verander, kan die oënskynlike fisiese oorsprong ook verander. 'n Gesofistikeerde actor kan 'n nabygeleë gekompromitteerde stelsel, 'n versteekte toestel, openbare toegang, cellular backhaul of 'n satellietontvanger gebruik sodat teikenlogs weg van die operateur wys. Nie een hiervan verwyder fisiese, radio- of providerbewyse nie; dit verskuif attribution na verskillende datastelle.

## Tegniekmatriks

| Tegniek | Oënskynlike oorsprong | Noodsaaklike voorwaarde | Bewyse met hoë waarde |
|---|---|---|---|
| Nabygeleë wireless pivot | 'n besigheid/huis langs die teiken | gekompromitteerde dual-homed host en teiken-Wi-Fi-toegang | endpoint-logs van die buurhost, RF-assosiasie en teiken-RADIUS/DHCP |
| Openbare/gasnetwerk | lokaal se NAT of tunnel exit | wettige toegang of omseiling van toegangsbeheer | captive portal, DHCP, AP-assosiasie, CCTV en betalings-/liggingsrekords |
| Bedekte drop device | teiken/nabygeleë bedrade, Wi-Fi- of cellular-adres | fisiese plasing of aflewering | switchport/USB, RF, voorraad, krag en telemetry van die outbound tunnel |
| Cellular-router/eSIM | carrier NAT of toegewyde APN | modem/SIM/subskripsie | IMEI/IMSI/eSIM, selsektor, carrier-rekening en verkeers-tydsberekening |
| Misbruik van satellietskakel | intekenaaradres binne die straalgebied | protokol- en diensspesifieke swakheid | RF-ligging, uplink-vloei, onmoontlike RTT/routing en providerrekords |

## Nearest-neighbor-aanval

Volexity het 'n APT28/GRU-operasie uit 2022 gedokumenteer waarin die actor op afstand van sy uiteindelike teiken was. Dit het die teiken se publieke diens met password spraying aangeval om geldige geloofsbriewe te bekom, maar MFA het direkte Internet-aanmelding verhoed. Die teiken se enterprise-Wi-Fi het daardie geloofsbriewe sonder MFA aanvaar. Die actor het organisasies wat fisies naby die teiken was, gekompromitteer, 'n dual-homed system met draadlose bereik gevind en daardie stelsel gebruik om by die teiken se Wi-Fi te authenticateer. Volexity het dit die **Nearest Neighbor Attack** genoem.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Die nuutheid lê in die samestelling. Geen operateur reis na die teiken nie, en die Internet-gerigte diens se MFA werk steeds. Die gekompromitteerde buurman verskaf fisiese nabyheid; die gesteelde teikenbewys verskaf logiese toegang; die teiken-Wi-Fi word die pad wat die grens oorsteek.

### Voorvereistes en sigbaarheid

- ’n Nabygeleë stelsel moet op afstand beheerbaar wees en ’n versoenbare radio hê, of toegang tot ’n ander nabygeleë pivot.
- Die teiken-SSID moet daardie stelsel bereik, en Wi-Fi-toelating moet ’n herbruikbare bewys/sertifikaat/toestelstatus aanvaar.
- Die pivot benodig dikwels twee gelyktydige paaie: een terug na die operateur en een na die teiken-WLAN.
- Die teiken kan ’n nuwe stasie-MAC en ’n geldige gebruikersnaam sien, maar geen ooreenstemmende managed-device-sertifikaat, posture, geskiedenis of verwagte gebouetoegang nie.
- Neighbor endpoint-logs kan wireless scans, nuwe profiele, interface-wysigings, tunneling en remote-control-aktiwiteit toon.

### Opsporing en voorkoming

1. Vereis certificate-backed EAP-TLS en managed-device posture vir enterprise-Wi-Fi; moenie ’n wagwoord wat op die Internet met MFA misluk het, bloot omdat dit oor radio aankom as voldoende beskou nie.
2. Korrelleer RADIUS-verifikasie met MDM/NAC-identiteit, historiese stasie/toestel-binding, AP-ligging, fisiese-toegangsgebeure en gelyktydige sessies.
3. Skep ’n waarskuwing wanneer ’n rekening vir die eerste keer assosieer, vanaf ’n ongewone AP-edge, sonder ’n managed sertifikaat, of terwyl dieselfde identiteit elders aktief is.
4. Monitor endpoints wat interfaces kan bridge. Ondersoek op Windows, Linux en network appliances onverwagte WLAN-profiele, forwarding/NAT-konfigurasie, virtuele adapters en volgehoue tunnels.
5. Verminder onnodige seinlekkasie met sinvolle AP-plasing en kragbeplanning. Dit is ’n ondersteunende beheermaatreël, nie verifikasie nie.
6. Koördineer incident response met naburige huurders: die finale radiosender kan self ’n slagoffer wees.

Die [owned two-organization lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot) reproduseer hierdie waarneembare tekens sonder om ’n buurman aan te val.

## Openbare plekke en derdeparty-Wi-Fi

Die gebruik van café-, hotel-, lughawe- of munisipale Wi-Fi verander die IP wat aan ’n bestemming getoon word. Dit skep nie anonimiteit nie. Die venue of sy provider kan AP-assosiasie, toestel-MAC, DHCP-lease, captive-portal-rekening, SMS/e-pos-validering en flow-logs behou. Fisiese toegang, CCTV, aankope, mobiele-ligging- en reisrekords kan die digitale gebeurtenis met ’n persoon verbind.

’n Akteur kan probeer om een identifiseerder te verminder deur gerandomiseerde MAC-adresse, ’n aparte toestel, kontant of ’n tunnel te gebruik. Cross-layer-korrelasie bly moontlik deur aankomstyd, herhaalde venue-patrone, radio-fingerprints, portalgedrag, verkeerstydsberekening, kamerabeelde en die tunnelprovider. ’n VPN verskuif ook die bestemming van venue-logs na VPN-logs; dit verwyder nie die venue se kennis dat die toestel teenwoordig was nie.

Verdedigers van openbare toegang behoort kliënte te isoleer, laterale verkeer te blokkeer, WPA2/3-Enterprise of per-toestel-sleutels te gebruik waar dit uitvoerbaar is, proporsionele DHCP/RADIUS/security-logs te behou, captive portals te beskerm en ’n abuse-proses te publiseer. Red teams behoort so ’n venue slegs te gebruik wanneer die bepalings daarvan en die engagement dit toelaat; die omseiling van ’n portal, diefstal van toegang of teikening van ander gaste is nie ’n gemagtigde testing-kortpad nie.

## Covert drop devices en warshipping

’n Drop is ’n klein stelsel wat op ’n perseel geplaas of daarheen afgelewer word en daarna deur outbound Ethernet, Wi-Fi of cellular beheer word. “Warshipping” verpak die toestel sodat gewone aflewering dit binne die radioperimeter bring. Moontlike hardeware wissel van ’n single-board computer tot ’n aangepaste charger, USB-peripheral, network appliance of battery-powered modem.

Operasionele argitektuur:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Die toestel kan 'n remote foothold verskaf, wireless measurements uitvoer, 'n gemagtigde exercise peripheral naboots, of verkeer relê. Die oënskynlike bron daarvan is plaaslik, maar dit skep fisiese artefakte: reeksnommers, verpakking, fingerprints, kameras, toegangslogboeke, kragverbruik, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions en herhalende rendezvous connections.

### Defensive controls

- Handhaaf prosedures vir ontvangskamers en asset inventories; inspekteer onverwagte elektronika en pakkette wat aan niebestaande personeel gerig is.
- Gebruik 802.1X/NAC op wired en wireless access, deaktiveer ongebruikte poorte, en plaas onbekende toestelle in 'n beperkte remediation VLAN.
- Stel alerts op vir nuwe DHCP fingerprints, locally administered MACs wat voortduur, nuwe USB network/HID devices, unauthorized Wi-Fi Direct/Bluetooth en langdurige outbound tunnels.
- Stel 'n baseline vir switchport-, power-over-Ethernet-, DNS- en TLS-gedrag. 'n Klein host sonder 'n inventory record wat periodieke encrypted connections maak, is 'n sterker aanduiding as slegs “Raspberry Pi OUI”.
- Tydens 'n exercise, inventariseer, label, scope en encrypt; verskaf 'n remote kill, stel 'n retrieval deadline, en verseker dat verlies nie reusable credentials kan blootstel nie.

## Cellular and eSIM backhaul

'n Cellular modem vermy die target se Internet gateway en kan 'n drop agter carrier NAT bereikbaar hou deur middel van 'n outbound rendezvous. Mobile addresses kan roteer of gedeel word; die cellular operator het steeds sterk subscriber- en network evidence: SIM/eSIM identity, IMSI, device IMEI, assigned addresses/ports, cell/sector timing, account/payment- en roaming records.

Vanuit die enterprise se oogpunt moet onverwagte modems en personal hotspots opgespoor word met wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring en fisiese inspeksie. 'n Drop wat cellular vir control gebruik, kan steeds deur sy plaaslike Ethernet/Wi-Fi behavior en sy radio emissions opgespoor word.

Vir gemagtigde exercises moet die organisasie die subscription en modem besit, identifiers saam met die controller aanteken, en bevestig dat carrier/provider terms die verkeer toelaat. 'n Prepaid label of cryptocurrency purchase verwyder nie tower-, device- of retail records nie.

## MAC randomization and device fingerprinting

Moderne stelsels kan 'n locally administered random MAC per network gebruik. Dit verminder passiewe langtermyn-tracking deur 'n stabiele factory MAC; dit verberg nie:

- probe/association timing en die stel van requested network capabilities nie;
- 802.11 information elements, supported rates en vendor-specific behavior nie;
- DHCP options/hostname, IPv6 identifiers en captive-portal/browser fingerprint nie;
- authenticated 802.1X identity of certificate nie;
- hoërlaag-account, tunnel- en traffic pattern nie; of
- fisiese observasie nie.

Defenders moenie MAC allowlists as authentication gebruik nie. Koppel radio identity aan certificate/device posture en behandel changing MACs as normaal, tensy ander context anomalous is.

## Satellite-link hijacking

Kaspersky het gedokumenteer dat Turla weaknesses in ouer one-way DVB-S satellite Internet gebruik het. In die gerapporteerde model het 'n legitimate remote subscriber outbound requests oor 'n terrestrial link gestuur, maar downstream data deur 'n unencrypted wide-area satellite broadcast ontvang. 'n Actor binne die satellite footprint kon die downlink observeer, 'n active subscriber IP kies en reël dat C2 replies aan daardie IP gerig word. Beide die legitimate subscriber en actor het die broadcast ontvang; die actor het verkeer vir die selected port onttrek terwyl die legitimate subscriber unsolicited packets weggegooi het. Die C2 operator het daarna voorgekom asof dit 'n satellite-provider address in 'n ander geografiese gebied gebruik.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Dit was protokol-/diensspesifiek, bandwydtebeperk en nie gelykstaande aan die kompromittering van 'n moderne tweerigting-geënkripteerde satellietterminaal nie. Dit het ook nie die akteur se uitgaande versoekpad vir 'n voldoende bekwame waarnemer versteek nie. Opsporingsgeleenthede sluit in asimmetriese/onmoontlike roetering, verkeer na 'n intekenaar wat nie die vloei geïnisieer het nie, ongewone bestemmingspoorte, verskaffer-telemetrie, ontvangerligging-/RF-ondersoek en malware-konfigurasie. Gebruik hierdie geval om die aanname uit te daag dat die geolokalisering van 'n C2-IP ook sy beheerder geolokaliseer—nie as 'n bouresep nie.

## Werkblad vir fisies-na-digitale korrelasie

Wanneer 'n oënskynlik plaaslike bron verdag is, bou een tydlyn:

1. normaliseer die horlosies van AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch en fisiese toegang;
2. identifiseer die eerste radio-assosiasie of link-up, nie net die eerste waarskuwing nie;
3. koppel die station aan sertifikaat, toestel se sekuriteitsposisie, DHCP-vingerafdruk en switch-/AP-ligging;
4. soek na gelyktydige remote-control-/tunnel-aktiwiteit op nabygeleë stelsels;
5. hersien aflewerings, besoekers, voorraad-afwykings, kameras en RF-bevindings ingevolge toepaslike beleid/wetgewing;
6. bewaar die vermoedelike toestel en vlugtige netwerktoestand; moenie blindelings die krag af- en aanskakel nie;
7. bepaal of die oënskynlike bron akteur-beheerde infrastruktuur of 'n ander slagoffer is.

## References

- [1] [Volexity — The Nearest Neighbor Attack: Hoe 'n Russiese APT nabygeleë Wi-Fi-netwerke gewapen het](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: APT command and control in the sky](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Guidelines for Securing Wireless Local Area Networks](https://csrc.nist.gov/pubs/sp/800/153/final)
